
#include "uplinknastransport.h"

#include "nas_util.h"
#include "s1ap_conv.h"
#include "nas_authentication_response.h"
#include "initialcontextsetuprequest.h"
#include "downlinknastransport.h"
#include "nas_detach_request.h"
#include "ue_initial_context_release_command.h"
#include "nas_attach_complete.h"
#include "nas_message_security.h" //TODO - included while testing, make sure it is actually needed when commiting final version
#include "nas_authentication_request.h"
#include "nas_attach.h"
#include <libck.h>
#include <pthread.h>

extern int db_sock;
extern pthread_mutex_t db_sock_mutex;

status_t handle_uplinknastransport(s1ap_message_t *received_message, S1AP_handler_response_t *response) {
    d_info("Handling UplinkNASTransport");
    S1AP_UplinkNASTransport_t *uplinkNASTransport = &received_message->choice.initiatingMessage->value.choice.UplinkNASTransport;

    S1AP_MME_UE_S1AP_ID_t *mme_ue_id;
    UplinkNASTransport_extract_MME_UE_ID(uplinkNASTransport, &mme_ue_id);

    S1AP_ENB_UE_S1AP_ID_t *enb_ue_id;
    UplinkNASTransport_extract_ENB_UE_ID(uplinkNASTransport, &enb_ue_id);

    // logging
    d_info("ENB_S1AP_UE_ID: %d and MME_S1AP_UE_ID: %d", *enb_ue_id, *mme_ue_id);

    nas_message_t nas_message;
    status_t decode_nas = decode_uplinknastransport_nas(uplinkNASTransport, mme_ue_id, &nas_message);
    d_assert(decode_nas == CORE_OK, return CORE_ERROR, "Failed to decode NAS authentication response");

    pkbuf_t *nas_pkbuf;

    switch (nas_message.emm.h.message_type) {
        case NAS_AUTHENTICATION_RESPONSE:
            ; // necessary to stop C complaining about labels and declarations

            // handle the NAS authentication response
            // saving the reply as an encoded NAS message in nas_pkbuf
            status_t handle_auth_resp = nas_handle_authentication_response(&nas_message, mme_ue_id, &nas_pkbuf);
            d_assert(handle_auth_resp == CORE_OK, return CORE_ERROR, "Failed to handle NAS Authentication Response");

            response->outcome = HAS_RESPONSE;

            break;
        
        case NAS_AUTHENTICATION_FAILURE:
            ; // necessary to stop C complaining about labels and declarations
            d_info("Handling NAS Authentication Failure");

            // get the message in questio
            nas_authentication_failure_t auth_failure = nas_message.emm.authentication_failure;

            // check it is a synch failure
            d_assert(auth_failure.emm_cause == EMM_CAUSE_SYNCH_FAILURE, return CORE_ERROR, "Only authentication failure of type synch error is handled");

            // get the SQN xor AK
            uint8_t sqn_xor_ak[6];
            memcpy(sqn_xor_ak, auth_failure.authentication_failure_parameter.auts, 6);
            d_info("Received SQN xor AK:");
            d_print_hex(sqn_xor_ak, 6);

            // get the PLMNidentity
            S1AP_PLMNidentity_t *PLMNidentity;
            UplinkNASTransport_extract_PLMNidentity(uplinkNASTransport, &PLMNidentity);

            // fetch the K, OPc, and RAND from the DB
            OCTET_STRING_t raw_mme_ue_id;
            s1ap_uint32_to_OCTET_STRING(*mme_ue_id, &raw_mme_ue_id);
            c_uint8_t buffer[1024];
            int n;
            n = push_items(buffer, MME_UE_S1AP_ID, raw_mme_ue_id.buf, 0);
            n = pull_items(buffer, n, 3, KEY, OPC, RAND);

            corekube_db_pulls_t db_pulls;
            d_info("DB access, waiting for mutex");
            pthread_mutex_lock(&db_sock_mutex);
            d_info("DB access, mutex accessed");
            send_request(db_sock, buffer, n);
            n = recv_response(db_sock, buffer, 1024);
            pthread_mutex_unlock(&db_sock_mutex);
            d_info("DB access, received response");

            d_assert(n == 17 * 3,
                d_print_hex(buffer, n); return CORE_ERROR,
                "Failed to extract values from DB");

            extract_db_values(buffer, n, &db_pulls);

            d_info("Fetched K:");
            d_print_hex(db_pulls.key, 16);
            d_info("Fetched OPc:");
            d_print_hex(db_pulls.opc, 16);
            d_info("Fetched RAND:");
            d_print_hex(db_pulls.rand, 16);

            // recalculating the old authentication parameters
            c_uint8_t old_sqn[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            d_info("Old SQN is:");
            d_print_hex(old_sqn, 6);
            nas_authentication_vector_t auth_vec;
            d_assert(PLMNidentity->size == 3, return CORE_ERROR, "PLMN identity not of size 3");
            status_t auth_generate = generate_authentication_vector(
                db_pulls.key,
                db_pulls.opc,
                db_pulls.rand,
                old_sqn,
                PLMNidentity->buf,
                &auth_vec);
            d_assert(auth_generate == CORE_OK, return CORE_ERROR, "Failed to generate authentication vector");

            // extract the AK from the authentication parameters
            c_uint8_t ak[6];
            memcpy(ak, auth_vec.autn, 6);
            for (int i = 0; i < 6; i++)
                ak[i] = ak[i] ^ old_sqn[i];
            d_info("Calculated old AK:");
            d_print_hex(ak, 6);

            // determine the correct SQN
            c_uint8_t new_sqn[6];
            for (int i = 0; i < 6; i++)
                new_sqn[i] = sqn_xor_ak[i] ^ ak[i];
            d_info("Calculated new SQN:");
            d_print_hex(new_sqn, 6);

            // recalculate the authentication parameters with the correct SQN
            nas_authentication_vector_t new_auth_vec;
            status_t new_auth_generate = generate_authentication_vector(
                db_pulls.key,
                db_pulls.opc,
                db_pulls.rand,
                new_sqn,
                PLMNidentity->buf,
                &new_auth_vec);
            d_assert(new_auth_generate == CORE_OK, return CORE_ERROR, "Failed to generate authentication vector");

            // send out a new authentication request with the new auth vectors
            status_t get_nas_auth_req = generate_nas_authentication_request(new_auth_vec.rand, new_auth_vec.autn, &nas_pkbuf);
            d_assert(get_nas_auth_req == CORE_OK, return CORE_ERROR, "Failed to generate NAS authentication request");

            // TODO: save in the DB

            // mark this message as having a response
            response->outcome = HAS_RESPONSE;

            break;


        case NAS_SECURITY_MODE_COMPLETE:
            // TODO: only for testing purposes - send back a sample attach accept
            // note that this function is special in that it does not send back
            // a DownlinkNASTransport message (like the other messages of type
            // UplinkNASTransport), instead sending back a InitialContextSetupRequest,
            // hence why it returns directly
            return nas_send_attach_accept(mme_ue_id, response);

        case NAS_ATTACH_COMPLETE:
            ; // necessary to stop C complaining about labels and declarations

            // handle the attach complete message
            status_t handle_attach_complete = nas_handle_attach_complete(&nas_message, mme_ue_id);
            d_assert(handle_attach_complete == CORE_OK, return CORE_ERROR, "Failed to handle NAS attach complete message");

            // there should be no response for an attach complete message
            response->outcome = NO_RESPONSE;

            // return to avoid attempting to generate the DownlinkNASTransport
            // response, since attach complete does not have a response
            return CORE_OK;

        case NAS_DETACH_REQUEST:
            ; // necessary to stop C complaining about labels and declarations

            // check for the UE switch-off detach, where no Attach Accept
            // message should be sent
            c_uint8_t switch_off = nas_message.emm.detach_request_from_ue.detach_type.switch_off;
            if (switch_off) {
                d_info("Detach with UE switch off");

                ue_context_release_command_params_t context_release_params;
                context_release_params.mme_ue_id = *mme_ue_id;
                context_release_params.enb_ue_id = *enb_ue_id;
                context_release_params.cause.present = S1AP_Cause_PR_nas;
                context_release_params.cause.choice.nas = S1AP_CauseNas_detach;

                status_t context_release = s1ap_build_ue_context_release_command(&context_release_params, response->response);
                d_assert(context_release == CORE_OK, return CORE_ERROR, "Failed to build UEInitialContextReleaseCommand");

                response->outcome = HAS_RESPONSE;

                return CORE_OK;
            }

            // handle the detach request
            status_t nas_handle_detach = nas_handle_detach_request(&nas_message, NULL, &nas_pkbuf);
            d_assert(nas_handle_detach == CORE_OK, return CORE_ERROR, "Failed to handle NAS detach");

            // also return an additional message - UEInitialContextReleaseCommand
            ue_context_release_command_params_t context_release_params;
            context_release_params.mme_ue_id = *mme_ue_id;
            context_release_params.enb_ue_id = *enb_ue_id;
            context_release_params.cause.present = S1AP_Cause_PR_nas;
            context_release_params.cause.choice.nas = S1AP_CauseNas_detach;

            status_t additional_message = s1ap_build_ue_context_release_command(&context_release_params, response->response2);
            d_assert(additional_message == CORE_OK, return CORE_ERROR, "Failed to build UEInitialContextReleaseCommand");

            // mark this message as being a special case with two replies
            response->outcome = DUAL_RESPONSE;
            
            break;

        default:
            d_error("Unknown NAS message type");
            return CORE_ERROR;
    }

    status_t get_downlink = generate_downlinknastransport(nas_pkbuf, *mme_ue_id, *enb_ue_id, response->response);
    d_assert(get_downlink == CORE_OK, return CORE_ERROR, "Failed to generate DownlinkNASTransport message");

    return CORE_OK;
}

status_t decode_uplinknastransport_nas(S1AP_UplinkNASTransport_t *uplinkNASTransport, S1AP_MME_UE_S1AP_ID_t *mme_ue_id, nas_message_t *auth_response) {
    d_info("Decoding NAS-PDU in UplinkNASTransport message");
    S1AP_NAS_PDU_t *NAS_PDU = NULL;

    S1AP_UplinkNASTransport_IEs_t *NAS_PDU_IE;
    status_t get_ie = get_uplinkNASTransport_IE(uplinkNASTransport, S1AP_UplinkNASTransport_IEs__value_PR_NAS_PDU, &NAS_PDU_IE);
    d_assert(get_ie == CORE_OK, return CORE_ERROR, "Failed to get NAS_PDU IE from UplinkNASTransport");
    NAS_PDU = &NAS_PDU_IE->value.choice.NAS_PDU;

    status_t nas_decode = decode_nas_emm(NAS_PDU, mme_ue_id, auth_response);
    d_assert(nas_decode == CORE_OK, return CORE_ERROR, "Failed to decode NAS authentication response");

    return CORE_OK;
}

status_t UplinkNASTransport_extract_MME_UE_ID(S1AP_UplinkNASTransport_t *uplinkNASTransport, S1AP_MME_UE_S1AP_ID_t **MME_UE_ID) {
    d_info("Extracting MME_UE_S1AP_ID from UplinkNASTransport message");

    S1AP_UplinkNASTransport_IEs_t *MME_UE_ID_IE;
    status_t get_ie = get_uplinkNASTransport_IE(uplinkNASTransport, S1AP_UplinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID, &MME_UE_ID_IE);
    d_assert(get_ie == CORE_OK, return CORE_ERROR, "Failed to get MME_UE_ID IE from UplinkNASTransport");

    *MME_UE_ID = &MME_UE_ID_IE->value.choice.MME_UE_S1AP_ID;

    return CORE_OK;
}

status_t UplinkNASTransport_extract_ENB_UE_ID(S1AP_UplinkNASTransport_t *uplinkNASTransport, S1AP_ENB_UE_S1AP_ID_t **ENB_UE_ID) {
    d_info("Extracting ENB_UE_S1AP_ID from UplinkNASTransport message");

    S1AP_UplinkNASTransport_IEs_t *ENB_UE_ID_IE;
    status_t get_ie = get_uplinkNASTransport_IE(uplinkNASTransport, S1AP_UplinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID, &ENB_UE_ID_IE);
    d_assert(get_ie == CORE_OK, return CORE_ERROR, "Failed to get ENB_UE_ID IE from UplinkNASTransport");

    *ENB_UE_ID = &ENB_UE_ID_IE->value.choice.ENB_UE_S1AP_ID;

    return CORE_OK;
}

status_t UplinkNASTransport_extract_PLMNidentity(S1AP_UplinkNASTransport_t *uplinkNASTransport, S1AP_PLMNidentity_t **PLMNidentity) {
    d_info("Extracting PLMN identity from UplinkNASTransport");

    S1AP_UplinkNASTransport_IEs_t *TAI_IE;
    status_t get_ie = get_uplinkNASTransport_IE(uplinkNASTransport, S1AP_UplinkNASTransport_IEs__value_PR_TAI, &TAI_IE);
    d_assert(get_ie == CORE_OK, return CORE_ERROR, "Failed to get TAI IE from UplinkNASTransport");

    *PLMNidentity = &TAI_IE->value.choice.TAI.pLMNidentity;

    return CORE_OK;
}

status_t get_uplinkNASTransport_IE(S1AP_UplinkNASTransport_t *uplinkNASTransport, S1AP_UplinkNASTransport_IEs__value_PR desiredIElabel, S1AP_UplinkNASTransport_IEs_t **desiredIE) {
    d_info("Searching for IE in UplinkNASTransport message");
    int numIEs = uplinkNASTransport->protocolIEs.list.count;
    for (int i = 0; i < numIEs; i++) {
        S1AP_UplinkNASTransport_IEs_t *theIE = uplinkNASTransport->protocolIEs.list.array[i];
        if (theIE->value.present == desiredIElabel) {
            *desiredIE = theIE;
            return CORE_OK;
        }
    }

    // if we reach here, then the desired IE has not been found
    return CORE_ERROR;
}