#include "handoverrequired.h"
#include "s1ap_conv.h"
#include "core/include/core_sha2_hmac.h"
#include "handoverrequest.h"
#include <pthread.h>

// external reference to variables in the listener
extern int db_sock;
extern pthread_mutex_t db_sock_mutex;

status_t handle_handoverrequired(s1ap_message_t *received_message, S1AP_handler_response_t *response) {
    d_info("Handling Handover Required message");

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_HandoverRequired_t *HandoverRequired = NULL;

    S1AP_HandoverRequiredIEs_t *ie = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_HandoverType_t *HandoverType = NULL;
    S1AP_Cause_t *Cause = NULL;
    S1AP_TargetID_t *TargetID = NULL;
    S1AP_Source_ToTarget_TransparentContainer_t
        *Source_ToTarget_TransparentContainer = NULL;

    d_assert(received_message, return CORE_ERROR, "No message parameter");
    initiatingMessage = received_message->choice.initiatingMessage;
    d_assert(initiatingMessage, return CORE_ERROR, "No initiating message");
    HandoverRequired = &initiatingMessage->value.choice.HandoverRequired;
    d_assert(HandoverRequired, return CORE_ERROR, "No handover required message");

    c_uint32_t target_enb_id = 0;

    for (int i = 0; i < HandoverRequired->protocolIEs.list.count; i++)
    {
        ie = HandoverRequired->protocolIEs.list.array[i];
        switch(ie->id)
        {
            case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
                MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_HandoverType:
                HandoverType = &ie->value.choice.HandoverType;
                break;
            case S1AP_ProtocolIE_ID_id_Cause:
                Cause = &ie->value.choice.Cause;
                break;
            case S1AP_ProtocolIE_ID_id_TargetID:
                TargetID = &ie->value.choice.TargetID;
                break;
            case S1AP_ProtocolIE_ID_id_Source_ToTarget_TransparentContainer:
                Source_ToTarget_TransparentContainer =
                    &ie->value.choice.Source_ToTarget_TransparentContainer;
                break;
            default:
                break;
        }
    }

    d_assert(ENB_UE_S1AP_ID, return CORE_ERROR, "No END_UE_S1AP_ID found");
    d_assert(MME_UE_S1AP_ID, return CORE_ERROR, "NO MME_UE_S1AP_ID found");
    d_assert(HandoverType, return CORE_ERROR, "No HandoverType field found");
    d_assert(Cause, return CORE_ERROR, "Failed to find Cause");
    d_assert(TargetID, return CORE_ERROR, "Failed to find eNB Target ID");
    d_assert(Source_ToTarget_TransparentContainer, return CORE_ERROR, "Failed to find Source_ToTarget_TransparentContainer");

    d_assert(TargetID->present == S1AP_TargetID_PR_targeteNB_ID, return CORE_ERROR, "Only S1AP_TargetID_eNB_ID is supported");
    s1ap_ENB_ID_to_uint32(
                &TargetID->choice.targeteNB_ID->global_ENB_ID.eNB_ID,
                &target_enb_id);
    
    c_uint8_t buffer[1024];
    corekube_db_pulls_t db_pulls;
    status_t db_access = get_handover_required_prerequisites_from_db(MME_UE_S1AP_ID, target_enb_id, response->enbSocket, buffer, &db_pulls);
    d_assert(db_access == CORE_OK, return CORE_ERROR, "Failed to access DB for handover prerequisities");
    
    // generate the new key
    c_uint8_t kasme[SHA256_DIGEST_SIZE];
    memcpy(kasme, db_pulls.kasme1, 16);
    memcpy(kasme+16, db_pulls.kasme2, 16);
    c_uint8_t current_knh[SHA256_DIGEST_SIZE];
    memcpy(current_knh, db_pulls.knh1, 16);
    memcpy(current_knh+16, db_pulls.knh2, 16);
    c_uint8_t new_knh[SHA256_DIGEST_SIZE];
    mme_kdf_nh(kasme, current_knh, new_knh);

    // TODO: store the new KNH into the DB
    //       (required for future handovers)

    // prepare the values for the response
    handover_request_params_t handover_params;

    // values contained within the received message
    handover_params.cause = Cause;
    handover_params.handovertype = HandoverType;
    handover_params.source_totarget_transparentContainer = Source_ToTarget_TransparentContainer;
    handover_params.mme_ue_s1ap_id = *MME_UE_S1AP_ID;

    // values fetched from the DB
    memcpy(handover_params.nh, new_knh, 32);
    handover_params.nhcc = *db_pulls.ncc;
    handover_params.ipv4_addr = array_to_int(db_pulls.spgw_ip);
    handover_params.sgw_teid = array_to_int(db_pulls.epc_teid);

    status_t build_handover = s1ap_build_handover_request(&handover_params, response->response);
    d_assert(build_handover == CORE_OK, return CORE_ERROR, "Failed to build handover");

    // set the response to having a single reply
    response->outcome = HAS_RESPONSE;

    // set the response to go to the target eNB, rather then the eNB that sent the message
    response->enbSocket = array_to_int(db_pulls.get_enb);

    return CORE_OK;
}

status_t get_handover_required_prerequisites_from_db(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, c_uint32_t enb_id, c_uint32_t source_enb_socket, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls) {
    d_info("Fetching Handover Required prerequisites from DB");

    OCTET_STRING_t raw_mme_ue_id;
    s1ap_uint32_to_OCTET_STRING(*mme_ue_id, &raw_mme_ue_id);

    OCTET_STRING_t raw_enb_id;
    s1ap_uint32_to_OCTET_STRING(enb_id, &raw_enb_id);

    int n;

    n = push_items(buffer, MME_UE_S1AP_ID, (uint8_t *)raw_mme_ue_id.buf, 0);

    const int NUM_PULL_ITEMS = 8;
    n = pull_items(buffer, n, NUM_PULL_ITEMS,
        KNH_1, KNH_2, KASME_1, KASME_2, NEXT_HOP_CHAINING_COUNT, EPC_TEID, SPGW_IP, GET_ENB, raw_enb_id.buf);
    core_free(raw_enb_id.buf);
    
    d_info("DB access, waiting for mutex");
    pthread_mutex_lock(&db_sock_mutex);
    d_info("DB access, mutex accessed");
    send_request(db_sock, buffer, n);
    n = recv_response(db_sock, buffer, 1024);
    pthread_mutex_unlock(&db_sock_mutex);
    d_info("DB access, received response");

    d_assert(n == 17 * NUM_PULL_ITEMS,
        d_print_hex(buffer, n); return CORE_ERROR,
        "Failed to extract values from DB");

    extract_db_values(buffer, n, db_pulls);

    // additional DB access:
    // now that we have the target eNB socket number
    // we can save both the source and target sockets into the UE DB

    OCTET_STRING_t raw_source_enb_socket;
    s1ap_uint32_to_OCTET_STRING(source_enb_socket, &raw_source_enb_socket);

    c_uint8_t save_buffer[1024];
    n = push_items(save_buffer, MME_UE_S1AP_ID, (uint8_t *)raw_mme_ue_id.buf, 2, ENB_SOURCE_SOCKET, raw_source_enb_socket.buf, ENB_TARGET_SOCKET, db_pulls->get_enb);
    n = pull_items(save_buffer, n, 0);

    d_info("DB access, waiting for mutex");
    pthread_mutex_lock(&db_sock_mutex);
    d_info("DB access, mutex accessed");
    send_request(db_sock, save_buffer, n);
    pthread_mutex_unlock(&db_sock_mutex);
    d_info("DB access, received response");

    core_free(raw_mme_ue_id.buf);
    core_free(raw_source_enb_socket.buf);

    return CORE_OK;
}

void mme_kdf_nh(c_uint8_t *kasme, c_uint8_t *sync_input, c_uint8_t *kenb)
{
    c_uint8_t s[35];

    s[0] = 0x12; /* FC Value */

    memcpy(s+1, sync_input, 32);

    s[33] = 0x00;
    s[34] = 0x20;

    hmac_sha256(kasme, 32, s, 35, kenb, 32);
}
