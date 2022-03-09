#include "handoverrequestacknowledge.h"
#include "s1ap_conv.h"
#include "handovercommand.h"
#include <pthread.h>

// external reference to variables in the listener
extern int db_sock;
extern pthread_mutex_t db_sock_mutex;

status_t handle_handoverrequestacknowledge(s1ap_message_t *received_message, S1AP_handler_response_t *response) {
    d_info("Handling Handover Request Acknowledge message");

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_HandoverRequestAcknowledge_t *HandoverRequestAcknowledge = NULL;

    S1AP_HandoverRequestAcknowledgeIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_E_RABAdmittedList_t *E_RABAdmittedList = NULL;
    S1AP_Target_ToSource_TransparentContainer_t
        *Target_ToSource_TransparentContainer = NULL;

    successfulOutcome = received_message->choice.successfulOutcome;
    HandoverRequestAcknowledge =
        &successfulOutcome->value.choice.HandoverRequestAcknowledge;

    for (int i = 0; i < HandoverRequestAcknowledge->protocolIEs.list.count; i++)
    {
        ie = HandoverRequestAcknowledge->protocolIEs.list.array[i];
        switch(ie->id)
        {
            case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
                MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_E_RABAdmittedList:
                E_RABAdmittedList = &ie->value.choice.E_RABAdmittedList;
                break;
            case S1AP_ProtocolIE_ID_id_Target_ToSource_TransparentContainer:
                Target_ToSource_TransparentContainer =
                    &ie->value.choice.Target_ToSource_TransparentContainer;
                break;
            default:
                break;
        }
    }

    d_assert(MME_UE_S1AP_ID, return CORE_ERROR, "Failed to extract MME_UE_S1AP_ID");
    d_assert(ENB_UE_S1AP_ID, return CORE_ERROR, "Failed to extract ENB_UE_S1AP_ID");
    d_assert(E_RABAdmittedList, return CORE_ERROR, "Failed to extract E_RABAdmittedList");
    d_assert(Target_ToSource_TransparentContainer, return CORE_ERROR, "Failed to extract Target_ToSource_TransparentContainer");

    // check we have the necessary items from the eRAB Admitted List
    d_assert(E_RABAdmittedList->list.array[0], return CORE_ERROR, "Empty eRAB Admitted List");
    S1AP_E_RABAdmittedItemIEs_t *ie2 = (S1AP_E_RABAdmittedItemIEs_t *)E_RABAdmittedList->list.array[0];
    S1AP_E_RABAdmittedItem_t *e_rab = &ie2->value.choice.E_RABAdmittedItem;
    d_assert(e_rab->e_RAB_ID, return CORE_ERROR, "No eRAB ID");
    d_assert(e_rab->dL_gTP_TEID, return CORE_ERROR, "No eRAB dL_gTP_TEID");
    d_assert(e_rab->dL_transportLayerAddress, return CORE_ERROR, "No eRAB dL_transportLayerAddress");

    c_uint32_t sgw_dl_teid;
    c_uint32_t sgw_teid;
    c_uint32_t sgw_dl_ip;
    c_uint32_t sgw_ip;

    memcpy(&sgw_dl_teid, e_rab->dL_gTP_TEID, sizeof(sgw_dl_teid));
    memcpy(&sgw_teid, &e_rab->gTP_TEID, sizeof(sgw_teid));

    memcpy(&sgw_dl_ip, e_rab->dL_transportLayerAddress->buf, IPV4_LEN);
    memcpy(&sgw_ip, e_rab->transportLayerAddress.buf, IPV4_LEN);

    c_uint8_t buffer[1024];
    corekube_db_pulls_t db_pulls;
    status_t db_access = get_handover_request_acknowledge_prerequisites_from_db(MME_UE_S1AP_ID, buffer, &db_pulls);
    d_assert(db_access == CORE_OK, return CORE_ERROR, "Failed to access DB for handover prerequisities");

    // prepare the values for the response
    handover_command_params_t handover_params;

    // values contained within the received message
    handover_params.handovertype = S1AP_HandoverType_intralte;
    handover_params.mme_ue_s1ap_id = *MME_UE_S1AP_ID;
    handover_params.Target_ToSource_TransparentContainer = Target_ToSource_TransparentContainer;
    handover_params.sgw_dl_ip = COREKUBE_DEFAULT_IP;
    handover_params.sgw_ul_ip = COREKUBE_DEFAULT_IP;
    handover_params.sgw_dl_teid = COREKUBE_DEFAULT_TEID;
    handover_params.sgw_ul_teid = COREKUBE_DEFAULT_TEID;

    // values fetched from the DB
    // db_pulls.enb_ue_s1ap_id is correct here because we are sending the
    // message to the source eNB, so we should use the source eNB ID
    handover_params.enb_ue_s1ap_id = array_to_int(db_pulls.enb_ue_s1ap_id);

    status_t build_handover = s1ap_build_handover_command(&handover_params, response->response);
    d_assert(build_handover == CORE_OK, return CORE_ERROR, "Failed to build handover");

    // set the response to having a single reply
    response->outcome = HAS_RESPONSE;

    // set the response to go to the source eNB, rather then the target eNB that sent the message
    response->enbSocket = array_to_int(db_pulls.enb_source_socket);

    return CORE_OK;
}

status_t get_handover_request_acknowledge_prerequisites_from_db(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls) {
    d_info("Fetching Handover Required prerequisites from DB");

    OCTET_STRING_t raw_mme_ue_id;
    s1ap_uint32_to_OCTET_STRING(*mme_ue_id, &raw_mme_ue_id);

    int n;

    n = push_items(buffer, MME_UE_S1AP_ID, (uint8_t *)raw_mme_ue_id.buf, 0);
    core_free(raw_mme_ue_id.buf);

    const int NUM_PULL_ITEMS = 2;
    n = pull_items(buffer, n, NUM_PULL_ITEMS, ENB_UE_S1AP_ID, ENB_SOURCE_SOCKET);
    
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

    return CORE_OK;
}