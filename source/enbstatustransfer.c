#include "enbstatustransfer.h"
#include "s1ap_conv.h"
#include "mmestatustransfer.h"
#include <pthread.h>

// external reference to variables in the listener
extern int db_sock;
extern pthread_mutex_t db_sock_mutex;

status_t handle_enbstatustransfer(s1ap_message_t *message, S1AP_handler_response_t *response) {
    d_info("Handling ENB Status Transfer message");

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_ENBStatusTransfer_t *ENBStatusTransfer = NULL;

    S1AP_ENBStatusTransferIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_ENB_StatusTransfer_TransparentContainer_t
        *ENB_StatusTransfer_TransparentContainer = NULL;

    d_assert(message, return CORE_ERROR, "No S1AP Message");
    initiatingMessage = message->choice.initiatingMessage;
    d_assert(initiatingMessage, return CORE_ERROR, "No Initiating Message");
    ENBStatusTransfer = &initiatingMessage->value.choice.ENBStatusTransfer;
    d_assert(ENBStatusTransfer, return CORE_ERROR, "No ENB Status Transfer Message");

    for (int i = 0; i < ENBStatusTransfer->protocolIEs.list.count; i++)
    {
        ie = ENBStatusTransfer->protocolIEs.list.array[i];
        switch(ie->id)
        {
            case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
                MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_eNB_StatusTransfer_TransparentContainer:
                ENB_StatusTransfer_TransparentContainer =
                    &ie->value.choice.ENB_StatusTransfer_TransparentContainer;
                break;
            default:
                break;
        }
    }

    d_assert(MME_UE_S1AP_ID, return CORE_ERROR, "Failed to extract MME_UE_S1AP_ID");
    d_assert(ENB_UE_S1AP_ID, return CORE_ERROR, "Failed to extract ENB_UE_S1AP_ID");
    d_assert(ENB_StatusTransfer_TransparentContainer, return CORE_ERROR, "Failed to extract ENB_StatusTransfer_TransparentContainer");

    // retreive the target eNB socket number and target ENB_UE_S1AP_ID
    c_uint8_t buffer[1024];
    corekube_db_pulls_t db_pulls;
    status_t db_access = get_enb_status_transfer_prerequisites_from_db(MME_UE_S1AP_ID, buffer, &db_pulls);
    d_assert(db_access == CORE_OK, return CORE_ERROR, "Failed to access DB for handover prerequisities");

    // prepare the values for the response
    mme_status_transfer_params_t status_transfer_params;
    status_transfer_params.mme_ue_s1ap_id = *MME_UE_S1AP_ID;
    status_transfer_params.enb_statustransfer_transparentContainer = ENB_StatusTransfer_TransparentContainer;

    // values fetched from the DB
    // db_pulls.target_enb_ue_s1ap_id is correct here because we are sending the
    // message to the target eNB, so we should use the target eNB ID
    status_transfer_params.enb_ue_s1ap_id = array_to_int(db_pulls.target_enb_ue_s1ap_id);

    // build the MME Status Transfer message
    status_t build_mme_status_transfer = s1ap_build_mme_status_transfer(&status_transfer_params, response->response);
    d_assert(build_mme_status_transfer == CORE_OK, return CORE_ERROR, "Failed to build MME Status Transfer command");

    // set the response to having a single reply
    response->outcome = HAS_RESPONSE;

    // set the response to go to the target eNB, rather then the source eNB that sent the message
    response->enbSocket = array_to_int(db_pulls.enb_target_socket);

    return CORE_OK;
}

status_t get_enb_status_transfer_prerequisites_from_db(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls) {
    d_info("Fetching eNB Status Transfer prerequisites from DB");

    OCTET_STRING_t raw_mme_ue_id;
    s1ap_uint32_to_OCTET_STRING(*mme_ue_id, &raw_mme_ue_id);

    int n;

    n = push_items(buffer, MME_UE_S1AP_ID, (uint8_t *)raw_mme_ue_id.buf, 0);
    core_free(raw_mme_ue_id.buf);

    const int NUM_PULL_ITEMS = 2;
    n = pull_items(buffer, n, NUM_PULL_ITEMS, Target_ENB_UE_S1AP_ID, ENB_TARGET_SOCKET);
    
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