#include "handovernotify.h"
#include "s1ap_conv.h"
#include <pthread.h>
#include "ue_initial_context_release_command.h"

// external reference to variables in the listener
extern int db_sock;
extern pthread_mutex_t db_sock_mutex;

status_t handle_handovernotify(s1ap_message_t *message, S1AP_handler_response_t *response) {
    d_info("Handling Handover Notify message");

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_HandoverNotify_t *HandoverNotify = NULL;

    S1AP_HandoverNotifyIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_EUTRAN_CGI_t *EUTRAN_CGI = NULL;
    S1AP_TAI_t *TAI = NULL;


    d_assert(message, return CORE_ERROR, "No message");
    initiatingMessage = message->choice.initiatingMessage;
    d_assert(initiatingMessage, return CORE_ERROR, "No initiating message");
    HandoverNotify = &initiatingMessage->value.choice.HandoverNotify;
    d_assert(HandoverNotify, return CORE_ERROR, "No handover notify");

    for (int i = 0; i < HandoverNotify->protocolIEs.list.count; i++)
    {
        ie = HandoverNotify->protocolIEs.list.array[i];
        switch(ie->id)
        {
            case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
                MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_EUTRAN_CGI:
                EUTRAN_CGI = &ie->value.choice.EUTRAN_CGI;
                break;
            case S1AP_ProtocolIE_ID_id_TAI:
                TAI = &ie->value.choice.TAI;
                break;
            default:
                break;
        }
    }
    

    d_assert(MME_UE_S1AP_ID, return CORE_ERROR, "Failed to extract MME_UE_S1AP_ID");
    d_assert(ENB_UE_S1AP_ID, return CORE_ERROR, "Failed to extract ENB_UE_S1AP_ID");
    d_assert(EUTRAN_CGI, return CORE_ERROR, "Failed to extract EUTRAN_CGI");
    d_assert(TAI, return CORE_ERROR, "Failed to extract TAI");

    // retreive the target eNB socket number and target ENB_UE_S1AP_ID
    c_uint8_t buffer[1024];
    corekube_db_pulls_t db_pulls;
    status_t db_access = get_handover_notify_prerequisites_from_db(MME_UE_S1AP_ID, buffer, &db_pulls);
    d_assert(db_access == CORE_OK, return CORE_ERROR, "Failed to access DB for handover prerequisities");

    // prepare the values for the response
    ue_context_release_command_params_t context_release_params;
    context_release_params.mme_ue_id = *MME_UE_S1AP_ID;
    context_release_params.cause.present = S1AP_Cause_PR_radioNetwork;
    context_release_params.cause.choice.nas = S1AP_CauseRadioNetwork_successful_handover;

    // values fetched from the DB
    // db_pulls.enb_ue_s1ap_id is correct here because we are sending the
    // message to the source eNB, so we should use the source eNB ID
    context_release_params.enb_ue_id = array_to_int(db_pulls.enb_ue_s1ap_id);

    status_t context_release = s1ap_build_ue_context_release_command(&context_release_params, response->response);
    d_assert(context_release == CORE_OK, return CORE_ERROR, "Failed to build UEInitialContextReleaseCommand");

    // set the response to having a single reply
    response->outcome = HAS_RESPONSE;

    // set the response to go to the source eNB, rather then the target eNB that sent the message
    response->enbSocket = array_to_int(db_pulls.enb_source_socket);

    return CORE_OK;
}

status_t get_handover_notify_prerequisites_from_db(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls) {
    d_info("Fetching Handover Notify prerequisites from DB");

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