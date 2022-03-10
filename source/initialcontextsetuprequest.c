#include <limits.h> //TODO: this should not be necessary, it's included in core.h
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include <pthread.h>

#include "initialcontextsetuprequest.h"
#include "nas_attach_accept.h"
#include "nas_activate_default_bearer_context_request.h"
#include "s6a_message.h"
#include "nas_message_security.h"
#include "s1ap_conv.h"
#include <arpa/inet.h>
#include "core/include/core_lib.h"
#include "nas_security_mode_command.h"
#include "handoverrequired.h"

// external reference to variables in the listener
extern int db_sock;
extern pthread_mutex_t db_sock_mutex;

// the following function is adapted from 
// nas_send_attach_accept() in the file 
// nextepc/src/mme/nas_path.c
status_t nas_send_attach_accept(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, S1AP_handler_response_t *response)
{
    d_info("Building Attach Accept");

    status_t rv;
    pkbuf_t *esmbuf = NULL, *emmbuf = NULL;

    // fetch the required state from the DB
    c_uint8_t buffer[1024];
    corekube_db_pulls_t db_pulls;
    status_t attach_accept_db = attach_accept_fetch_state(mme_ue_id, buffer, &db_pulls);
    d_assert(attach_accept_db == CORE_OK, return CORE_ERROR, "Failed to fetch attach accept prerequisites from DB");

    rv = esm_build_activate_default_bearer_context_request(&esmbuf);
    d_assert(rv == CORE_OK && esmbuf, return CORE_ERROR, "esm build error");

    rv = emm_build_attach_accept(&emmbuf, esmbuf, &db_pulls);
    d_assert(rv == CORE_OK && emmbuf, 
            pkbuf_free(esmbuf); return CORE_ERROR, "emm build error");

    rv = s1ap_build_initial_context_setup_request(emmbuf, &db_pulls, response->response);
    d_assert(rv == CORE_OK, pkbuf_free(emmbuf); return CORE_ERROR, "s1ap build error");

    d_info("finished building attach accept");

    response->outcome = HAS_RESPONSE;
    return CORE_OK;
}

status_t attach_accept_fetch_state(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls) {
    d_info("Fetching Attach Accept state from DB");

    OCTET_STRING_t raw_mme_ue_id;
    s1ap_uint32_to_OCTET_STRING(*mme_ue_id, &raw_mme_ue_id);

    int n;

    // required items from DB:
    //     esm_build_activate_default_bearer_context_request():
    //     emm_build_attach_accept(): 
    //          TMSI
    //          nas_security_encode():
    //              epc_nas_sequence_number, kasme
    //     s1ap_build_initial_context_setup_request():
    //          mme_ue_s1ap_id, enb_ue_s1ap_id, kasme1, kasme2, ue_nas_sequence_number

    const int NUM_PULL_ITEMS = 9;
    n = push_items(buffer, MME_UE_S1AP_ID, (uint8_t *)raw_mme_ue_id.buf, 0);
    n = pull_items(buffer, n, NUM_PULL_ITEMS,
        MME_UE_S1AP_ID, ENB_UE_S1AP_ID, KASME_1, KASME_2, EPC_NAS_SEQUENCE_NUMBER, UE_NAS_SEQUENCE_NUMBER_NO_INC, KASME_1, KASME_2, TMSI);
    
    d_info("DB access, waiting for mutex");
    pthread_mutex_lock(&db_sock_mutex);
    d_info("DB access, mutex accessed");
    send_request(db_sock, buffer, n);
    n = recv_response(db_sock, buffer, 1024);
    pthread_mutex_unlock(&db_sock_mutex);
    d_info("DB access, received response");

    // free the temporary MME_UE_ID
    core_free(raw_mme_ue_id.buf);

    d_assert(n == 17 * NUM_PULL_ITEMS,
        d_print_hex(buffer, n); return CORE_ERROR,
        "Failed to extract values from DB");

    extract_db_values(buffer, n, db_pulls);

    return CORE_OK;
}


// the following function is heavily adapted from 
// s1ap_build_initial_context_setup_request() in
// the file nextepc/src/mme/s1ap_build.c
status_t s1ap_build_initial_context_setup_request(
        pkbuf_t *emmbuf, corekube_db_pulls_t *db_pulls, s1ap_message_t *pdu)
{
    d_info("Building S1AP Initial Context Setup Request");

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_InitialContextSetupRequest_t *InitialContextSetupRequest = NULL;

    S1AP_InitialContextSetupRequestIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_UEAggregateMaximumBitrate_t *UEAggregateMaximumBitrate = NULL;
    S1AP_E_RABToBeSetupListCtxtSUReq_t *E_RABToBeSetupListCtxtSUReq = NULL;
    S1AP_UESecurityCapabilities_t *UESecurityCapabilities = NULL;
    S1AP_SecurityKey_t *SecurityKey = NULL;

    s6a_subscription_data_t subscription_data;
    
    status_t get_sub_data = get_default_s6a_subscription_data(&subscription_data);
    d_assert(get_sub_data == CORE_OK, return CORE_ERROR, "Failed to get S6a subscription data");


    memset(pdu, 0, sizeof (S1AP_S1AP_PDU_t));
    pdu->present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = 
        core_calloc(1, sizeof(S1AP_InitiatingMessage_t));

    initiatingMessage = pdu->choice.initiatingMessage;
    initiatingMessage->procedureCode =
        S1AP_ProcedureCode_id_InitialContextSetup;
    initiatingMessage->criticality = S1AP_Criticality_reject;
    initiatingMessage->value.present =
        S1AP_InitiatingMessage__value_PR_InitialContextSetupRequest;

    InitialContextSetupRequest =
        &initiatingMessage->value.choice.InitialContextSetupRequest;


    ie = core_calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ASN_SEQUENCE_ADD(&InitialContextSetupRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_InitialContextSetupRequestIEs__value_PR_MME_UE_S1AP_ID;

    MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;


    ie = core_calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ASN_SEQUENCE_ADD(&InitialContextSetupRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_InitialContextSetupRequestIEs__value_PR_ENB_UE_S1AP_ID;

    ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;


    ie = core_calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ASN_SEQUENCE_ADD(&InitialContextSetupRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_uEaggregateMaximumBitrate;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_InitialContextSetupRequestIEs__value_PR_UEAggregateMaximumBitrate;

    UEAggregateMaximumBitrate = &ie->value.choice.UEAggregateMaximumBitrate;


    ie = core_calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ASN_SEQUENCE_ADD(&InitialContextSetupRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
    S1AP_InitialContextSetupRequestIEs__value_PR_E_RABToBeSetupListCtxtSUReq;

    E_RABToBeSetupListCtxtSUReq = &ie->value.choice.E_RABToBeSetupListCtxtSUReq;


    ie = core_calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ASN_SEQUENCE_ADD(&InitialContextSetupRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_UESecurityCapabilities;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_InitialContextSetupRequestIEs__value_PR_UESecurityCapabilities;

    UESecurityCapabilities = &ie->value.choice.UESecurityCapabilities;


    ie = core_calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ASN_SEQUENCE_ADD(&InitialContextSetupRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_SecurityKey;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_InitialContextSetupRequestIEs__value_PR_SecurityKey;

    SecurityKey = &ie->value.choice.SecurityKey;

    

    *MME_UE_S1AP_ID = array_to_int(db_pulls->mme_ue_s1ap_id);
    *ENB_UE_S1AP_ID = array_to_int(db_pulls->enb_ue_s1ap_id);

    asn_uint642INTEGER(
            &UEAggregateMaximumBitrate->uEaggregateMaximumBitRateUL, 
            subscription_data.ambr.uplink);
    asn_uint642INTEGER(
            &UEAggregateMaximumBitrate->uEaggregateMaximumBitRateDL, 
            subscription_data.ambr.downlink);

    S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t *item = NULL;
    S1AP_E_RABToBeSetupItemCtxtSUReq_t *e_rab = NULL;
    S1AP_NAS_PDU_t *nasPdu = NULL;


    item = core_calloc(
            1, sizeof(S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t));
    ASN_SEQUENCE_ADD(&E_RABToBeSetupListCtxtSUReq->list, item);

    item->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq;
    item->criticality = S1AP_Criticality_reject;
    item->value.present = S1AP_E_RABToBeSetupItemCtxtSUReqIEs__value_PR_E_RABToBeSetupItemCtxtSUReq;

    e_rab = &item->value.choice.E_RABToBeSetupItemCtxtSUReq;

    e_rab->e_RAB_ID = 5; // TODO: fixed value may need to be derived
    e_rab->e_RABlevelQoSParameters.qCI = 9;

    e_rab->e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel = 1; // highest
    e_rab->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionCapability = 0; // shall-not-trigger-pre-emption
    e_rab->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionVulnerability = 0; // not-pre-emptable

    int sgw_s1u_ip = ntohl(inet_addr("192.168.56.106"));
    s1ap_uint32_to_OCTET_STRING(sgw_s1u_ip, (OCTET_STRING_t *) &e_rab->transportLayerAddress);

    // the following is a bodge, but since the data plane isn't implemented, it is acceptable
    // set the TEID to the TMSI of the UE
    d_assert(db_pulls->tmsi != NULL, return CORE_ERROR, "DB TMSI is NULL");
    c_uint32_t tmsi = array_to_int(db_pulls->tmsi);
    s1ap_uint32_to_OCTET_STRING(tmsi, &e_rab->gTP_TEID);


    if (emmbuf && emmbuf->len)
    {
        nasPdu = (S1AP_NAS_PDU_t *)core_calloc(
                1, sizeof(S1AP_NAS_PDU_t));
        nasPdu->size = emmbuf->len;
        nasPdu->buf = core_calloc(nasPdu->size, sizeof(c_uint8_t));
        memcpy(nasPdu->buf, emmbuf->payload, nasPdu->size);
        e_rab->nAS_PDU = nasPdu;
        pkbuf_free(emmbuf);
    }


    UESecurityCapabilities->encryptionAlgorithms.size = 2;
    UESecurityCapabilities->encryptionAlgorithms.buf = 
        core_calloc(UESecurityCapabilities->encryptionAlgorithms.size, 
                    sizeof(c_uint8_t));
    UESecurityCapabilities->encryptionAlgorithms.bits_unused = 0;
    UESecurityCapabilities->encryptionAlgorithms.buf[0] = 0x00; // no encryption

    UESecurityCapabilities->integrityProtectionAlgorithms.size = 2;
    UESecurityCapabilities->integrityProtectionAlgorithms.buf =
        core_calloc(UESecurityCapabilities->
                        integrityProtectionAlgorithms.size, sizeof(c_uint8_t));
    UESecurityCapabilities->integrityProtectionAlgorithms.bits_unused = 0;
    UESecurityCapabilities->integrityProtectionAlgorithms.buf[0] = 0b01000000; // 128-EIA2


    // set the security key to zero bytes, it is not used
    SecurityKey->size = SHA256_DIGEST_SIZE;
    SecurityKey->buf = 
        core_calloc(SecurityKey->size, sizeof(c_uint8_t));
    SecurityKey->bits_unused = 0;

    c_uint8_t kenb[SHA256_DIGEST_SIZE];
    c_uint8_t kasme[SHA256_DIGEST_SIZE];
    c_uint8_t knh[SHA256_DIGEST_SIZE];

    // kasme is stored in the DB as two 16-byte values, kasme1 and kasme2
    memcpy(kasme, db_pulls->kasme1, SHA256_DIGEST_SIZE/2);
    memcpy(kasme+SHA256_DIGEST_SIZE/2, db_pulls->kasme2, SHA256_DIGEST_SIZE/2);

    // the ul_count is stored in the DB as 6-bytes, we only care about 4-bytes
    // subtract 1 from the count because it is accessed separately and therefore will
    // be one larger than it would otherwise be
    c_uint32_t nas_ul_count = 0; //array_to_int(db_pulls->ue_nas_sequence_number+2) - 1;

    // calculate the Kenb from Kasme
    kdf_enb(kasme, nas_ul_count, kenb);

    // calculate the Knh from Kasme and Kenb
    mme_kdf_nh(kasme, kenb, knh);

    // store the knh in the DB
    status_t db_store = store_knh_in_db(*MME_UE_S1AP_ID, knh);
    d_assert(db_store == CORE_OK, return CORE_ERROR, "Failed to store Knh in DB");

    memcpy(SecurityKey->buf, kenb, SecurityKey->size);

    return CORE_OK;
}

status_t store_knh_in_db(S1AP_MME_UE_S1AP_ID_t mme_ue_s1ap_id, c_uint8_t * knh) {
    int n;
    c_uint8_t buffer[1024];

    // convert the MME ID to a buffer
    OCTET_STRING_t raw_mme_us_s1ap_id;
    s1ap_uint32_to_OCTET_STRING(mme_ue_s1ap_id, &raw_mme_us_s1ap_id);

    // save the new eNB into the DB
    n = push_items(buffer, MME_UE_S1AP_ID, raw_mme_us_s1ap_id.buf, 2, KNH_1, knh, KNH_2, knh+16);
    n = pull_items(buffer, n, 0);

    d_info("DB access, waiting for mutex");
    pthread_mutex_lock(&db_sock_mutex);
    d_info("DB access, mutex accessed");
    send_request(db_sock, buffer, n);
    pthread_mutex_unlock(&db_sock_mutex);
    d_info("DB access, received response");

    return CORE_OK;
}