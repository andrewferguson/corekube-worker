#include "handoverrequest.h"
#include "s1ap_conv.h"
#include "nas_message_security.h" // for the EEA / EIA constants

status_t s1ap_build_handover_request(handover_request_params_t *params, s1ap_message_t *response) {
    d_info("Building Handover Request");

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_HandoverRequest_t *HandoverRequest = NULL;

    S1AP_HandoverRequestIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_HandoverType_t *HandoverType = NULL;
    S1AP_Cause_t *Cause = NULL;
    S1AP_UEAggregateMaximumBitrate_t *UEAggregateMaximumBitrate = NULL;
    S1AP_E_RABToBeSetupListHOReq_t *E_RABToBeSetupListHOReq = NULL;
    S1AP_Source_ToTarget_TransparentContainer_t
        *Source_ToTarget_TransparentContainer = NULL;
    S1AP_UESecurityCapabilities_t *UESecurityCapabilities = NULL;
    S1AP_SecurityContext_t *SecurityContext = NULL;
    d_assert(params->handovertype, return CORE_ERROR, "No handover type");
    d_assert(params->cause, return CORE_ERROR, "No cause");
    d_assert(params->source_totarget_transparentContainer, return CORE_ERROR, "No SourceToTarget container");

    memset(response, 0, sizeof (S1AP_S1AP_PDU_t));
    response->present = S1AP_S1AP_PDU_PR_initiatingMessage;
    response->choice.initiatingMessage = 
        core_calloc(1, sizeof(S1AP_InitiatingMessage_t));

    initiatingMessage = response->choice.initiatingMessage;
    initiatingMessage->procedureCode =
        S1AP_ProcedureCode_id_HandoverResourceAllocation;
    initiatingMessage->criticality = S1AP_Criticality_reject;
    initiatingMessage->value.present =
        S1AP_InitiatingMessage__value_PR_HandoverRequest;

    HandoverRequest = &initiatingMessage->value.choice.HandoverRequest;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_HandoverRequestIEs__value_PR_MME_UE_S1AP_ID;

    MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_HandoverType;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_HandoverRequestIEs__value_PR_HandoverType;

    HandoverType = &ie->value.choice.HandoverType;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_Cause;
    ie->criticality = S1AP_Criticality_ignore;
    ie->value.present = S1AP_HandoverRequestIEs__value_PR_Cause;

    Cause = &ie->value.choice.Cause;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_uEaggregateMaximumBitrate;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_HandoverRequestIEs__value_PR_UEAggregateMaximumBitrate;

    UEAggregateMaximumBitrate = &ie->value.choice.UEAggregateMaximumBitrate;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupListHOReq;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_HandoverRequestIEs__value_PR_E_RABToBeSetupListHOReq;

    E_RABToBeSetupListHOReq = &ie->value.choice.E_RABToBeSetupListHOReq;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_Source_ToTarget_TransparentContainer;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_HandoverRequestIEs__value_PR_Source_ToTarget_TransparentContainer;

    Source_ToTarget_TransparentContainer =
        &ie->value.choice.Source_ToTarget_TransparentContainer;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_UESecurityCapabilities;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_HandoverRequestIEs__value_PR_UESecurityCapabilities;

    UESecurityCapabilities = &ie->value.choice.UESecurityCapabilities;

    ie = core_calloc(1, sizeof(S1AP_HandoverRequestIEs_t));
    ASN_SEQUENCE_ADD(&HandoverRequest->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_SecurityContext;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_HandoverRequestIEs__value_PR_SecurityContext;

    SecurityContext = &ie->value.choice.SecurityContext;

    *MME_UE_S1AP_ID = params->mme_ue_s1ap_id;
    *HandoverType = *params->handovertype;
    Cause->present = params->cause->present;
    Cause->choice.radioNetwork = params->cause->choice.radioNetwork;

    asn_uint642INTEGER(
            &UEAggregateMaximumBitrate->uEaggregateMaximumBitRateUL, 
            DEFAULT_UPLINK_BITRATE);
    asn_uint642INTEGER(
            &UEAggregateMaximumBitrate->uEaggregateMaximumBitRateDL, 
            DEFAULT_DOWNLINK_BITRATE);

    S1AP_E_RABToBeSetupItemHOReqIEs_t *item = NULL;
    S1AP_E_RABToBeSetupItemHOReq_t *e_rab = NULL;

    item = core_calloc(1, sizeof(S1AP_E_RABToBeSetupItemHOReqIEs_t));
    ASN_SEQUENCE_ADD(&E_RABToBeSetupListHOReq->list, item);

    item->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupItemHOReq;
    item->criticality = S1AP_Criticality_reject;
    item->value.present =
    S1AP_E_RABToBeSetupItemHOReqIEs__value_PR_E_RABToBeSetupItemHOReq;

    e_rab = &item->value.choice.E_RABToBeSetupItemHOReq;

    e_rab->e_RAB_ID = COREKUBE_DEFAULT_EBI;
    e_rab->e_RABlevelQosParameters.qCI = COREKUBE_DEFAULT_QCI;

    e_rab->e_RABlevelQosParameters.allocationRetentionPriority.
        priorityLevel = COREKUBE_DEFAULT_ARP_PRIORITY_LEVEL;
    e_rab->e_RABlevelQosParameters.allocationRetentionPriority.
        pre_emptionCapability =
            !(COREKUBE_DEFAULT_ARP_PRE_EMPTION_CAPABILITY);
    e_rab->e_RABlevelQosParameters.allocationRetentionPriority.
        pre_emptionVulnerability =
            !(COREKUBE_DEFAULT_ARP_PRE_EMPTION_VULNERABILITY);

    e_rab->transportLayerAddress.size = IPV4_LEN;
    e_rab->transportLayerAddress.buf = core_calloc(IPV4_LEN, sizeof(c_uint8_t));
    memcpy(e_rab->transportLayerAddress.buf, (c_uint8_t *) &params->ipv4_addr, IPV4_LEN);
    s1ap_uint32_to_OCTET_STRING(params->sgw_teid, &e_rab->gTP_TEID);

    s1ap_buffer_to_OCTET_STRING(
            params->source_totarget_transparentContainer->buf, 
            params->source_totarget_transparentContainer->size, 
            Source_ToTarget_TransparentContainer);

    UESecurityCapabilities->encryptionAlgorithms.size = 2;
    UESecurityCapabilities->encryptionAlgorithms.buf = 
        core_calloc(UESecurityCapabilities->encryptionAlgorithms.size, 
                    sizeof(c_uint8_t));
    UESecurityCapabilities->encryptionAlgorithms.bits_unused = 0;
    UESecurityCapabilities->encryptionAlgorithms.buf[0] = EEA_JUST_EEA0;

    UESecurityCapabilities->integrityProtectionAlgorithms.size = 2;
    UESecurityCapabilities->integrityProtectionAlgorithms.buf =
        core_calloc(UESecurityCapabilities->
                        integrityProtectionAlgorithms.size, sizeof(c_uint8_t));
    UESecurityCapabilities->integrityProtectionAlgorithms.bits_unused = 0;
    UESecurityCapabilities->integrityProtectionAlgorithms.buf[0] = EEA_JUST_EIA2;

    SecurityContext->nextHopChainingCount = params->nhcc;
    SecurityContext->nextHopParameter.size = SHA256_DIGEST_SIZE;
    SecurityContext->nextHopParameter.buf = 
        core_calloc(SecurityContext->nextHopParameter.size,
        sizeof(c_uint8_t));
    SecurityContext->nextHopParameter.bits_unused = 0;
    memcpy(SecurityContext->nextHopParameter.buf,
            params->nh, SecurityContext->nextHopParameter.size);

    return CORE_OK;
}