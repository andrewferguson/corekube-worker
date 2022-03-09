#include "handovercommand.h"
#include "handoverrequest.h"
#include "s1ap_conv.h"

status_t s1ap_build_handover_command(handover_command_params_t *params, s1ap_message_t *response) {
    d_info("Building Handover Command");

    S1AP_SuccessfulOutcome_t *successfulOutcome = NULL;
    S1AP_HandoverCommand_t *HandoverCommand = NULL;

    S1AP_HandoverCommandIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_HandoverType_t *HandoverType = NULL;
    S1AP_E_RABSubjecttoDataForwardingList_t
        *E_RABSubjecttoDataForwardingList = NULL;
    S1AP_Target_ToSource_TransparentContainer_t *Target_ToSource_TransparentContainer = NULL;

    memset(response, 0, sizeof (S1AP_S1AP_PDU_t));
    response->present = S1AP_S1AP_PDU_PR_successfulOutcome;
    response->choice.successfulOutcome = 
        core_calloc(1, sizeof(S1AP_SuccessfulOutcome_t));

    successfulOutcome = response->choice.successfulOutcome;
    successfulOutcome->procedureCode =
        S1AP_ProcedureCode_id_HandoverPreparation;
    successfulOutcome->criticality = S1AP_Criticality_reject;
    successfulOutcome->value.present =
        S1AP_SuccessfulOutcome__value_PR_HandoverCommand;

    HandoverCommand = &successfulOutcome->value.choice.HandoverCommand;
    d_assert(HandoverCommand, return CORE_ERROR,);

    ie = core_calloc(1, sizeof(S1AP_HandoverCommandIEs_t));
    ASN_SEQUENCE_ADD(&HandoverCommand->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_HandoverCommandIEs__value_PR_MME_UE_S1AP_ID;

    MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;

    ie = core_calloc(1, sizeof(S1AP_HandoverCommandIEs_t));
    ASN_SEQUENCE_ADD(&HandoverCommand->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_HandoverCommandIEs__value_PR_ENB_UE_S1AP_ID;

    ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;

    ie = core_calloc(1, sizeof(S1AP_HandoverCommandIEs_t));
    ASN_SEQUENCE_ADD(&HandoverCommand->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_HandoverType;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_HandoverCommandIEs__value_PR_HandoverType;

    HandoverType = &ie->value.choice.HandoverType;

    *MME_UE_S1AP_ID = params->mme_ue_s1ap_id;
    *ENB_UE_S1AP_ID = params->enb_ue_s1ap_id;
    *HandoverType = params->handovertype;

    S1AP_E_RABDataForwardingItem_t *e_rab = NULL;

    S1AP_E_RABDataForwardingItemIEs_t *item = NULL;

    ie = core_calloc(1, sizeof(S1AP_HandoverCommandIEs_t));
    d_assert(ie, return CORE_ERROR,);
    ASN_SEQUENCE_ADD(&HandoverCommand->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_E_RABSubjecttoDataForwardingList;
    ie->criticality = S1AP_Criticality_ignore;
    ie->value.present =
        S1AP_HandoverCommandIEs__value_PR_E_RABSubjecttoDataForwardingList;

    E_RABSubjecttoDataForwardingList =
        &ie->value.choice.E_RABSubjecttoDataForwardingList;

    item = core_calloc(
            1, sizeof(S1AP_E_RABDataForwardingItemIEs_t));
    d_assert(item, return CORE_ERROR,);
    ASN_SEQUENCE_ADD(&E_RABSubjecttoDataForwardingList->list, item);

    item->id = S1AP_ProtocolIE_ID_id_E_RABDataForwardingItem;
    item->criticality = S1AP_Criticality_ignore;
    item->value.present =
        S1AP_E_RABDataForwardingItemIEs__value_PR_E_RABDataForwardingItem;

    e_rab = &item->value.choice.E_RABDataForwardingItem;
    d_assert(e_rab, return CORE_ERROR,);

    e_rab->e_RAB_ID = COREKUBE_DEFAULT_EBI;

    d_assert(e_rab, return CORE_ERROR,);
    e_rab->dL_transportLayerAddress =
        (S1AP_TransportLayerAddress_t *)
        core_calloc(1, sizeof(S1AP_TransportLayerAddress_t));
    e_rab->dL_transportLayerAddress->size = IPV4_LEN;
    e_rab->dL_transportLayerAddress->buf = core_calloc(IPV4_LEN, sizeof(c_uint8_t));
    memcpy(e_rab->dL_transportLayerAddress->buf, &params->sgw_dl_ip, IPV4_LEN);

    e_rab->dL_gTP_TEID = (S1AP_GTP_TEID_t *)
        core_calloc(1, sizeof(S1AP_GTP_TEID_t));
    s1ap_uint32_to_OCTET_STRING(
            params->sgw_dl_teid, e_rab->dL_gTP_TEID);

    d_assert(e_rab, return CORE_ERROR,);
    e_rab->uL_TransportLayerAddress =
        (S1AP_TransportLayerAddress_t *)
        core_calloc(1, sizeof(S1AP_TransportLayerAddress_t));
    e_rab->uL_TransportLayerAddress->size = IPV4_LEN;
    e_rab->uL_TransportLayerAddress->buf = core_calloc(IPV4_LEN, sizeof(c_uint8_t));
    memcpy(e_rab->uL_TransportLayerAddress->buf, &params->sgw_ul_ip, IPV4_LEN);

    e_rab->uL_GTP_TEID = (S1AP_GTP_TEID_t *)
        core_calloc(1, sizeof(S1AP_GTP_TEID_t));
    s1ap_uint32_to_OCTET_STRING(
            params->sgw_ul_teid, e_rab->uL_GTP_TEID);

    ie = core_calloc(1, sizeof(S1AP_HandoverCommandIEs_t));
    ASN_SEQUENCE_ADD(&HandoverCommand->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_Target_ToSource_TransparentContainer;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_HandoverCommandIEs__value_PR_Target_ToSource_TransparentContainer;

    Target_ToSource_TransparentContainer =
        &ie->value.choice.Target_ToSource_TransparentContainer;

    s1ap_buffer_to_OCTET_STRING(params->Target_ToSource_TransparentContainer->buf, params->Target_ToSource_TransparentContainer->size, 
            Target_ToSource_TransparentContainer);

    return CORE_OK;
}