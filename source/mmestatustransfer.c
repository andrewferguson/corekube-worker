#include "mmestatustransfer.h"
#include "s1ap_conv.h"

status_t s1ap_build_mme_status_transfer(mme_status_transfer_params_t *params, s1ap_message_t *response) {
    d_info("Building MME Status Transfer message");

    S1AP_InitiatingMessage_t *initiatingMessage = NULL;
    S1AP_MMEStatusTransfer_t *MMEStatusTransfer = NULL;

    S1AP_MMEStatusTransferIEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *MME_UE_S1AP_ID = NULL;
    S1AP_ENB_UE_S1AP_ID_t *ENB_UE_S1AP_ID = NULL;
    S1AP_ENB_StatusTransfer_TransparentContainer_t
        *ENB_StatusTransfer_TransparentContainer = NULL;

    d_assert(params->enb_statustransfer_transparentContainer, return CORE_ERROR, "No enb_statustransfer_transparentContainer found");

    memset(response, 0, sizeof (S1AP_S1AP_PDU_t));
    response->present = S1AP_S1AP_PDU_PR_initiatingMessage;
    response->choice.initiatingMessage = 
        core_calloc(1, sizeof(S1AP_InitiatingMessage_t));

    initiatingMessage = response->choice.initiatingMessage;
    initiatingMessage->procedureCode = S1AP_ProcedureCode_id_MMEStatusTransfer;
    initiatingMessage->criticality = S1AP_Criticality_ignore;
    initiatingMessage->value.present =
        S1AP_InitiatingMessage__value_PR_MMEStatusTransfer;

    MMEStatusTransfer = &initiatingMessage->value.choice.MMEStatusTransfer;

    ie = core_calloc(1, sizeof(S1AP_MMEStatusTransferIEs_t));
    ASN_SEQUENCE_ADD(&MMEStatusTransfer->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_MMEStatusTransferIEs__value_PR_MME_UE_S1AP_ID;

    MME_UE_S1AP_ID = &ie->value.choice.MME_UE_S1AP_ID;

    ie = core_calloc(1, sizeof(S1AP_MMEStatusTransferIEs_t));
    ASN_SEQUENCE_ADD(&MMEStatusTransfer->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_MMEStatusTransferIEs__value_PR_ENB_UE_S1AP_ID;

    ENB_UE_S1AP_ID = &ie->value.choice.ENB_UE_S1AP_ID;

    ie = core_calloc(1, sizeof(S1AP_MMEStatusTransferIEs_t));
    ASN_SEQUENCE_ADD(&MMEStatusTransfer->protocolIEs, ie);

    ie->id = S1AP_ProtocolIE_ID_id_eNB_StatusTransfer_TransparentContainer;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
    S1AP_MMEStatusTransferIEs__value_PR_ENB_StatusTransfer_TransparentContainer;

    ENB_StatusTransfer_TransparentContainer =
        &ie->value.choice.ENB_StatusTransfer_TransparentContainer;

    *MME_UE_S1AP_ID = params->mme_ue_s1ap_id;
    *ENB_UE_S1AP_ID = params->enb_ue_s1ap_id;

    status_t copy_status_transfer = s1ap_copy_ie(
            &asn_DEF_S1AP_ENB_StatusTransfer_TransparentContainer,
            params->enb_statustransfer_transparentContainer,
            ENB_StatusTransfer_TransparentContainer);
    d_assert(copy_status_transfer == CORE_OK, return CORE_ERROR, "Failed to copy enb_statustransfer_transparentContainer");

    return CORE_OK;
}
