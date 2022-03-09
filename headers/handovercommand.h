#ifndef __S1AP_HANDLER_HANDOVERCOMMAND_H__
#define __S1AP_HANDLER_HANDOVERCOMMAND_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "core/include/3gpp_types.h"

#define COREKUBE_DEFAULT_IP 0
#define COREKUBE_DEFAULT_TEID 0

typedef struct handover_command_params {
    S1AP_HandoverType_t handovertype;
    S1AP_MME_UE_S1AP_ID_t mme_ue_s1ap_id;
    S1AP_ENB_UE_S1AP_ID_t enb_ue_s1ap_id;
    S1AP_Target_ToSource_TransparentContainer_t *Target_ToSource_TransparentContainer;
    c_uint32_t sgw_dl_ip;
    c_uint32_t sgw_ul_ip;
    c_uint32_t sgw_dl_teid;
    c_uint32_t sgw_ul_teid;

} handover_command_params_t;


status_t s1ap_build_handover_command(handover_command_params_t *params, s1ap_message_t *response);

#endif /* __S1AP_HANDLER_HANDOVERCOMMAND_H__ */