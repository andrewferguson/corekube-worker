#ifndef __S1AP_HANDLER_UE_INITIAL_CONTEXT_RELEASE_COMMAND_H__
#define __S1AP_HANDLER_UE_INITIAL_CONTEXT_RELEASE_COMMAND_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "core/include/core_pkbuf.h"

typedef struct ue_context_release_command_params {
    S1AP_MME_UE_S1AP_ID_t mme_ue_id;
    S1AP_ENB_UE_S1AP_ID_t enb_ue_id;
    S1AP_Cause_t cause;
} ue_context_release_command_params_t;

status_t s1ap_build_ue_context_release_command(ue_context_release_command_params_t *params, s1ap_message_t *pdu);


#endif /* __S1AP_HANDLER_UE_INITIAL_CONTEXT_RELEASE_COMMAND_H__ */