#ifndef __S1AP_HANDLER_HANDOVERREQUESTACKNOWLEDGE_H__
#define __S1AP_HANDLER_HANDOVERREQUESTACKNOWLEDGE_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "s1ap_handler.h"
#include <libck.h>


status_t handle_handoverrequestacknowledge(s1ap_message_t *received_message, S1AP_handler_response_t *response);

status_t get_handover_request_acknowledge_prerequisites_from_db(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, S1AP_ENB_UE_S1AP_ID_t * target_enb_ue_s1ap_id, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls);


#endif /* __S1AP_HANDLER_HANDOVERREQUESTACKNOWLEDGE_H__ */