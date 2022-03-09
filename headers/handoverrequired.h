#ifndef __S1AP_HANDLER_HANDOVERREQUIRED_H__
#define __S1AP_HANDLER_HANDOVERREQUIRED_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "s1ap_handler.h"
#include <libck.h>

status_t handle_handoverrequired(s1ap_message_t *received_message, S1AP_handler_response_t *response);

status_t get_handover_required_prerequisites_from_db(S1AP_MME_UE_S1AP_ID_t *mme_ue_id, c_uint32_t enb_id, c_uint32_t source_enb_socket, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls);

void mme_kdf_nh(c_uint8_t *kasme, c_uint8_t *sync_input, c_uint8_t *kenb);


#endif /* __S1AP_HANDLER_HANDOVERREQUIRED_H__ */