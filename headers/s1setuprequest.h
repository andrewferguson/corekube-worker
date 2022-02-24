#ifndef __S1AP_HANDLER_S1SETUPREQUEST_H__
#define __S1AP_HANDLER_S1SETUPREQUEST_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "s1ap_handler.h"

status_t handle_s1setuprequest(s1ap_message_t *received_message, S1AP_handler_response_t *response);

status_t getPLMNidentity(s1ap_message_t *received_message, S1AP_PLMNidentity_t **PLMNidentity);

status_t get_ENB_ID(s1ap_message_t * received_message, c_uint32_t *enb_id);

status_t save_enb_socket_in_db(c_uint32_t enb_id, c_uint32_t enb_sock);

#endif /* __S1AP_HANDLER_S1SETUPREQUEST_H__ */