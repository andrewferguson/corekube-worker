#ifndef __S1AP_HANDLER_INITIALUEMESSAGE_H__
#define __S1AP_HANDLER_INITIALUEMESSAGE_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "s1ap_handler.h"

#include "nas_attach.h"

#include "nas/nas_message.h"

// Forward declaration
c_int32_t nas_decode_attach_request(nas_message_t *message, pkbuf_t *pkbuf);

S1AP_handle_outcome_t handle_initialuemessage(s1ap_message_t *received_message, s1ap_message_t *response);

status_t extract_PLMNidentity(S1AP_InitialUEMessage_t *initialUEMessage, S1AP_PLMNidentity_t **PLMNidentity);

status_t extract_ENB_UE_ID(S1AP_InitialUEMessage_t *initialUEMessage, S1AP_ENB_UE_S1AP_ID_t **ENB_UE_ID);

status_t get_InitialUE_IE(S1AP_InitialUEMessage_t *initialUEMessage, S1AP_InitialUEMessage_IEs__value_PR desiredIElabel, S1AP_InitialUEMessage_IEs_t **desiredIE);

status_t get_initialue_prerequisites_from_db(nas_mobile_identity_imsi_t *imsi, c_uint8_t *buffer, corekube_db_pulls_t *db_pulls);

status_t save_initialue_info_in_db(nas_mobile_identity_imsi_t * imsi, nas_authentication_vector_t *auth_vec, S1AP_ENB_UE_S1AP_ID_t *enb_ue_id);

#endif /* __S1AP_HANDLER_INITIALUEMESSAGE_H__ */