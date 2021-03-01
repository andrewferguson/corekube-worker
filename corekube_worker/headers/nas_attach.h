#ifndef __S1AP_HANDLER_NAS_ATTACH_H__
#define __S1AP_HANDLER_NAS_ATTACH_H__

#include "nas_message.h"
#include "s1ap/s1ap_message.h"

#include "core_sha2_hmac.h"

#include <libck.h>

typedef struct nas_authentication_vector {
    c_uint8_t rand[RAND_LEN];
    c_uint8_t autn[AUTN_LEN];
    c_uint8_t res[MAX_RES_LEN];
    c_uint8_t knas_int[SHA256_DIGEST_SIZE/2];
    c_uint8_t knas_enc[SHA256_DIGEST_SIZE/2];
    c_uint8_t kasme[SHA256_DIGEST_SIZE];
} nas_authentication_vector_t;

status_t get_authentication_vector(nas_mobile_identity_imsi_t *imsi, S1AP_PLMNidentity_t *PLMNidentity, corekube_db_pulls_t *db_pulls, nas_authentication_vector_t *auth_vec);

status_t extract_raw_imsi(nas_mobile_identity_imsi_t *imsi, c_uint8_t *raw_imsi);

status_t generate_authentication_vector(c_uint8_t *k, c_uint8_t *opc, c_uint8_t *rand, c_uint8_t *sqn, c_uint8_t *plmn_id, nas_authentication_vector_t *auth_vec);

status_t check_network_capabilities(nas_message_t *nas_message);

status_t extract_imsi(nas_attach_request_t *attach_request, nas_mobile_identity_imsi_t **imsi);

status_t decode_attach_request(S1AP_InitialUEMessage_t *initialUEMessage, nas_message_t *attach_request);

#endif /* __S1AP_HANDLER_NAS_ATTACH_H__ */