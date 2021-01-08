#ifndef __S1AP_HANDLER_H__
#define __S1AP_HANDLER_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "core/include/core_pkbuf.h"

typedef enum S1AP_handle_outcome {NO_RESPONSE, HAS_RESPONSE} S1AP_handle_outcome_t;

typedef struct S1AP_handler_response {
    S1AP_handle_outcome_t outcome;
    // the response can either be a pointer to an s1ap_message_t
    // or a pointer to a pkbuf_t, so use void* to allow it to
    // take on both types
    void * response;
} S1AP_handler_response_t;

status_t s1ap_handler_entrypoint(void *incoming, int incoming_len, S1AP_handler_response_t *response);

static status_t bytes_to_message(void *payload, int payload_len, s1ap_message_t *message);

static status_t message_to_bytes(S1AP_handler_response_t *response);

static status_t s1ap_message_handler(s1ap_message_t *message, S1AP_handler_response_t *response);

static status_t s1ap_initiatingMessage_handler(s1ap_message_t *initiatingMessage, S1AP_handler_response_t *response);

#endif /* __S1AP_HANDLER_H__ */