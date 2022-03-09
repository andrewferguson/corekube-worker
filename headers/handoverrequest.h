#ifndef __S1AP_HANDLER_HANDOVERREQUEST_H__
#define __S1AP_HANDLER_HANDOVERREQUEST_H__

#include "s1ap/asn1c/asn_system.h"
#include "s1ap/s1ap_message.h"
#include "core/include/3gpp_types.h"
#include "core/include/core_sha2.h"

#define COREKUBE_DEFAULT_QCI 9
#define COREKUBE_DEFAULT_EBI 5

#define COREKUBE_DEFAULT_ARP_PRIORITY_LEVEL 1
#define COREKUBE_DEFAULT_ARP_PRE_EMPTION_CAPABILITY 0 // shall-not-trigger-pre-emption
#define COREKUBE_DEFAULT_ARP_PRE_EMPTION_VULNERABILITY 0 // not-pre-emptable

#define DEFAULT_UPLINK_BITRATE 100000000
#define DEFAULT_DOWNLINK_BITRATE 200000000

typedef struct handover_request_params {
    S1AP_HandoverType_t *handovertype;
    S1AP_Cause_t *cause;
    S1AP_Source_ToTarget_TransparentContainer_t *source_totarget_transparentContainer;
    c_uint32_t ipv4_addr;
    c_uint32_t sgw_teid;
    S1AP_MME_UE_S1AP_ID_t mme_ue_s1ap_id;
    c_uint8_t nhcc;
    c_uint8_t nh[SHA256_DIGEST_SIZE];;

} handover_request_params_t;


status_t s1ap_build_handover_request(handover_request_params_t *params, s1ap_message_t *response);



#endif /* __S1AP_HANDLER_HANDOVERREQUEST_H__ */
