#include <limits.h> //TODO: this should not be necessary, it's included in core.h
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "s6a_message.h"

#include "core/include/core_pkbuf.h"
#include <string.h>
#include <arpa/inet.h>

status_t get_default_s6a_subscription_data(s6a_subscription_data_t * subscription_data) {
    d_info("Getting Default S6a Subscription Data");

    memset(subscription_data, 0, sizeof(s6a_subscription_data_t));

    bitrate_t * ambr;
    
    // define the defaut AMBR bitrates
    ambr = &subscription_data->ambr;
    ambr->uplink = 100000000;
    ambr->downlink = 200000000;

    // TODO: currently this is only used by
    //       s1ap_build_initial_context_setup_request()
    //       which only requires ambr->uplink / downlink to be set
    //       In the future it is likely further attributes will need
    //       be filled!

    return CORE_OK;
}