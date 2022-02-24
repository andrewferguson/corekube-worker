/*************************************************************************** 

    Copyright (C) 2019 NextEPC Inc. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

***************************************************************************/

#include "s1setuprequest.h"
#include "s1ap_handler.h"
#include "s1setupresponse.h"
#include "s1ap_conv.h"
#include <libck.h>
#include <pthread.h>

// external reference to variables in the listener
extern int db_sock;
extern pthread_mutex_t db_sock_mutex;

status_t handle_s1setuprequest(s1ap_message_t *received_message, S1AP_handler_response_t *response)
{
    d_info("Handling S1AP S1SetupReqest messge");

    S1AP_PLMNidentity_t *PLMNidentity; // TODO: free this

    status_t getPLMN = getPLMNidentity(received_message, &PLMNidentity);
    d_assert(getPLMN == CORE_OK, return CORE_ERROR, "Failed to get PLMN identity");

    c_uint32_t enb_id;
    status_t getEnbID = get_ENB_ID(received_message, &enb_id);
    d_assert(getEnbID == CORE_OK, return CORE_ERROR, "Failed to get eNB ID");

    status_t saveDB = save_enb_socket_in_db(enb_id, response->enbSocket);
    d_assert(saveDB == CORE_OK, return CORE_ERROR, "Failed to save eNB ID and socket in DB");

    s1ap_build_setup_resp(response->response, PLMNidentity);

    response->outcome = HAS_RESPONSE;

    // the S1SetupResponse is the only time that
    // the SCTP stream ID must be 0
    response->sctpStreamID = 0;

    return CORE_OK;
}

status_t getPLMNidentity(s1ap_message_t *received_message, S1AP_PLMNidentity_t **PLMNidentity)
{
    d_info("Fetching PLMN identity from S1AP S1SetupReqest message");

    S1AP_S1SetupRequest_t *S1SetupRequest = &received_message->choice.initiatingMessage->value.choice.S1SetupRequest;
    int numIEs = S1SetupRequest->protocolIEs.list.count;
    for (int i = 0; i < numIEs; i++) {
        S1AP_S1SetupRequestIEs_t *theIE = S1SetupRequest->protocolIEs.list.array[i];
        if (theIE->value.present == S1AP_S1SetupRequestIEs__value_PR_SupportedTAs) {
            int numSupportedTAs = theIE->value.choice.SupportedTAs.list.count;
            for (int j = 0; j < numSupportedTAs; j++) {
                int numPLMNs = theIE->value.choice.SupportedTAs.list.array[j]->broadcastPLMNs.list.count;
                for (int k = 0; k < numPLMNs; k++) {
                    *PLMNidentity = theIE->value.choice.SupportedTAs.list.array[j]->broadcastPLMNs.list.array[k];
                }
            }
        }
    }
    return CORE_OK;
}

status_t get_ENB_ID(s1ap_message_t * received_message, c_uint32_t *enb_id) {
    d_info("Extracting ENB ID from S1 Setup Request");

    S1AP_Global_ENB_ID_t *Global_ENB_ID = NULL;
    S1AP_S1SetupRequest_t *S1SetupRequest = &received_message->choice.initiatingMessage->value.choice.S1SetupRequest;

    for (int i = 0; i < S1SetupRequest->protocolIEs.list.count; i++)
    {
        S1AP_S1SetupRequestIEs_t * ie = S1SetupRequest->protocolIEs.list.array[i];
        if (ie->id == S1AP_ProtocolIE_ID_id_Global_ENB_ID) {
            Global_ENB_ID = &ie->value.choice.Global_ENB_ID;
            break;
        }
    }

    d_assert(Global_ENB_ID, return CORE_ERROR, "Failed to find ENB_ID");

    s1ap_ENB_ID_to_uint32(&Global_ENB_ID->eNB_ID, enb_id);

    return CORE_OK;
}

status_t save_enb_socket_in_db(c_uint32_t enb_id, c_uint32_t enb_sock) {
    d_info("Saving eNB ID and socket into DB");

    OCTET_STRING_t raw_enb_id;
    s1ap_uint32_to_OCTET_STRING(enb_id, &raw_enb_id);

    OCTET_STRING_t raw_enb_sock;
    s1ap_uint32_to_OCTET_STRING(enb_sock, &raw_enb_sock);

    int n;
    c_uint8_t buffer[1024];

    // save the new eNB into the DB
    n = push_items(buffer, NEW_ENB, NULL, 1, NEW_ENB, raw_enb_id.buf, raw_enb_sock.buf);
    n = pull_items(buffer, n, 0);

    d_info("DB access, waiting for mutex");
    pthread_mutex_lock(&db_sock_mutex);
    d_info("DB access, mutex accessed");
    send_request(db_sock, buffer, n);
    pthread_mutex_unlock(&db_sock_mutex);
    d_info("DB access, received response");

    return CORE_OK;
}