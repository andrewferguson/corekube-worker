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

S1AP_handle_outcome_t handle_s1setuprequest(s1ap_message_t *received_message, s1ap_message_t *response)
{
    S1AP_PLMNidentity_t *PLMNidentity; // TODO: free this

    getPLMNidentity(received_message, &PLMNidentity);

    s1ap_build_setup_resp(response, PLMNidentity);

    return HAS_RESPONSE;
}

static status_t getPLMNidentity(s1ap_message_t *received_message, S1AP_PLMNidentity_t **PLMNidentity)
{
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