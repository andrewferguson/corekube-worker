
// Client side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>

#include "s1ap/asn1c/asn_system.h"
#include "core/include/core_lib.h"
#include "core/include/core_debug.h"
#include "core/include/3gpp_types.h"

#define MAXLINE 1024

int PORT;
  
// Driver code 
int send_message(char *mme_ip, char *payload, int numResponse) {

    int sockfd; 
    char buffer[MAXLINE]; 
    struct sockaddr_in     servaddr; 
  
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        d_error("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
  
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    servaddr.sin_addr.s_addr = inet_addr(mme_ip);
      
    uint n, len; 

    char hexbuf[MAX_SDU_LEN];
    CORE_HEX(payload, strlen(payload), hexbuf);

    d_print_hex(hexbuf, strlen(payload) / 2);
      
    sendto(sockfd, (const char *)hexbuf, strlen(payload) / 2, 
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr)); 
    d_info("Message sent"); 

    for (int i = 0; i < numResponse; i++) {
        d_info("Waiting for response %d of %d.", i, numResponse);
        n = recvfrom(sockfd, (char *)buffer, MAXLINE,  
                    MSG_WAITALL, (struct sockaddr *) &servaddr, 
                    &len); 
        d_info("Received message from server"); 
        d_print_hex(buffer, n);
    }
  
    close(sockfd); 
    return 0; 
}


void runMessage(char * ip_address, int message_number) {
    char *S1SetupRequest =
        "0f0a0c0e"
        "00110037000004003b00080002f83900"
        "00e000003c40140880654e425f457572"
        "65636f6d5f4c5445426f780040000700"
        "00004002f8390089400140";

    char *AttachRequest =
        "0f0a0c0e"
        "000c405b00000500080003400008001a"
        "00323107417108298039000000008002"
        "802000200201d011271a808021100100"
        "0010810600000000830600000000000d"
        "00000a00004300060002f83900010064"
        "40080002f83900e000000086400130";

    char *AuthenticationResponse =
        "0f0a0c0e"
        "000d4036000005000000020008000800"
        "03400008001a000c0b07530800b51ac6"
        "a8cf6175006440080002f83900e00000"
        "004340060002f8390001";
    
    char *SecurityModeComplete =
        "0f0a0c0e"
        "000d4034000005000000020001000800"
        "048006692d001a000908475ab132f300"
        "075e006440080002f83900e000000043"
        "40060002f8390001";

    char *UECapabilityInfoIndication = 
        "0f0a0c0e"
        "00164029000003000000020008000800"
        "03400008004a00151400940100f01800"
        "03089864a0c1b83b07a0f80000";

    char *InitialContextSetupResponse = 
        "0f0a0c0e"
        "20090024000003000040020001000840"
        "048006692d0033400f000032400a0a1f"
        "c0a83866ca6fe0dd";
    
    char *AttachComplete = 
        "0f0a0c0e"
        "000d4039000005000000020001000800"
        "048006692d001a000e0d276a60cd5501"
        "074300035200c2006440080002f83900"
        "e00000004340060002f8390001";

    char *DetachRequest =
        "0f0a0c0e"
        "000d404000000500000002000100080003400001001a00161527bd9a"
        "d244020745010bf602f83900040100000001006440080002f83900e000000043"
        "00060002f8390001";

    char * UEContextReleaseComplete =
        "0f0a0c0e"
        "20170010200002000000020003000800"
        "03400003";

    char * AuthenticationFailure =
        "0f0a0c0e"
        "000d403d000005000000020001000800"
        "020001001a001413075c15300edc1863"
        "9ef6c751e7768e819dac120064400800"
        "02f8390019b010004340060002f83900"
        "02";

    char * HandoverRequired = 
        "0f0a0c0e"
        "00000080db00000600000002"
        "00040008000200030001000100000240"
        "0202000004000d0000f110000019c000"
        "f110000100680080ab80a940808c0a10"
        "26dd8000018000f3020800001000a040"
        "0a200425000c00aa0004008a48000100"
        "000825050004d015800004068b020000"
        "9e00029009400000004246b6df07d40c"
        "a0bc8ca283a7397330f4179706664306"
        "980004c810001f008012180000004004"
        "0300010019b01814601082800ce1bf78"
        "8800ca11e00100000801829945ab9c30"
        "c6a6ccc1c0d1680128dd00004e400245"
        "000000f1100019c0100000f1100019b0"
        "1100000c";

    char * HandoverRequestAcknowledge =
        "0f0a0c0e"
        "2001005c0000040000400200"
        "050008400200020012401a0000144015"
        "60a1f0c0a80103000000040f80c0a801"
        "0300000005007b002b2a0028013100d8"
        "800000203458100002f000b002400420"
        "002000000bcb833321834c0002640800"
        "0f840900";

    char * ENBStatusTransfer =
        "0f0a0c0e"
        "001840240000030000000200"
        "04000800020003005a00110000005940"
        "0b0500010d000000010d0000";

    char * HandoverNotify =
        "0f0a0c0e"
        "000240250000040000000200"
        "05000800020002006440080000f11000"
        "19c010004340060000f1100001";

    switch (message_number) {
        case 1:
            send_message(ip_address, S1SetupRequest, 1);
            break;
        case 2:
            send_message(ip_address, AttachRequest, 1);
            break;
        case 3:
            send_message(ip_address, AuthenticationResponse, 1);
            break;
        case 4:
            send_message(ip_address, SecurityModeComplete, 1);
            break;
        case 5:
            send_message(ip_address, InitialContextSetupResponse, 0);
            break;
        case 6:
            send_message(ip_address, UECapabilityInfoIndication, 0);
            break;
        case 7:
            send_message(ip_address, AttachComplete, 0);
            break;
        case 8:
            send_message(ip_address, DetachRequest, 2);
            break;
        case 9:
            send_message(ip_address, UEContextReleaseComplete, 0);
            break;
        case 10:
            send_message(ip_address, AuthenticationFailure, 1);
            break;
        case 11:
            send_message(ip_address, HandoverRequired, 1);
            break;
        case 12:
            send_message(ip_address, HandoverRequestAcknowledge, 1);
            break;
        case 13:
            send_message(ip_address, ENBStatusTransfer, 1);
            break;
        case 14:
            send_message(ip_address, HandoverNotify, 1);
            break;
        default:
            d_info("Unknown message number %d", message_number);
    }
}

// Driver code
int main(int argc, char const *argv[]) {
    if(argc != 4) {
        printf("RUN: ./udp_client <MME_IP_ADDRESS> <PORT> [MESSAGE_NUMBER=0]\n");
        return 1;
    }

    char * ip_address = (char *) argv[1];

    PORT = atoi(argv[2]);

    int message_number = atoi(argv[3]);

    if (message_number < 0) {
        for (int i = 1; i <= 9; i++)
            runMessage(ip_address, i);
        return 0;
    }
    runMessage(ip_address, message_number);

    return 0;
}
