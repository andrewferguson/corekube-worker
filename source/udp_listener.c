#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libck.h>
#include <pthread.h>

#include "s1ap_handler.h"
#include "core/include/core_general.h"

#define MME_LISTEN_PORT 5566
#define BUFFER_LEN 1024

int db_sock;

int configure_udp_socket(char * mme_ip_address)
{
	int sock_udp;
	struct sockaddr_in listener_addr;

	/****************************/
	/* Initialise socket struct */
	/****************************/
	memset(&listener_addr, 0, sizeof(listener_addr));


	/*****************/
	/* Create socket */
	/*****************/
	sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
	d_assert(sock_udp >= 0, return -1, "Failed to setup UDP socket");


	/***************************/
    /* Set up MME address */
    /***************************/
    listener_addr.sin_addr.s_addr = inet_addr(mme_ip_address); //INADDR_ANY;
    listener_addr.sin_family = AF_INET;
    listener_addr.sin_port = htons(MME_LISTEN_PORT);
    memset(&(listener_addr.sin_zero), 0, sizeof(struct sockaddr));

    /***********/
    /* Binding */
    /***********/
	int bind_outcome = bind(sock_udp,(struct sockaddr*)&listener_addr, sizeof(listener_addr));
	d_assert(bind_outcome != -1, close(sock_udp); return -1, "Failed to bind MME socket");

	return sock_udp;
}

// TODO: move to separate header
// or perhaps separate file (since
// process_message() might be able
// to be made SCTP / UDP independent?)
typedef struct process_message_args {
	int sock_udp;
	socklen_t *from_len;
	struct sockaddr_in *client_addr;
	c_uint8_t *buffer;
	int num_bytes_received;
} process_message_args_t;

void *process_message(void *raw_args) {
	process_message_args_t *args = (process_message_args_t *) raw_args;

	if (d_log_get_level(D_MSG_TO_STDOUT) >= D_LOG_LEVEL_INFO)
		d_print_hex(args->buffer, args->num_bytes_received);

	S1AP_handler_response_t response;

	status_t outcome = s1ap_handler_entrypoint((args->buffer)+4, (args->num_bytes_received)-4, &response);
	d_assert(outcome == CORE_OK, return NULL, "Failed to handle S1AP message");

	if (response.outcome == NO_RESPONSE) {
		d_info("Finished handling NO_RESPONSE message");
		return NULL;
	}

	args->client_addr->sin_port = htons(32566);
	d_print_hex(&(args->client_addr), sizeof(args->client_addr));
	d_info("S_addr: %d, ", args->client_addr->sin_addr.s_addr);
	d_info("S_port: %d, ", args->client_addr->sin_port);


	// handle the first response, if there is one
	if (response.outcome == HAS_RESPONSE || response.outcome == DUAL_RESPONSE) {
		pkbuf_t *responseBuffer = response.response;

		uint8_t response_out[responseBuffer->len + 5];
		memcpy(response_out, args->buffer, 4);
		response_out[4] = response.sctpStreamID;
		memcpy(response_out+5, responseBuffer->payload, responseBuffer->len);
		
		int ret = sendto(args->sock_udp, (void *)response_out, responseBuffer->len + 5,
			MSG_CONFIRM, (const struct sockaddr *) args->client_addr,
			*(args->from_len));

		pkbuf_free(responseBuffer);

		d_assert(ret != -1, return NULL, "Failed to send UDP message");
		d_info("Send %d bytes over UDP", ret);
	}

	// handle the (optional) second response
	if (response.outcome == DUAL_RESPONSE) {
		pkbuf_t *responseBuffer = response.response2;

		uint8_t response_out[responseBuffer->len + 5];
		memcpy(response_out, args->buffer, 4);
		response_out[4] = response.sctpStreamID;
		memcpy(response_out+5, responseBuffer->payload, responseBuffer->len);
		
		int ret = sendto(args->sock_udp, (void *)response_out, responseBuffer->len + 5,
			MSG_CONFIRM, (const struct sockaddr *) args->client_addr,
			*(args->from_len));

		pkbuf_free(responseBuffer);

		d_assert(ret != -1, return NULL, "Failed to send UDP message");
		d_info("Send %d bytes over UDP", ret);
	}

	d_info("Finished processing message");

	return NULL;
}


void start_listener(char * mme_ip_address)
{
	int sock_udp;
	int n;
	socklen_t from_len;
	struct sockaddr_in client_addr;
	uint8_t buffer[BUFFER_LEN];

	/* Initialise socket structs */
	memset(&client_addr, 0, sizeof(struct sockaddr_in));
	from_len = (socklen_t)sizeof(struct sockaddr_in);

	/* Configure the socket */
	sock_udp = configure_udp_socket(mme_ip_address);
	d_assert(sock_udp >= 0, return, "Error configuring UDP socket");
	d_info("UDP socket configured correctly.\n");

	while (1) {

		/* Wait to receive a message */
		n = recvfrom(sock_udp, (char *)buffer, BUFFER_LEN, MSG_WAITALL, ( struct sockaddr *) &client_addr, &from_len); 
		d_assert(n > 0, break, "No longer connected to eNB");

		process_message_args_t args;
		args.buffer = buffer;
		args.client_addr = &client_addr;
		args.from_len = &from_len;
		args.num_bytes_received = n;
		args.sock_udp = sock_udp;

		void *raw_args = (void *) &args;

		pthread_t thread;
		int thread_create = pthread_create(&thread, NULL, process_message, raw_args);
		d_assert(thread_create == 0, continue, "Failed to create thread"); 
	}

	d_assert(n != -1,, "An UDP error occured");

	/* Close the socket when done */
	close(sock_udp);

}


int main(int argc, char const *argv[])
{
	if(argc != 3 && argc != 4) {
		printf("RUN: ./corekube_udp_listener <WORKER_IP_ADDRESS> <DB_IP_ADDRESS> [PRODUCTION=0]\n");
		return 1;
	}
	core_initialize();

	// in production, turn off info logs
	if (argc == 4 && atoi(argv[3]))
		d_log_set_level(D_MSG_TO_STDOUT, D_LOG_LEVEL_ERROR);

	// setup the DB IP address
	//db_ip_address = (char*) core_calloc(strlen((char *)argv[2]), sizeof(char));
	//memcpy(db_ip_address, (char *)argv[2], strlen((char *)argv[2]));
	db_sock = db_connect((char *)argv[2], 0);

	start_listener((char *)argv[1]);

	db_disconnect(db_sock);

	return 0;
}
