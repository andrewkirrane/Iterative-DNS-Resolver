/*
 * Authors: Andrew Kirrane and Jacob Weil
 * Date: 4/01/2022
 * This project is an implementation of DNS protocol to build an iterative DNS
 * query resolver
 *
 */


#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#include "dns.h"

#define MAX_QUERY_SIZE 1024
#define MAX_RESPONSE_SIZE 4096

// Note: uint8_t* is a pointer to 8 bits of data.

//Saves info thats included in query
struct query_info {
	char name[256];
	uint8_t type;
	uint8_t class;
};


//saves answer data
struct answer_info {
	char name[256];
	uint8_t data_length;
	uint8_t type;
	uint8_t class;
	uint8_t extra_data[256];
	uint32_t ttl;
};


/** parses data received in query
 *
 * @param response entire DNS response
 * @param offset location of start of query in DNS response
 *
 * @return info parsed data
 */
struct query_info get_info(uint8_t response[], int *offset) {
	struct query_info info;
	*offset += getStringFromDNS(response, (response + *offset), info.name); // get offest from DNS
	info.type = ((uint16_t)response[*offset] << 8) + response[*offset + 1]; // set query type
	info.class = ((uint16_t)response[*offset + 2] << 8) + response[*offset + 3]; // set query class
	*offset += 4; // increase offset
	return info;
}


/** Get Answer info, Takes in DNS message then parses into our desired info
 *
 * @param response entire DNS response
 * @param offset location of start of query in DNS response
 *
 * @return info previously defined struct updates that holds the response
 */
struct answer_info get_answer_info(uint8_t response[], int *offset) {
	struct answer_info info;
	*offset += getStringFromDNS(response, (response + *offset), info.name); // get offset from DNS
	info.type = ((uint16_t)response[*offset] << 8) + response[*offset + 1]; // set answer type
	info.class = ((uint16_t)response[*offset + 2] << 8) + response[*offset + 3]; // set answer class
	info.ttl = ((uint32_t)response[*offset + 4] << 24) + ((uint32_t)response[*offset + 5] << 16); // set time to live
	info.ttl += ((uint16_t)response[*offset + 6] << 8) + response[*offset + 7]; // increase time to live
	info.data_length = ((uint16_t)response[*offset + 8] << 8) + response[*offset + 9]; // set data length
	for(int i = 0; i < info.data_length; i++) { // append any extra data into array
		info.extra_data[i] = response[*offset + i + 10];
	}
	*offset += 10 + info.data_length;
	return info;
}

//forward declaration
char *send_q(char* root, char* host, bool is_mx, int sock, char *ans);
char *process_request(struct answer_info *answers, uint8_t *response, int num_ans, char *hostname, bool is_mx, int sock, char *q_ans);

/**
 * Converts byte into a string
 *
 * @param byte data desired to convert
 * @param address address desired to put into converted data 
 *
 * @return void
 */

void byte_to_string(uint8_t* byte, char* address) {
	sprintf(address, "%u.%u.%u.%u", byte[0], byte[1], byte[2], byte[3]);
}
/**
 * Searches for desired location in struct with matching DNS type
 *
 * @param answers array of answer_info struct
 * @param type type of DNS record that we are looking for
 * @param num_ans number of answers in answer_info struct
 *
 * @return returns in that is the location in answer_info that has correct DNS
 * type
 */
int search(struct answer_info *answers, int type, int num_ans) {
	for(int i = 0; i < num_ans; i++) {
		if(answers[i].type == type) {
			return i;
		}
	}
	return -1;
}

/**
 * Constructs a DNS query for hostname's Type A record.
 *
 * @param query Pointer to memory where query will stored.
 * @param hostname The host we are trying to resolve
 * @return The number of bytes in the constructed query.
 */
int construct_query(uint8_t* query, char* hostname, bool is_mx) {
	memset(query, 0, MAX_QUERY_SIZE);

	// first part of the query is a fixed size header
	DNSHeader *hdr = (DNSHeader*)query;

	// generate random id
	hdr->id = htons(rand() % 65536);

	// set header flags to request iterative query
	hdr->flags = htons(0x0000);	

	// 1 question, no answers or other records
	hdr->q_count=htons(1);
	hdr->a_count=htons(0);
	hdr->auth_count=htons(0);
	hdr->other_count=htons(0);

	// We are going to have to wade into pointer arithmetic here since our
	// struct is a fixed size but our queries will be variably sized.

	// add the name
	int query_len = sizeof(DNSHeader); 
	int name_len = convertStringToDNS(hostname,query+query_len);
	query_len += name_len;

	// set the query type to A (i.e. 1)
	if(!is_mx) {
		uint16_t *type = (uint16_t*)(query+query_len);
		*type = htons(1);
		query_len += 2;
	}
	// set the query type to 15 for mx
	else {
		uint16_t *type = (uint16_t*)(query+query_len);
		*type = htons(15);
		query_len += 2;
	}

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
 
	return query_len;
}


/**
 * Returns a string with the IP address (for an A record) or name of mail
 * server associated with the given hostname.
 *
 * @param hostname The name of the host to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if
 *    requesting the A record.
 *
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 *   mail server (e.g. "mail.google.com"). If the request could not be
 *   resolved, NULL will be returned.
 */
char* resolve(char *hostname, bool is_mx) {

	if (is_mx == false) {
		printf("Requesting A record for %s\n", hostname);
	}
	else {
		printf("Requesting MX record for %s\n", hostname);
	}
	// create a UDP (i.e. Datagram) socket
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(0);
	}
	// Create a time value structure and set it to five seconds.
	struct timeval tv;
	memset(&tv, 0, sizeof(struct timeval));
	tv.tv_sec = 5;
	/* Tell the OS to use that time value as a time out for operations on
	 * our socket. */
	int res = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv,
			sizeof(struct timeval));
	if (res < 0) {
		perror("setsockopt");
		exit(0);
	}

	// The following is the IP address of USD's local DNS server. It is a
	// placeholder only (i.e. you shouldn't have this hardcoded into your final
	// program).
	FILE *root = fopen("root-servers.txt", "r"); // open root-servers file
	char root_ip[256];
	while(fgets(root_ip, sizeof(root_ip), root)) {
		char *q_ans = malloc(200);
		char* ans = send_q(root_ip, hostname, is_mx, sock, q_ans);
		if(strcmp(ans, "SOA") == 0) { // error handling
			fclose(root);
			exit(0);
		}
		if(q_ans != NULL) { // if file is empty, close
			fclose(root);
			return q_ans;
		}

		printf("Could not find response. Trying the next root server.\n");
	}
	fclose(root);
	return NULL;
}
/**
 * Send Q (query) takes in the query and its root IP and sends it looking for
 * a response
 *
 *@param dest_ip ip we are targetting
 *@param hostname hostname we are trying to resolve
 *@param is_mx whether or not it is an mx request
 *@param sock socket we are connecting to
 *@return returns 1 for no error and 0 for error
 */

char *send_q(char* dest_ip, char* hostname, bool is_mx, int sock, char *q_ans){
	uint8_t q[MAX_QUERY_SIZE];
	int q_len = construct_query(q, hostname, is_mx);
	uint8_t response[MAX_RESPONSE_SIZE];
	in_addr_t nameserver_address = inet_addr(dest_ip);
	
	// socket address
	struct sockaddr_in address;

	address.sin_family = AF_INET;
	address.sin_port = htons(53);//port 53 for DNS
	address.sin_addr.s_addr = nameserver_address; // set destination address
	
	// send query to socket
	int send_counter = sendto(sock, q, q_len, 0, (struct sockaddr*)&address, sizeof(address));
	if (send_counter < 0){
		perror("Send Failed");
		exit(1);
	}

	socklen_t length = sizeof(struct sockaddr_in);

	// receive answer from socket
	int resp = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, (struct sockaddr *)&address, &length);
	if (resp < 1){
		if (errno == EAGAIN){
			printf("Timed out!\n");
		}
		else{
			perror("recv");
		}
	}
	
	/*Sever's response located in response array
	 * Data is processed and required info is processed
	 */

	// processing data, picking apart the header and saving information
	memset(q, 0, MAX_QUERY_SIZE);
	DNSHeader *header = (DNSHeader*)q;
	header->id = ((uint16_t)response[0] << 8) + response[1];
	header->flags = ((uint16_t)response[2] << 8) + response[3];
	header->q_count = ((uint16_t)response[4] << 8) + response[5];
	header->a_count = ((uint16_t)response[6] << 8) + response[7];
	header->auth_count = ((uint16_t)response[8] << 8) + response[9];
	header->other_count = ((uint16_t)response[10] << 8) + response[11];
	
	// account for flags and id
	int offset = 12;

	for (int i = 0; i < header->q_count; i++){
		get_info(response, &offset);
	}
	int num_ans = header->a_count + header->auth_count + header->other_count;
	struct answer_info answers[num_ans];
	for (int i = 0; i < num_ans; i++){
		answers[i] = get_answer_info(response, &offset);
	}
	// process the request after labeling parts of query and answer
	return process_request(answers, response, num_ans, hostname, is_mx, sock, q_ans);
}

/** Checks type of response ns/cname/mx then reads data using iterative
 * process. Returns address when correct request type found.
 *
 * @param answers list of structs of all answers in response
 * @param response entire DNS reponse that was received
 * @param num_ans number of responses from request
 * @param hostname hostname desired to resolve
 * @param is_mx if/not mx
 * @param sock socket we are connecting to
 *
 * @returns recursive send_q call or address
 */
char *process_request(struct answer_info *answers, uint8_t *response, int num_ans, char *hostname, bool is_mx, int sock, char* q_ans){
	int type = answers[0].type;
	if (type == 2){ // NS response
		char new_server[256];
		getStringFromDNS(response, answers[0].extra_data, new_server);
		for (int i = 0; i < num_ans; i++){
			if (answers[i].type == 1 && strcmp(answers[i].name, new_server)){ // check if the name server's IP is given in the answer
				char new_address[17];
				byte_to_string(answers[i].extra_data, new_address);
				printf("NS response received, querying %s to %s\n", hostname, new_address);
				return send_q(new_address, hostname, is_mx, sock, q_ans);
			}
		}
		// search for A response
		int decide_ans = search(answers, 1, num_ans);
		if (decide_ans > -1){
			char new_address[17];
			byte_to_string(answers[decide_ans].extra_data, new_address);
			printf("NS response received, querying %s to %s\n", hostname, new_address);
			return send_q(new_address, hostname, is_mx, sock, q_ans); // send new query after NS response is processed
		}
		printf("NS response received without type A response. Sending request to find NS IP\n");
		char *ip = resolve(new_server, false); // search for NS IP
		printf("Found NS IP. Querying %s to %s\n", hostname, ip);
		char ip_stack[17];
		strcpy(ip_stack, ip);
		free(ip);
		return send_q(ip_stack, hostname, is_mx, sock, q_ans);
	}
	else if (type == 1){//type A
		byte_to_string(answers[0].extra_data, q_ans);
		return q_ans;
	}
	else if (type == 5){//type CNAME
		char newname[256];
		getStringFromDNS(response, answers[0].extra_data, newname);
		printf("CNAME actual name: %s\n", newname);
		free(q_ans);
		return resolve(newname, is_mx);
	}
	//type mx
	else if (type == 15){
		getStringFromDNS(response, answers[0].extra_data + 2, q_ans);
		return q_ans;
	}
	//SOA type
	else if (type == 6){
		printf("Invalid Hostname.\n");
		free(q_ans);
		return "SOA";
	}
	free(q_ans);
	return NULL;
}




int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Invalid program usage for %s!\n", argv[0]);
		printf("Present the hostname desired to resolve as an argument.\nIf an MX request make the first parameter -m\n");
		exit(1);
	}
	bool not_mx = strcmp("-m", argv[1]);
	char *answer;
	//"-m" flag in command line
	if (!not_mx){
		answer = resolve(argv[2], true);
		}
	//"-m" flag not in command line
	else{
		answer = resolve(argv[1], false);
	}

	if (answer != NULL) {
		printf("Answer: %s\n", answer);
	}
	else {
		printf("Could not resolve request.\n");
	}
	free(answer);
	return 0;
}
