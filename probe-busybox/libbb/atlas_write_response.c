/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include "../eperd/json_output.h"

/* Response type definitions */
#define RESP_PACKET	1
#define RESP_SOCKNAME	2
#define RESP_DSTADDR	3
#define RESP_PEERNAME	4
#define RESP_PROTO	4
#define RESP_RCVDTTL	5
#define RESP_RCVDTCLASS	6
#define RESP_SENDTO	7
#define RESP_ADDRINFO	8
#define RESP_ADDRINFO_SA	9
#define RESP_TTL	4
#define RESP_TIMEOFDAY	4
#define RESP_READ_ERROR	4
#define RESP_N_RESOLV	4
#define RESP_RESOLVER	5
#define RESP_LENGTH	6
#define RESP_DATA	7
#define RESP_CMSG	8
#define RESP_TIMEOUT	9
#define RESP_ADDRINFO_10	10

/* External flag to indicate if JSON output is enabled */
extern int using_json;

/* Response type names for JSON output */
static const char* get_response_type_name(int type) {
    switch (type) {
        case RESP_PACKET: return "RESP_PACKET";
        case RESP_DSTADDR: return "RESP_DSTADDR";
        case RESP_SOCKNAME: return "RESP_SOCKNAME";
        case RESP_PEERNAME: return "RESP_PEERNAME";
        case RESP_TTL: return "RESP_TTL";
        case RESP_TIMEOUT: return "RESP_TIMEOUT";
        case RESP_READ_ERROR: return "RESP_READ_ERROR";
        case RESP_LENGTH: return "RESP_LENGTH";
        case RESP_PROTO: return "RESP_PROTO";
        case RESP_RCVDTTL: return "RESP_RCVDTTL";
        case RESP_RCVDTCLASS: return "RESP_RCVDTCLASS";
        case RESP_SENDTO: return "RESP_SENDTO";
        case RESP_CMSG: return "RESP_CMSG";
        case RESP_DATA: return "RESP_DATA";
        case RESP_ADDRINFO: return "RESP_ADDRINFO";
        case RESP_ADDRINFO_SA: return "RESP_ADDRINFO_SA";
        case RESP_RESOLVER: return "RESP_RESOLVER";
        case RESP_N_RESOLV: return "RESP_N_RESOLV";
        case RESP_TIMEOFDAY: return "RESP_TIMEOFDAY";
        default: return "UNKNOWN";
    }
}

/* Write JSON representation of response data */
static void write_response_json(FILE *file, int type, size_t size, void *data) {
    if (!using_json || !file) return;
    
    fprintf(file, "{\"type\":%d,\"type_name\":\"%s\",\"size\":%zu", 
            type, get_response_type_name(type), size);
    
    /* Handle different response types */
    switch (type) {
        case RESP_DSTADDR:
        case RESP_SOCKNAME:
        case RESP_PEERNAME:
            if (data && size >= sizeof(struct sockaddr)) {
                json_write_sockaddr(file, "sockaddr", (struct sockaddr*)data, size);
            }
            break;
            
        case RESP_PACKET:
            if (data && size > 0) {
                json_write_packet_data(file, "packet_data", data, size);
            }
            break;
            
        case RESP_TTL:
        case RESP_RCVDTTL:
        case RESP_RCVDTCLASS:
            if (data && size > 0) {
                if (size == sizeof(uint8_t)) {
                    fprintf(file, ",\"value\":%d", *(uint8_t*)data);
                } else if (size == sizeof(uint16_t)) {
                    fprintf(file, ",\"value\":%d", *(uint16_t*)data);
                } else if (size == sizeof(uint32_t)) {
                    fprintf(file, ",\"value\":%u", *(uint32_t*)data);
                }
            }
            break;
            
        case RESP_PROTO:
            if (data && size == sizeof(uint8_t)) {
                fprintf(file, ",\"protocol\":%d", *(uint8_t*)data);
            }
            break;
            
        case RESP_LENGTH:
            if (data && size > 0) {
                if (size == sizeof(uint32_t)) {
                    fprintf(file, ",\"length\":%u", *(uint32_t*)data);
                } else if (size == sizeof(uint16_t)) {
                    fprintf(file, ",\"length\":%d", *(uint16_t*)data);
                }
            }
            break;
            
        case RESP_TIMEOUT:
        case RESP_READ_ERROR:
            /* These are typically empty responses */
            break;
            
        default:
            /* For unknown types, include raw data as hex */
            if (data && size > 0) {
                json_write_packet_data(file, "raw_data", data, size);
            }
            break;
    }
    
    fprintf(file, "}\n");
}

void write_response(FILE *file, int type, size_t size, void *data)
{
	/* Write binary response data */
	fwrite(&type, sizeof(type), 1, file);
	fwrite(&size, sizeof(size), 1, file);
	fwrite(data, size, 1, file);
	
	/* Also write JSON representation if enabled */
	write_response_json(file, type, size, data);
}

