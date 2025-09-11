/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <json-c/json.h>

/* JSON-based response reader for fuzzing files */
static json_object *json_root = NULL;
static json_object *json_responses = NULL;
static int json_response_index = 0;
static int json_got_type = 0;
static int json_stored_type = 0;
static int json_fd = -1;

/* Convert JSON address data to sockaddr structure */
static int json_to_sockaddr(json_object *data, struct sockaddr *sa, socklen_t *salen)
{
    json_object *family_obj, *address_obj, *port_obj;
    const char *family_str, *address_str;
    int port = 0;
    
    if (!json_object_object_get_ex(data, "family", &family_obj)) {
        return -1;
    }
    
    family_str = json_object_get_string(family_obj);
    
    // Address might be null for DNS lookup scenarios
    if (json_object_object_get_ex(data, "address", &address_obj)) {
        address_str = json_object_get_string(address_obj);
        if (json_object_is_type(address_obj, json_type_null)) {
            address_str = NULL;  // Blank/undefined address
        }
    } else {
        address_str = NULL;  // No address field
    }
    
    if (json_object_object_get_ex(data, "port", &port_obj)) {
        port = json_object_get_int(port_obj);
    }
    
    if (strcmp(family_str, "AF_INET") == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        
        // Handle null/blank addresses (common during DNS lookup)
        if (address_str == NULL || strlen(address_str) == 0) {
            sin->sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0
        } else {
            if (inet_pton(AF_INET, address_str, &sin->sin_addr) != 1) {
                return -1;
            }
        }
        *salen = sizeof(*sin);
        return 0;
    } else if (strcmp(family_str, "AF_INET6") == 0) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        json_object *flowinfo_obj, *scope_id_obj;
        
        memset(sin6, 0, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        
        if (json_object_object_get_ex(data, "flowinfo", &flowinfo_obj)) {
            sin6->sin6_flowinfo = json_object_get_int(flowinfo_obj);
        }
        if (json_object_object_get_ex(data, "scope_id", &scope_id_obj)) {
            sin6->sin6_scope_id = json_object_get_int(scope_id_obj);
        }
        
        // Handle null/blank addresses (common during DNS lookup)
        if (address_str == NULL || strlen(address_str) == 0) {
            memset(&sin6->sin6_addr, 0, sizeof(sin6->sin6_addr));  // All zeros
        } else {
            if (inet_pton(AF_INET6, address_str, &sin6->sin6_addr) != 1) {
                return -1;
            }
        }
        *salen = sizeof(*sin6);
        return 0;
    }
    
    return -1;
}

/* Initialize JSON response reader */
int json_response_init(const char *filename)
{
    json_object *version_obj;
    const char *version_str;
    
    if (json_root) {
        json_object_put(json_root);
    }
    
    json_root = json_object_from_file(filename);
    if (!json_root) {
        return -1;
    }
    
    if (!json_object_object_get_ex(json_root, "responses", &json_responses)) {
        json_object_put(json_root);
        json_root = NULL;
        return -1;
    }
    
    if (!json_object_is_type(json_responses, json_type_array)) {
        json_object_put(json_root);
        json_root = NULL;
        return -1;
    }
    
    json_response_index = 0;
    json_got_type = 0;
    
    return 0;
}

/* Cleanup JSON response reader */
void json_response_cleanup(void)
{
    if (json_root) {
        json_object_put(json_root);
        json_root = NULL;
    }
    json_responses = NULL;
    json_response_index = 0;
    json_got_type = 0;
}

/* Peek at next response type */
void json_peek_response(int *typep)
{
    json_object *response, *type_obj;
    const char *type_str;
    
    if (!json_got_type) {
        if (json_response_index >= json_object_array_length(json_responses)) {
            *typep = -1; /* EOF */
            return;
        }
        
        response = json_object_array_get_idx(json_responses, json_response_index);
        if (!json_object_object_get_ex(response, "type", &type_obj)) {
            *typep = -1;
            return;
        }
        
        if (json_object_is_type(type_obj, json_type_string)) {
            type_str = json_object_get_string(type_obj);
            if (strcmp(type_str, "RESP_DSTADDR") == 0) {
                json_stored_type = RESP_DSTADDR;
            } else if (strcmp(type_str, "RESP_SOCKNAME") == 0) {
                json_stored_type = RESP_SOCKNAME;
            } else if (strcmp(type_str, "RESP_PEERNAME") == 0) {
                json_stored_type = RESP_PEERNAME;
            } else if (strcmp(type_str, "RESP_PACKET") == 0) {
                json_stored_type = RESP_PACKET;
            } else if (strcmp(type_str, "RESP_TIMEOFDAY") == 0) {
                json_stored_type = RESP_TIMEOFDAY;
            } else if (strcmp(type_str, "RESP_READ_ERROR") == 0) {
                json_stored_type = RESP_READ_ERROR;
            } else {
                json_stored_type = -1;
            }
        } else if (json_object_is_type(type_obj, json_type_int)) {
            int type_num = json_object_get_int(type_obj);
            switch (type_num) {
                case 0: json_stored_type = RESP_PACKET; break;
                case 1: json_stored_type = RESP_DATA; break;
                case 2: json_stored_type = RESP_SOCKNAME; break;
                case 3: json_stored_type = RESP_DSTADDR; break;
                case 4: json_stored_type = RESP_PEERNAME; break;
                case 5: json_stored_type = RESP_TIMEOFDAY; break;
                case 6: json_stored_type = RESP_TIMEOUT; break;
                case 7: json_stored_type = RESP_READ_ERROR; break;
                default: json_stored_type = -1; break;
            }
        } else {
            json_stored_type = -1;
        }
        
        json_got_type = 1;
    }
    
    *typep = json_stored_type;
}

/* Read response data */
void json_read_response(int type, size_t *sizep, void *data)
{
    json_object *response, *data_obj;
    int tmp_type;
    
    if (json_got_type) {
        tmp_type = json_stored_type;
        json_got_type = 0;
    } else {
        json_peek_response(&tmp_type);
        if (tmp_type == -1) {
            *sizep = 0;
            return;
        }
    }
    
    if (tmp_type != type) {
        fprintf(stderr, "json_read_response: wrong type, expected %d, got %d\n",
                type, tmp_type);
        *sizep = 0;
        return;
    }
    
    if (json_response_index >= json_object_array_length(json_responses)) {
        *sizep = 0;
        return;
    }
    
    response = json_object_array_get_idx(json_responses, json_response_index);
    json_response_index++;
    
    if (!json_object_object_get_ex(response, "data", &data_obj)) {
        *sizep = 0;
        return;
    }
    
    /* Handle sockaddr types */
    if (type == RESP_DSTADDR || type == RESP_SOCKNAME || type == RESP_PEERNAME) {
        if (json_to_sockaddr(data_obj, (struct sockaddr *)data, sizep) != 0) {
            *sizep = 0;
            return;
        }
    } else {
        /* For other types, we'd need to implement specific handling */
        *sizep = 0;
    }
}
