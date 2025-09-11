/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#ifndef JSON_OUTPUT_H
#define JSON_OUTPUT_H

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Only include JSON output functions if JSON support is available */
#ifdef CONFIG_HAVE_JSON_C

/* JSON output helper functions for portable test data */

/* Convert sockaddr to portable JSON representation */
static inline void json_write_sockaddr(FILE *fh, const char *field_name, 
                                       const struct sockaddr *sa, socklen_t salen)
{
    char addr_str[INET6_ADDRSTRLEN];
    int port = 0;
    const char *family_str = "AF_UNKNOWN";
    
    if (sa == NULL || salen == 0) {
        fprintf(fh, ", \"%s\": null", field_name);
        return;
    }
    
    switch (sa->sa_family) {
        case AF_INET: {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
            family_str = "AF_INET";
            port = ntohs(sin->sin_port);
            inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
            break;
        }
        case AF_INET6: {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
            family_str = "AF_INET6";
            port = ntohs(sin6->sin6_port);
            inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
            break;
        }
        default:
            fprintf(fh, ", \"%s\": {\"family\":\"%s\"}", field_name, family_str);
            return;
    }
    
    /* Write complete sockaddr info as JSON object */
    fprintf(fh, ", \"%s\": {\"family\":\"%s\",\"address\":\"%s\",\"port\":%d", 
            field_name, family_str, addr_str, port);
    
    /* Add IPv6-specific fields if applicable */
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        fprintf(fh, ",\"flowinfo\":%u,\"scope_id\":%u", 
                sin6->sin6_flowinfo, sin6->sin6_scope_id);
    }
    
    fprintf(fh, "}");
}

/* Write packet data as base64-encoded JSON */
static inline void json_write_packet_data(FILE *fh, const char *field_name,
                                          const void *data, size_t len)
{
    if (data == NULL || len == 0) {
        fprintf(fh, ", \"%s\": null", field_name);
        return;
    }
    
    /* For now, write as hex string - could be base64 if needed */
    fprintf(fh, ", \"%s\": \"", field_name);
    const unsigned char *bytes = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        fprintf(fh, "%02x", bytes[i]);
    }
    fprintf(fh, "\"");
}

/* Write timestamp as JSON */
static inline void json_write_timestamp(FILE *fh, const char *field_name, 
                                        const struct timeval *tv)
{
    if (tv == NULL) {
        fprintf(fh, ", \"%s\": null", field_name);
        return;
    }
    
    fprintf(fh, ", \"%s\": {\"sec\":%ld,\"usec\":%ld}", 
            field_name, tv->tv_sec, tv->tv_usec);
}

/* Write address family as string */
static inline void json_write_address_family(FILE *fh, int af)
{
    const char *family_str;
    switch (af) {
        case AF_INET:  family_str = "AF_INET"; break;
        case AF_INET6: family_str = "AF_INET6"; break;
        case AF_UNSPEC: family_str = "AF_UNSPEC"; break;
        default: family_str = "AF_UNKNOWN"; break;
    }
    fprintf(fh, ", \"af\":\"%s\"", family_str);
}

/* Write numeric address family as string */
static inline void json_write_address_family_num(FILE *fh, int af_num)
{
    const char *family_str;
    switch (af_num) {
        case 4:  family_str = "AF_INET"; break;
        case 6:  family_str = "AF_INET6"; break;
        case 0:  family_str = "AF_UNSPEC"; break;
        default: family_str = "AF_UNKNOWN"; break;
    }
    fprintf(fh, ", \"af\":\"%s\"", family_str);
}

#else /* !CONFIG_HAVE_JSON_C */

/* Stub functions when JSON support is not available */
static inline void json_write_sockaddr(FILE *fh, const char *field_name, 
                                       const struct sockaddr *sa, socklen_t salen) { (void)fh; (void)field_name; (void)sa; (void)salen; }
static inline void json_write_packet_data(FILE *fh, const char *field_name,
                                          const void *data, size_t len) { (void)fh; (void)field_name; (void)data; (void)len; }
static inline void json_write_timestamp(FILE *fh, const char *field_name, 
                                        const struct timeval *tv) { (void)fh; (void)field_name; (void)tv; }
static inline void json_write_address_family(FILE *fh, int af) { (void)fh; (void)af; }
static inline void json_write_address_family_num(FILE *fh, int af_num) { (void)fh; (void)af_num; }

#endif /* CONFIG_HAVE_JSON_C */

#endif /* JSON_OUTPUT_H */
