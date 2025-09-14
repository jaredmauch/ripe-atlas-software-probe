/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <netinet/in.h>

/* Response types for packet replay */
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

/* Application-specific response type mapping based on calling application */
int map_linux_to_app_response_type(int linux_type, const char *app_tool) {
	/* Suppress unused parameter warning */
	(void)app_tool;
	/* No mapping needed - return original type */
	return linux_type;
}


/* Linux-specific struct definitions for binary data compatibility */
#ifndef __linux__

/* Linux sockaddr_in structure (different from FreeBSD) */
struct linux_sockaddr_in {
	uint16_t sin_family;    /* AF_INET */
	uint16_t sin_port;      /* Port number in network byte order */
	struct in_addr sin_addr; /* Internet address */
	uint8_t sin_zero[8];    /* Zero padding */
};

/* Linux sockaddr_in6 structure (different from FreeBSD) */
struct linux_sockaddr_in6 {
	uint16_t sin6_family;     /* AF_INET6 */
	uint16_t sin6_port;       /* Port number in network byte order */
	uint32_t sin6_flowinfo;   /* IPv6 flow information */
	struct in6_addr sin6_addr; /* IPv6 address */
	uint32_t sin6_scope_id;   /* Scope ID */
};

/* Linux dstaddr structure */
struct linux_dstaddr {
	int family;            /* Address family */
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
};

/* Linux addrinfo structure (different from FreeBSD) */
struct linux_addrinfo {
	int ai_flags;          /* AI_* flags */
	int ai_family;         /* AF_* family */
	int ai_socktype;       /* SOCK_* type */
	int ai_protocol;       /* Protocol */
	socklen_t ai_addrlen;  /* Address length */
	char *ai_canonname;    /* Canonical name */
	struct sockaddr *ai_addr; /* Address */
	struct addrinfo *ai_next; /* Next in list */
};

/* Convert Linux addrinfo to local OS addrinfo - safe field-by-field conversion */
static void convert_linux_addrinfo_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const uint8_t *data = (const uint8_t*)linux_data;
	struct addrinfo *local_ai = (struct addrinfo *)local_data;
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	if (linux_size >= 24 && *local_size >= sizeof(struct addrinfo)) {
		/* Parse binary data field by field to avoid struct layout issues */
		/* ai_flags (4 bytes at offset 0) */
		local_ai->ai_flags = *(const int32_t*)(data + 0);
		
		/* ai_family (4 bytes at offset 4) */
		local_ai->ai_family = *(const int32_t*)(data + 4);
		
		/* ai_socktype (4 bytes at offset 8) */
		local_ai->ai_socktype = *(const int32_t*)(data + 8);
		
		/* ai_protocol (4 bytes at offset 12) */
		local_ai->ai_protocol = *(const int32_t*)(data + 12);
		
		/* ai_addrlen (8 bytes at offset 16) */
		local_ai->ai_addrlen = *(const socklen_t*)(data + 16);
		
		/* ai_canonname (8 bytes at offset 24) - pointer, set to NULL for safety */
		local_ai->ai_canonname = NULL;
		
		/* ai_addr (8 bytes at offset 32) - pointer, set to NULL for safety */
		local_ai->ai_addr = NULL;
		
		/* ai_next (8 bytes at offset 40) - pointer, set to NULL for safety */
		local_ai->ai_next = NULL;
		
		*local_size = sizeof(struct addrinfo);
	} else {
		/* Fallback: copy what we can */
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
	}
}

/* Convert Linux dstaddr to FreeBSD dstaddr - safe field-by-field conversion */
static void convert_linux_dstaddr_to_local(const void *linux_data, size_t linux_size, void *local_data, size_t *local_size) {
	const uint8_t *data = (const uint8_t*)linux_data;
	struct sockaddr_in *local_sin = (struct sockaddr_in *)local_data;
	struct sockaddr_in6 *local_sin6 = (struct sockaddr_in6 *)local_data;
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	if (linux_size >= 16) {
		/* Parse binary data field by field to avoid struct layout issues */
		/* family field (4 bytes at offset 0) */
		uint16_t family = *(const uint16_t*)(data + 0);
		
		/* Handle IPv4 addresses */
		if (family == AF_INET || family == 2 || family == 0) {
			if (*local_size >= sizeof(struct sockaddr_in)) {
				local_sin->sin_family = AF_INET;
				local_sin->sin_port = *(const uint16_t*)(data + 2);
				memcpy(&local_sin->sin_addr, data + 4, 4);
				memset(local_sin->sin_zero, 0, 8);
				*local_size = sizeof(struct sockaddr_in);
			} else {
				fprintf(stderr, "ERROR: Dstaddr IPv4 buffer too small (%zu < %zu)\n", *local_size, sizeof(struct sockaddr_in));
				*local_size = 0;
			}
		}
		/* Handle IPv6 addresses */
		else if (family == AF_INET6 || family == 10 || family == 28) {
			if (*local_size >= sizeof(struct sockaddr_in6)) {
				local_sin6->sin6_family = AF_INET6;
				local_sin6->sin6_port = *(const uint16_t*)(data + 2);
				memcpy(&local_sin6->sin6_flowinfo, data + 4, 4);
				memcpy(&local_sin6->sin6_addr, data + 8, 16);
				memcpy(&local_sin6->sin6_scope_id, data + 24, 4);
				*local_size = sizeof(struct sockaddr_in6);
			} else {
				fprintf(stderr, "ERROR: Dstaddr IPv6 buffer too small (%zu < %zu)\n", *local_size, sizeof(struct sockaddr_in6));
				*local_size = 0;
			}
		}
		/* Fallback: assume IPv4 based on size */
		else if (linux_size <= 16) {
			if (*local_size >= sizeof(struct sockaddr_in)) {
				local_sin->sin_family = AF_INET;
				local_sin->sin_port = *(const uint16_t*)(data + 2);
				memcpy(&local_sin->sin_addr, data + 4, 4);
				memset(local_sin->sin_zero, 0, 8);
				*local_size = sizeof(struct sockaddr_in);
			} else {
				fprintf(stderr, "ERROR: Dstaddr IPv4 buffer too small (%zu < %zu)\n", *local_size, sizeof(struct sockaddr_in));
				*local_size = 0;
			}
		}
		/* Fallback: assume IPv6 based on size */
		else if (linux_size >= 28) {
			if (*local_size >= sizeof(struct sockaddr_in6)) {
				local_sin6->sin6_family = AF_INET6;
				local_sin6->sin6_port = *(const uint16_t*)(data + 2);
				memcpy(&local_sin6->sin6_flowinfo, data + 4, 4);
				memcpy(&local_sin6->sin6_addr, data + 8, 16);
				memcpy(&local_sin6->sin6_scope_id, data + 24, 4);
				*local_size = sizeof(struct sockaddr_in6);
			} else {
				fprintf(stderr, "ERROR: Dstaddr IPv6 buffer too small (%zu < %zu)\n", *local_size, sizeof(struct sockaddr_in6));
				*local_size = 0;
			}
		}
	} else {
		fprintf(stderr, "ERROR: Dstaddr data too small (linux=%zu)\n", linux_size);
		*local_size = 0;
	}
}

/* Convert Linux sockaddr to local OS sockaddr - safe field-by-field conversion */
static void convert_linux_sockaddr_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const uint8_t *data = (const uint8_t*)linux_data;
	struct sockaddr_in *local_sin = (struct sockaddr_in *)local_data;
	struct sockaddr_in6 *local_sin6 = (struct sockaddr_in6 *)local_data;
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	/* Parse binary data field by field to avoid struct layout issues */
	if (linux_size >= 16) {
		/* Extract family field (2 bytes at offset 0) */
		uint16_t family = *(const uint16_t*)(data + 0);
		
		/* Handle IPv4 addresses */
		if (family == AF_INET || family == 2 || family == 0) {
			local_sin->sin_family = AF_INET;
			local_sin->sin_port = *(const uint16_t*)(data + 2);
			memcpy(&local_sin->sin_addr, data + 4, 4);
			memset(local_sin->sin_zero, 0, 8);
			*local_size = sizeof(struct sockaddr_in);
			return;
		}
		/* Handle IPv6 addresses */
		else if (family == AF_INET6 || family == 10 || family == 28) {
			if (*local_size >= sizeof(struct sockaddr_in6)) {
				local_sin6->sin6_family = AF_INET6;
				local_sin6->sin6_port = *(const uint16_t*)(data + 2);
				memcpy(&local_sin6->sin6_flowinfo, data + 4, 4);
				memcpy(&local_sin6->sin6_addr, data + 8, 16);
				memcpy(&local_sin6->sin6_scope_id, data + 24, 4);
				*local_size = sizeof(struct sockaddr_in6);
			} else {
				/* Buffer too small for IPv6, convert to IPv4 if possible */
				fprintf(stderr, "WARNING: IPv6 sockaddr too large for buffer (%zu < %zu), converting to IPv4\n", 
					*local_size, sizeof(struct sockaddr_in6));
				if (*local_size >= sizeof(struct sockaddr_in)) {
					local_sin->sin_family = AF_INET;
					local_sin->sin_port = *(const uint16_t*)(data + 2);
					/* Use first 4 bytes of IPv6 address as IPv4 address */
					memcpy(&local_sin->sin_addr, data + 8, 4);
					memset(local_sin->sin_zero, 0, 8);
					*local_size = sizeof(struct sockaddr_in);
				} else {
					*local_size = 0;
				}
			}
			return;
		}
		/* Fallback: assume IPv4 based on size */
		else if (linux_size <= 16) {
			if (*local_size >= sizeof(struct sockaddr_in)) {
				local_sin->sin_family = AF_INET;
				local_sin->sin_port = *(const uint16_t*)(data + 2);
				memcpy(&local_sin->sin_addr, data + 4, 4);
				memset(local_sin->sin_zero, 0, 8);
				*local_size = sizeof(struct sockaddr_in);
			} else {
				*local_size = 0;
			}
			return;
		}
		/* Fallback: assume IPv6 based on size */
		else if (linux_size >= 28) {
			if (*local_size >= sizeof(struct sockaddr_in6)) {
				local_sin6->sin6_family = AF_INET6;
				local_sin6->sin6_port = *(const uint16_t*)(data + 2);
				memcpy(&local_sin6->sin6_flowinfo, data + 4, 4);
				memcpy(&local_sin6->sin6_addr, data + 8, 16);
				memcpy(&local_sin6->sin6_scope_id, data + 24, 4);
				*local_size = sizeof(struct sockaddr_in6);
			} else {
				/* Buffer too small for IPv6, convert to IPv4 if possible */
				fprintf(stderr, "WARNING: IPv6 sockaddr too large for buffer (%zu < %zu), converting to IPv4\n", 
					*local_size, sizeof(struct sockaddr_in6));
				if (*local_size >= sizeof(struct sockaddr_in)) {
					local_sin->sin_family = AF_INET;
					local_sin->sin_port = *(const uint16_t*)(data + 2);
					/* Use first 4 bytes of IPv6 address as IPv4 address */
					memcpy(&local_sin->sin_addr, data + 8, 4);
					memset(local_sin->sin_zero, 0, 8);
					*local_size = sizeof(struct sockaddr_in);
				} else {
					*local_size = 0;
				}
			}
			return;
		}
	}
	
	/* Final fallback: direct copy with size limit */
	{
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
	}
}

/* Load and convert Linux binary data to local OS format */
int load_linux_binary_data(int response_type, const void *linux_data, size_t linux_size, void *local_data, size_t *local_size) {
	extern const char *current_tool;
	int mapped_type;
	
	
	/* Safety checks */
	if (!linux_data || !local_data || !local_size) {
		fprintf(stderr, "ERROR: NULL pointer detected in load_linux_binary_data\n");
		return -1;
	}
	if (linux_size == 0) {
		/* Some response types may legitimately have zero size (e.g., empty addrinfo lists, empty packets) */
		if (response_type == 1 || response_type == 8 || response_type == 10) { /* RESP_PACKET, RESP_ADDRINFO, RESP_ADDRINFO_10 */
			*local_size = 0;
			return 0;
		}
		fprintf(stderr, "ERROR: Zero linux_size detected in load_linux_binary_data\n");
		return -1;
	}
	if (*local_size == 0) {
		fprintf(stderr, "ERROR: Zero local_size detected in load_linux_binary_data\n");
		return -1;
	}
	
	/* Map response type if needed */
	mapped_type = response_type;
	if (current_tool) {
		mapped_type = response_type; // Keep original response type
	}
	
	/* Handle different response types with proper struct conversion */
	/* Group by actual numeric values to avoid duplicate case errors */
	if (mapped_type == 1) { /* RESP_PACKET */
		/* Handle packet data - just copy as-is */
		if (linux_size > *local_size) {
			fprintf(stderr, "ERROR: Packet data too large (%zu > %zu)\n", linux_size, *local_size);
			return -1;
		}
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
		return 0;
	}
	else if (mapped_type == 2) { /* RESP_SOCKNAME */
		/* Handle socket name - convert using safe field-by-field method */
		convert_linux_sockaddr_to_local(linux_data, linux_size, local_data, local_size);
		return 0;
	}
	else if (mapped_type == 3) { /* RESP_DSTADDR */
		/* Handle destination address - convert using safe field-by-field method */
		convert_linux_dstaddr_to_local(linux_data, linux_size, local_data, local_size);
		return 0;
	}
	else if (mapped_type == 4) { /* RESP_PEERNAME, RESP_PROTO, RESP_TTL, RESP_TIMEOFDAY, RESP_READ_ERROR, RESP_N_RESOLV */
		/* Handle simple integer/byte data - just copy */
		if (linux_size > *local_size) {
			fprintf(stderr, "ERROR: Simple data too large (%zu > %zu)\n", linux_size, *local_size);
			return -1;
		}
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
		return 0;
	}
	else if (mapped_type == 5) { /* RESP_RCVDTTL, RESP_RESOLVER */
		/* Handle TTL/resolver data - check if it's sockaddr data */
		if (linux_size >= 16 && (*local_size >= sizeof(struct sockaddr_in) || *local_size >= sizeof(struct sockaddr_in6))) {
			/* Likely sockaddr data - convert using safe method */
			convert_linux_sockaddr_to_local(linux_data, linux_size, local_data, local_size);
		} else {
			/* Regular TTL/resolver data - just copy */
			if (linux_size > *local_size) {
				fprintf(stderr, "ERROR: TTL/resolver data too large (%zu > %zu)\n", linux_size, *local_size);
				return -1;
			}
			memcpy(local_data, linux_data, linux_size);
			*local_size = linux_size;
		}
		return 0;
	}
	else if (mapped_type == 6) { /* RESP_RCVDTCLASS, RESP_LENGTH */
		/* Handle class/length data - just copy */
		if (linux_size > *local_size) {
			fprintf(stderr, "ERROR: Class/length data too large (%zu > %zu)\n", linux_size, *local_size);
			return -1;
		}
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
		return 0;
	}
	else if (mapped_type == 7) { /* RESP_SENDTO, RESP_DATA */
		/* Handle sendto/data - just copy */
		if (linux_size > *local_size) {
			fprintf(stderr, "ERROR: Sendto/data too large (%zu > %zu)\n", linux_size, *local_size);
			return -1;
		}
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
		return 0;
	}
	else if (mapped_type == 8) { /* RESP_ADDRINFO, RESP_CMSG */
		/* Handle addrinfo/control message - convert using safe field-by-field method */
		convert_linux_addrinfo_to_local(linux_data, linux_size, local_data, local_size);
		return 0;
	}
	else if (mapped_type == 9) { /* RESP_ADDRINFO_SA, RESP_TIMEOUT */
		/* Handle addrinfo_sa/timeout data - just copy */
		if (linux_size > *local_size) {
			fprintf(stderr, "ERROR: Addrinfo_sa/timeout data too large (%zu > %zu)\n", linux_size, *local_size);
			return -1;
		}
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
		return 0;
	}
	else if (mapped_type == 10) { /* RESP_ADDRINFO_10 */
		/* Handle addrinfo type 10 - convert using safe field-by-field method */
		convert_linux_addrinfo_to_local(linux_data, linux_size, local_data, local_size);
		return 0;
	}
	else if (mapped_type == 11) { /* RESP_ADDRINFO_SA */
		/* Handle addrinfo_sa (sockaddr) data - convert using safe field-by-field method */
		convert_linux_sockaddr_to_local(linux_data, linux_size, local_data, local_size);
		return 0;
	}
	else {
		/* Unknown response type - copy what we can */
		fprintf(stderr, "WARNING: Unknown response type %d, copying data as-is\n", mapped_type);
		if (linux_size > *local_size) {
			fprintf(stderr, "ERROR: Unknown data too large (%zu > %zu)\n", linux_size, *local_size);
			return -1;
		}
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
		return 0;
	}
}

#endif /* !__linux__ */

