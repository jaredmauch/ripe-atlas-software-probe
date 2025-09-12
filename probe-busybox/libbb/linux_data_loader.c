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

/* Convert Linux sockaddr_in to FreeBSD sockaddr_in */
static void convert_linux_sockaddr_in_to_local(const struct linux_sockaddr_in *linux_sin, struct sockaddr_in *local_sin) {
	local_sin->sin_family = linux_sin->sin_family;
	local_sin->sin_port = linux_sin->sin_port;  /* Port is already in network byte order */
	local_sin->sin_addr = linux_sin->sin_addr;  /* Address is already in network byte order */
	memset(local_sin->sin_zero, 0, sizeof(local_sin->sin_zero));
}

/* Convert Linux addrinfo to local OS addrinfo */
static void convert_linux_addrinfo_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const struct addrinfo *linux_ai = (const struct addrinfo *)linux_data;
	struct addrinfo *local_ai = (struct addrinfo *)local_data;
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	if (linux_size >= sizeof(struct addrinfo) && *local_size >= sizeof(struct addrinfo)) {
		/* Copy basic fields that are generally compatible */
		local_ai->ai_flags = linux_ai->ai_flags;
		local_ai->ai_family = linux_ai->ai_family;
		local_ai->ai_socktype = linux_ai->ai_socktype;
		local_ai->ai_protocol = linux_ai->ai_protocol;
		local_ai->ai_addrlen = linux_ai->ai_addrlen;
		
		/* Handle canonical name - copy if present */
		if (linux_ai->ai_canonname) {
			size_t name_len = strlen(linux_ai->ai_canonname) + 1;
			if (name_len <= 256) { /* Reasonable limit */
				local_ai->ai_canonname = malloc(name_len);
				if (local_ai->ai_canonname) {
					strcpy(local_ai->ai_canonname, linux_ai->ai_canonname);
				}
			}
		}
		
		/* ai_addr and ai_next are pointers - will be set by caller */
		local_ai->ai_addr = NULL;
		local_ai->ai_next = NULL;
		
		*local_size = sizeof(struct addrinfo);
	} else {
		/* Fallback: copy what we can */
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
	}
}

/* Convert Linux sockaddr_in to FreeBSD sockaddr_in */
static void convert_linux_sockaddr_in_to_local(const struct linux_sockaddr_in *linux_sin, struct sockaddr_in *local_sin) {
	/* Convert Linux family value to FreeBSD family value */
	/* Handle common address family values */
	if (linux_sin->sin_family == 2 || linux_sin->sin_family == AF_INET) {
		/* AF_INET = 2 (same on Linux and FreeBSD) */
		local_sin->sin_family = AF_INET;
	} else if (linux_sin->sin_family == 0 || linux_sin->sin_family == AF_UNSPEC) {
		/* AF_UNSPEC = 0, but in sockaddr_in context, assume IPv4 */
		local_sin->sin_family = AF_INET;
	} else {
		/* For other values, assume they're already correct for the target system */
		local_sin->sin_family = linux_sin->sin_family;
	}
	local_sin->sin_port = linux_sin->sin_port;
	local_sin->sin_addr = linux_sin->sin_addr;
	memset(local_sin->sin_zero, 0, sizeof(local_sin->sin_zero));
}

/* Convert Linux sockaddr_in6 to FreeBSD sockaddr_in6 */
static void convert_linux_sockaddr_in6_to_local(const struct linux_sockaddr_in6 *linux_sin6, struct sockaddr_in6 *local_sin6) {
	/* Convert Linux family value to FreeBSD family value */
	/* Handle common address family values */
	if (linux_sin6->sin6_family == 10 || linux_sin6->sin6_family == AF_INET6) {
		/* Linux AF_INET6 = 10, FreeBSD AF_INET6 = 28 */
		local_sin6->sin6_family = AF_INET6;
	} else if (linux_sin6->sin6_family == 0 || linux_sin6->sin6_family == AF_UNSPEC) {
		/* AF_UNSPEC = 0, but in sockaddr_in6 context, assume IPv6 */
		local_sin6->sin6_family = AF_INET6;
	} else {
		/* For other values, assume they're already correct for the target system */
		local_sin6->sin6_family = linux_sin6->sin6_family;
	}
	local_sin6->sin6_port = linux_sin6->sin6_port;
	local_sin6->sin6_flowinfo = linux_sin6->sin6_flowinfo;
	local_sin6->sin6_addr = linux_sin6->sin6_addr;
	local_sin6->sin6_scope_id = linux_sin6->sin6_scope_id;
}

/* Convert Linux addrinfo to local OS addrinfo */
static void convert_linux_addrinfo_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const struct addrinfo *linux_ai = (const struct addrinfo *)linux_data;
	struct addrinfo *local_ai = (struct addrinfo *)local_data;
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	if (linux_size >= sizeof(struct addrinfo) && *local_size >= sizeof(struct addrinfo)) {
		/* Copy basic fields that are generally compatible */
		local_ai->ai_flags = linux_ai->ai_flags;
		local_ai->ai_family = linux_ai->ai_family;
		local_ai->ai_socktype = linux_ai->ai_socktype;
		local_ai->ai_protocol = linux_ai->ai_protocol;
		local_ai->ai_addrlen = linux_ai->ai_addrlen;
		
		/* Handle canonical name - copy if present */
		if (linux_ai->ai_canonname) {
			size_t name_len = strlen(linux_ai->ai_canonname) + 1;
			if (name_len <= 256) { /* Reasonable limit */
				local_ai->ai_canonname = malloc(name_len);
				if (local_ai->ai_canonname) {
					strcpy(local_ai->ai_canonname, linux_ai->ai_canonname);
				}
			}
		}
		
		/* ai_addr and ai_next are pointers - will be set by caller */
		local_ai->ai_addr = NULL;
		local_ai->ai_next = NULL;
		
		*local_size = sizeof(struct addrinfo);
	} else {
		/* Fallback: copy what we can */
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
	}
}

/* Convert Linux dstaddr to FreeBSD dstaddr */
static void convert_linux_dstaddr_to_local(const struct linux_dstaddr *linux_dst, struct linux_dstaddr *local_dst) {
	local_dst->family = linux_dst->family;
	if (linux_dst->family == AF_INET) {
		local_dst->addr.ipv4 = linux_dst->addr.ipv4;
	} else if (linux_dst->family == AF_INET6) {
		local_dst->addr.ipv6 = linux_dst->addr.ipv6;
	}
}

/* Convert Linux sockaddr to local OS sockaddr - comprehensive conversion */
static void convert_linux_sockaddr_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const struct sockaddr_in *linux_sin = (const struct sockaddr_in *)linux_data;
	const struct sockaddr_in6 *linux_sin6 = (const struct sockaddr_in6 *)linux_data;
	struct sockaddr_in *local_sin = (struct sockaddr_in *)local_data;
	struct sockaddr_in6 *local_sin6 = (struct sockaddr_in6 *)local_data;
	
#ifdef __DEBUG__
	fprintf(stderr, "DEBUG: convert_linux_sockaddr_to_local: linux_size=%zu, local_size=%zu\n", 
		linux_size, *local_size);
	fprintf(stderr, "DEBUG: Linux sin_family=%d, sin6_family=%d\n", 
		linux_sin->sin_family, linux_sin6->sin6_family);
#endif /* __DEBUG__ */
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	/* Handle IPv4 addresses - check multiple possible family values */
	if (linux_size >= sizeof(struct sockaddr_in)) {
		if (linux_sin->sin_family == AF_INET || 
		    linux_sin->sin_family == 2 ||  /* Common AF_INET value */
		    linux_sin->sin_family == 0 ||  /* AF_UNSPEC = 0, assume IPv4 in sockaddr_in context */
		    linux_sin->sin_family == AF_UNSPEC) {  /* AF_UNSPEC constant */
			/* IPv4 address - convert Linux format to local format */
			local_sin->sin_family = AF_INET;
			local_sin->sin_port = linux_sin->sin_port;
			local_sin->sin_addr = linux_sin->sin_addr;
			*local_size = sizeof(struct sockaddr_in);
			return;
		}
	}
	
	/* Handle IPv6 addresses - check multiple possible family values */
	if (linux_size >= sizeof(struct sockaddr_in6)) {
		if (linux_sin6->sin6_family == AF_INET6 || 
		    linux_sin6->sin6_family == 10 ||  /* Linux AF_INET6 */
		    linux_sin6->sin6_family == 28 ||  /* FreeBSD AF_INET6 */
		    linux_sin6->sin6_family == 0 ||   /* AF_UNSPEC = 0, assume IPv6 in sockaddr_in6 context */
		    linux_sin6->sin6_family == AF_UNSPEC) {  /* AF_UNSPEC constant */
			/* IPv6 address - convert Linux format to local format */
			local_sin6->sin6_family = AF_INET6;
			local_sin6->sin6_port = linux_sin6->sin6_port;
			local_sin6->sin6_flowinfo = linux_sin6->sin6_flowinfo;
			local_sin6->sin6_addr = linux_sin6->sin6_addr;
			local_sin6->sin6_scope_id = linux_sin6->sin6_scope_id;
			*local_size = sizeof(struct sockaddr_in6);
			return;
		}
	}
	
	/* Enhanced inference based on data size and content */
	if (linux_size >= 8) {
		/* Try to parse as IPv4 if data length suggests it */
		if (linux_size == sizeof(struct sockaddr_in)) {
			/* Check if port is in big-endian or little-endian format */
			uint16_t port_be = ntohs(linux_sin->sin_port);
			uint16_t port_le = linux_sin->sin_port;
			
			/* Use the port that makes sense (reasonable port numbers) */
			uint16_t port = (port_be > 0 && port_be != port_le) ? port_be : port_le;
			
			local_sin->sin_family = AF_INET;
			local_sin->sin_port = htons(port);
			local_sin->sin_addr = linux_sin->sin_addr;
			*local_size = sizeof(struct sockaddr_in);
			return;
		}
		/* Try to parse as IPv6 if data length suggests it */
		else if (linux_size == sizeof(struct sockaddr_in6)) {
			local_sin6->sin6_family = AF_INET6;
			local_sin6->sin6_port = linux_sin6->sin6_port;
			local_sin6->sin6_flowinfo = linux_sin6->sin6_flowinfo;
			local_sin6->sin6_addr = linux_sin6->sin6_addr;
			local_sin6->sin6_scope_id = linux_sin6->sin6_scope_id;
			*local_size = sizeof(struct sockaddr_in6);
			return;
		}
	}
	
	/* Enhanced fallback: try to detect address family from data content */
	if (linux_size >= 16) {
		/* Check if this might be IPv6 data (28 bytes typical) */
		if (linux_size >= 28) {
			/* Assume IPv6 and try to convert */
			memcpy(local_sin6, linux_data, sizeof(struct sockaddr_in6));
			local_sin6->sin6_family = AF_INET6;
			*local_size = sizeof(struct sockaddr_in6);
			return;
		}
		/* Check if this might be IPv4 data (16 bytes typical) */
		else if (linux_size >= 16) {
			/* Assume IPv4 and try to convert */
			memcpy(local_sin, linux_data, sizeof(struct sockaddr_in));
			local_sin->sin_family = AF_INET;
			*local_size = sizeof(struct sockaddr_in);
			return;
		}
	}
	
	/* Final fallback: direct copy with size limit */
	size_t copy_size;
	copy_size = (linux_size < *local_size) ? linux_size : *local_size;
	memcpy(local_data, linux_data, copy_size);
	*local_size = copy_size;
}

/* Load and convert Linux binary data to local OS format */
int load_linux_binary_data(int response_type, const void *linux_data, size_t linux_size, void *local_data, size_t *local_size) {
	printf("DEBUG: load_linux_binary_data called: response_type=%d, linux_size=%zu, local_size=%zu\n", response_type, linux_size, *local_size);
	
	/* Safety checks */
	if (!linux_data || !local_data || !local_size) {
		fprintf(stderr, "ERROR: NULL pointer detected in load_linux_binary_data\n");
		return -1;
	}
	if (linux_size == 0 || *local_size == 0) {
		fprintf(stderr, "ERROR: Zero size detected in load_linux_binary_data\n");
		return -1;
	}
	
	/* Map response type if needed */
	extern const char *current_tool;
	int mapped_type;
	
	mapped_type = response_type;
	if (current_tool) {
		mapped_type = response_type; // Keep original response type
		printf("DEBUG: current_tool=%s, mapped_type=%d\n", current_tool, mapped_type);
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
		/* Handle socket name - convert Linux sockaddr to local sockaddr */
		printf("DEBUG: Converting sockaddr structure\n");
		convert_linux_sockaddr_to_local(linux_data, linux_size, local_data, local_size);
		return 0;
	}
	else if (mapped_type == 3) { /* RESP_DSTADDR */
		/* Handle destination address - convert Linux dstaddr to local dstaddr */
		if (linux_size >= sizeof(struct linux_dstaddr) && *local_size >= sizeof(struct linux_dstaddr)) {
			convert_linux_dstaddr_to_local((const struct linux_dstaddr*)linux_data, (struct linux_dstaddr*)local_data);
			*local_size = sizeof(struct linux_dstaddr);
		} else {
			fprintf(stderr, "ERROR: Dstaddr data size mismatch (linux=%zu, local=%zu)\n", linux_size, *local_size);
			return -1;
		}
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
		/* Handle TTL/resolver data - just copy */
		if (linux_size > *local_size) {
			fprintf(stderr, "ERROR: TTL/resolver data too large (%zu > %zu)\n", linux_size, *local_size);
			return -1;
		}
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
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
		/* Handle addrinfo/control message - convert or copy */
		if (linux_size >= sizeof(struct linux_addrinfo) && *local_size >= sizeof(struct addrinfo)) {
			convert_linux_addrinfo_to_local(linux_data, linux_size, local_data, local_size);
		} else {
			/* Fallback: just copy */
			if (linux_size > *local_size) {
				fprintf(stderr, "ERROR: Addrinfo/cmsg data too large (%zu > %zu)\n", linux_size, *local_size);
				return -1;
			}
			memcpy(local_data, linux_data, linux_size);
			*local_size = linux_size;
		}
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
		/* Handle addrinfo type 10 - convert Linux addrinfo to local addrinfo */
		if (linux_size >= sizeof(struct linux_addrinfo) && *local_size >= sizeof(struct addrinfo)) {
			convert_linux_addrinfo_to_local(linux_data, linux_size, local_data, local_size);
		} else {
			fprintf(stderr, "ERROR: Addrinfo data size mismatch (linux=%zu, local=%zu)\n", linux_size, *local_size);
			return -1;
		}
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

/* Stub function for Linux systems - just copy data as-is */
#ifdef __linux__
int load_linux_binary_data(int response_type, const void *linux_data, size_t linux_size, void *local_data, size_t *local_size) {
	/* On Linux, just copy the data as-is */
	size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
	memcpy(local_data, linux_data, copy_size);
	*local_size = copy_size;
	return 0;
}
#endif
