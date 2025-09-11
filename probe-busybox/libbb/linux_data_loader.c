/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <netinet/in.h>

/* Linux-specific struct definitions for binary data compatibility */
#ifdef __FreeBSD__

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

/* Linux timeval structure (different from FreeBSD) */
struct linux_timeval {
	int32_t tv_sec;   /* seconds */
	int32_t tv_usec;  /* microseconds */
};

/* Linux addrinfo structure (different from FreeBSD) */
struct linux_addrinfo {
	int32_t ai_flags;     /* AI_PASSIVE, AI_CANONNAME, etc. */
	int32_t ai_family;    /* AF_INET, AF_INET6, AF_UNSPEC */
	int32_t ai_socktype;  /* SOCK_STREAM, SOCK_DGRAM */
	int32_t ai_protocol;  /* IPPROTO_TCP, IPPROTO_UDP */
	uint32_t ai_addrlen;  /* Length of ai_addr */
	char *ai_canonname;   /* Canonical name for hostname */
	struct sockaddr *ai_addr; /* Binary address */
	struct linux_addrinfo *ai_next; /* Next structure in linked list */
};

/* Linux sockaddr structure (generic) */
struct linux_sockaddr {
	uint16_t sa_family;    /* Address family */
	char sa_data[14];      /* Address data */
};

/* Convert Linux sockaddr_in to FreeBSD sockaddr_in */
static void convert_linux_sockaddr_in_to_local(const struct linux_sockaddr_in *linux_sin, struct sockaddr_in *local_sin) {
	local_sin->sin_family = linux_sin->sin_family;
	local_sin->sin_port = linux_sin->sin_port;
	local_sin->sin_addr = linux_sin->sin_addr;
	memset(local_sin->sin_zero, 0, sizeof(local_sin->sin_zero));
}

/* Convert Linux sockaddr_in6 to FreeBSD sockaddr_in6 */
static void convert_linux_sockaddr_in6_to_local(const struct linux_sockaddr_in6 *linux_sin6, struct sockaddr_in6 *local_sin6) {
	local_sin6->sin6_family = linux_sin6->sin6_family;
	local_sin6->sin6_port = linux_sin6->sin6_port;
	local_sin6->sin6_flowinfo = linux_sin6->sin6_flowinfo;
	local_sin6->sin6_addr = linux_sin6->sin6_addr;
	local_sin6->sin6_scope_id = linux_sin6->sin6_scope_id;
}

/* Convert Linux timeval to FreeBSD timeval */
static void convert_linux_timeval_to_local(const struct linux_timeval *linux_tv, struct timeval *local_tv) {
	local_tv->tv_sec = linux_tv->tv_sec;
	local_tv->tv_usec = linux_tv->tv_usec;
}

/* Convert Linux addrinfo to FreeBSD addrinfo */
static void convert_linux_addrinfo_to_local(const struct linux_addrinfo *linux_ai, struct addrinfo *local_ai) {
	local_ai->ai_flags = linux_ai->ai_flags;
	local_ai->ai_family = linux_ai->ai_family;
	local_ai->ai_socktype = linux_ai->ai_socktype;
	local_ai->ai_protocol = linux_ai->ai_protocol;
	local_ai->ai_addrlen = linux_ai->ai_addrlen;
	local_ai->ai_canonname = linux_ai->ai_canonname;
	local_ai->ai_addr = linux_ai->ai_addr;
	local_ai->ai_next = (struct addrinfo *)linux_ai->ai_next;
}

/* Load and convert Linux binary data to local format */
int load_linux_binary_data(int response_type, const void *linux_data, size_t linux_size, 
                          void *local_data, size_t *local_size) {
	
	fprintf(stderr, "DEBUG: load_linux_binary_data: type=%d, linux_size=%zu, local_size=%zu\n", 
		response_type, linux_size, *local_size);
	
	/* Handle different response types */
	switch (response_type) {
		case RESP_SOCKNAME:
		case RESP_PEERNAME:
		case RESP_ADDRINFO_SA:
			/* Handle sockaddr structures */
			if (linux_size >= sizeof(struct linux_sockaddr_in)) {
				const struct linux_sockaddr_in *linux_sin = (const struct linux_sockaddr_in *)linux_data;
				if (linux_sin->sin_family == AF_INET) {
					convert_linux_sockaddr_in_to_local(linux_sin, (struct sockaddr_in *)local_data);
					*local_size = sizeof(struct sockaddr_in);
					return 0;
				}
			}
			if (linux_size >= sizeof(struct linux_sockaddr_in6)) {
				const struct linux_sockaddr_in6 *linux_sin6 = (const struct linux_sockaddr_in6 *)linux_data;
				if (linux_sin6->sin6_family == AF_INET6) {
					convert_linux_sockaddr_in6_to_local(linux_sin6, (struct sockaddr_in6 *)local_data);
					*local_size = sizeof(struct sockaddr_in6);
					return 0;
				}
			}
			break;
			
		case RESP_TIMEOFDAY:
			/* Handle timeval structures */
			if (linux_size >= sizeof(struct linux_timeval)) {
				const struct linux_timeval *linux_tv = (const struct linux_timeval *)linux_data;
				convert_linux_timeval_to_local(linux_tv, (struct timeval *)local_data);
				*local_size = sizeof(struct timeval);
				return 0;
			}
			break;
			
		case RESP_ADDRINFO:
			/* Handle addrinfo structures */
			if (linux_size >= sizeof(struct linux_addrinfo)) {
				const struct linux_addrinfo *linux_ai = (const struct linux_addrinfo *)linux_data;
				convert_linux_addrinfo_to_local(linux_ai, (struct addrinfo *)local_data);
				*local_size = sizeof(struct addrinfo);
				return 0;
			}
			break;
			
		default:
			/* For other types, just copy the data as-is */
			size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
			memcpy(local_data, linux_data, copy_size);
			*local_size = copy_size;
			return 0;
	}
	
	/* If we get here, just copy the data as-is */
	size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
	memcpy(local_data, linux_data, copy_size);
	*local_size = copy_size;
	return 0;
}

#endif /* __FreeBSD__ */
