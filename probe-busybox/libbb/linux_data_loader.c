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

/* Application-specific response type mapping based on calling application */
int map_linux_to_app_response_type(int linux_type, const char *app_tool) {
	if (!app_tool) return linux_type;
	
	/* Map Linux response types to application-specific expected types */
	if (strcmp(app_tool, "evtraceroute") == 0) {
		/* evtraceroute expects: 4, 1, 2, 5, 6, 7, 3, 8, 9 */
		/* Linux datafile has: 8, 9, 3, 7, 4, 1, 5, 6, 7, ... */
		/* This datafile appears to be from a different application */
		/* For now, just pass through the types and let the application handle it */
		fprintf(stderr, "DEBUG: evtraceroute detected but datafile sequence doesn't match expected sequence\n");
		return linux_type;
	} else if (strcmp(app_tool, "evtdig") == 0) {
		/* evtdig expects: 1, 2, 8, 3, 8, 9 */
		switch (linux_type) {
			case 1: return 1; /* RESP_PACKET */
			case 2: return 2; /* RESP_PEERNAME */
			case 8: return 8; /* RESP_CMSG */
			case 3: return 3; /* RESP_SOCKNAME */
			case 9: return 9; /* RESP_ADDRINFO_SA */
			default: return linux_type;
		}
	} else if (strcmp(app_tool, "evping") == 0) {
		/* evping expects: 1, 2, 5, 4, 3, 8, 9 */
		switch (linux_type) {
			case 1: return 1; /* RESP_PACKET */
			case 2: return 2; /* RESP_PEERNAME */
			case 5: return 5; /* RESP_DSTADDR */
			case 4: return 4; /* RESP_TTL */
			case 3: return 3; /* RESP_SOCKNAME */
			case 8: return 8; /* RESP_ADDRINFO */
			case 9: return 9; /* RESP_ADDRINFO_SA */
			default: return linux_type;
		}
	} else if (strcmp(app_tool, "evntp") == 0) {
		/* evntp expects: 4, 1, 5, 3, 8, 9 */
		switch (linux_type) {
			case 4: return 4; /* RESP_TIMEOFDAY */
			case 1: return 1; /* RESP_PACKET */
			case 5: return 5; /* RESP_DSTADDR */
			case 3: return 3; /* RESP_SOCKNAME */
			case 8: return 8; /* RESP_ADDRINFO */
			case 9: return 9; /* RESP_ADDRINFO_SA */
			default: return linux_type;
		}
	} else if (strcmp(app_tool, "evhttpget") == 0 || strcmp(app_tool, "evsslgetcert") == 0) {
		/* evhttpget/evsslgetcert expect: 1, 3, 5 */
		switch (linux_type) {
			case 1: return 1; /* RESP_PACKET */
			case 3: return 3; /* RESP_SOCKNAME */
			case 5: return 5; /* RESP_DSTADDR */
			default: return linux_type;
		}
	}
	
	return linux_type;
}

/* Load and convert Linux binary data to local format */
int load_linux_binary_data(int response_type, const void *linux_data, size_t linux_size, 
                          void *local_data, size_t *local_size) {
	
	fprintf(stderr, "DEBUG: load_linux_binary_data: type=%d, linux_size=%zu, local_size=%zu\n", 
		response_type, linux_size, *local_size);
	
	/* Dump the raw Linux data for verification */
	fprintf(stderr, "DEBUG: Raw Linux data (first 16 bytes): ");
	for (size_t i = 0; i < linux_size && i < 16; i++) {
		fprintf(stderr, "%02x ", ((const unsigned char*)linux_data)[i]);
	}
	fprintf(stderr, "\n");
	
	/* Get current tool from global variable */
	extern const char *current_tool;
	int mapped_type = response_type;
	if (current_tool) {
		mapped_type = map_linux_to_app_response_type(response_type, current_tool);
		fprintf(stderr, "DEBUG: load_linux_binary_data: processing for tool '%s', mapped type %d->%d\n", 
			current_tool, response_type, mapped_type);
	}
	
	/* Handle different response types based on the mapped type */
	if (mapped_type == RESP_SOCKNAME || mapped_type == RESP_PEERNAME || mapped_type == RESP_ADDRINFO_SA) {
		/* Handle sockaddr structures */
		fprintf(stderr, "DEBUG: Processing sockaddr structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_sockaddr_in)) {
			const struct linux_sockaddr_in *linux_sin = (const struct linux_sockaddr_in *)linux_data;
			fprintf(stderr, "DEBUG: Linux sockaddr_in: family=%d, port=%d\n", 
				linux_sin->sin_family, linux_sin->sin_port);
			if (linux_sin->sin_family == AF_INET) {
				convert_linux_sockaddr_in_to_local(linux_sin, (struct sockaddr_in *)local_data);
				*local_size = sizeof(struct sockaddr_in);
				fprintf(stderr, "DEBUG: Converted to FreeBSD sockaddr_in, size=%zu\n", *local_size);
				return 0;
			}
		}
		if (linux_size >= sizeof(struct linux_sockaddr_in6)) {
			const struct linux_sockaddr_in6 *linux_sin6 = (const struct linux_sockaddr_in6 *)linux_data;
			fprintf(stderr, "DEBUG: Linux sockaddr_in6: family=%d, port=%d\n", 
				linux_sin6->sin6_family, linux_sin6->sin6_port);
			if (linux_sin6->sin6_family == AF_INET6) {
				convert_linux_sockaddr_in6_to_local(linux_sin6, (struct sockaddr_in6 *)local_data);
				*local_size = sizeof(struct sockaddr_in6);
				fprintf(stderr, "DEBUG: Converted to FreeBSD sockaddr_in6, size=%zu\n", *local_size);
				return 0;
			}
		}
	} else if (mapped_type == RESP_TIMEOFDAY) {
		/* Handle timeval structures */
		fprintf(stderr, "DEBUG: Processing timeval structure\n");
		if (linux_size >= sizeof(struct linux_timeval)) {
			const struct linux_timeval *linux_tv = (const struct linux_timeval *)linux_data;
			fprintf(stderr, "DEBUG: Linux timeval: sec=%d, usec=%d\n", 
				linux_tv->tv_sec, linux_tv->tv_usec);
			convert_linux_timeval_to_local(linux_tv, (struct timeval *)local_data);
			*local_size = sizeof(struct timeval);
			fprintf(stderr, "DEBUG: Converted to FreeBSD timeval, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_ADDRINFO) {
		/* Handle addrinfo structures */
		fprintf(stderr, "DEBUG: Processing addrinfo structure\n");
		if (linux_size >= sizeof(struct linux_addrinfo)) {
			const struct linux_addrinfo *linux_ai = (const struct linux_addrinfo *)linux_data;
			fprintf(stderr, "DEBUG: Linux addrinfo: family=%d, socktype=%d, protocol=%d\n", 
				linux_ai->ai_family, linux_ai->ai_socktype, linux_ai->ai_protocol);
			convert_linux_addrinfo_to_local(linux_ai, (struct addrinfo *)local_data);
			*local_size = sizeof(struct addrinfo);
			fprintf(stderr, "DEBUG: Converted to FreeBSD addrinfo, size=%zu\n", *local_size);
			return 0;
		}
	} else {
		fprintf(stderr, "DEBUG: Processing generic data (type %d)\n", response_type);
	}
	
	/* If we get here, just copy the data as-is */
	size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
	memcpy(local_data, linux_data, copy_size);
	*local_size = copy_size;
	
	/* Dump the final converted data for verification */
	fprintf(stderr, "DEBUG: Final converted data (first 16 bytes): ");
	for (size_t i = 0; i < *local_size && i < 16; i++) {
		fprintf(stderr, "%02x ", ((const unsigned char*)local_data)[i]);
	}
	fprintf(stderr, "\n");
	
	return 0;
}

#endif /* __FreeBSD__ */
