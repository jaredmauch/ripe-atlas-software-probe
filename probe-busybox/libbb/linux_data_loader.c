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

/* Application-specific response type mapping based on calling application */
int map_linux_to_app_response_type(int linux_type, const char *app_tool) {
	/* No mapping needed - return original type */
	return linux_type;
}

/* Load and convert Linux binary data to local OS format */
int load_linux_binary_data(int response_type, const void *linux_data, size_t linux_size, void *local_data, size_t *local_size) {
	/* Map response type if needed */
	extern const char *current_tool;
	int mapped_type = response_type;
	if (current_tool) {
		mapped_type = response_type; // Keep original response type
		fprintf(stderr, "DEBUG: load_linux_binary_data: processing for tool '%s', mapped type %d->%d\n",
			current_tool, response_type, mapped_type);
	}
	
	/* Handle different response types */
	if (mapped_type == RESP_PACKET) {
		/* Handle packet data - just copy as-is */
		fprintf(stderr, "DEBUG: Processing packet data (type %d)\n", response_type);
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
		return 0;
	} else if (mapped_type == RESP_SOCKNAME) {
		/* Handle socket name - just copy as-is for now */
		fprintf(stderr, "DEBUG: Processing socket name (type %d)\n", response_type);
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
		return 0;
	} else if (mapped_type == RESP_DSTADDR) {
		/* Handle destination address - just copy as-is for now */
		fprintf(stderr, "DEBUG: Processing destination address (type %d)\n", response_type);
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
		return 0;
	} else if (mapped_type == RESP_ADDRINFO) {
		/* Handle addrinfo - just copy as-is for now */
		fprintf(stderr, "DEBUG: Processing addrinfo (type %d)\n", response_type);
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
		return 0;
	} else {
		/* For other types, just copy the data as-is */
		fprintf(stderr, "DEBUG: Processing generic data (type %d)\n", response_type);
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
		return 0;
	}
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

/* Linux protocol structure */
struct linux_proto {
	uint8_t protocol;      /* Protocol number (IPPROTO_TCP, IPPROTO_UDP, etc.) */
	uint8_t flags;         /* Protocol flags */
	uint16_t reserved;     /* Reserved field */
};

/* Linux control message structure */
struct linux_cmsg {
	uint32_t cmsg_len;     /* Length of control message */
	int32_t cmsg_level;    /* Originating protocol */
	int32_t cmsg_type;     /* Protocol-specific type */
	uint8_t cmsg_data[0];  /* Control message data */
};

/* Linux length structure */
struct linux_length {
	uint32_t length;       /* Data length */
	uint32_t flags;        /* Length flags */
};

/* Linux timeout structure */
struct linux_timeout {
	uint32_t timeout_ms;   /* Timeout in milliseconds */
	uint32_t flags;        /* Timeout flags */
};

/* Linux resolver structure */
struct linux_resolver {
	uint32_t resolver_id;  /* Resolver identifier */
	uint32_t flags;        /* Resolver flags */
	char resolver_name[64]; /* Resolver name/address */
};

/* Linux read error structure */
struct linux_read_error {
	int32_t error_code;    /* Error code (errno) */
	uint32_t flags;        /* Error flags */
	char error_msg[128];   /* Error message */
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

/* Linux-specific destination address structure */
struct linux_dstaddr {
	int family;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
};

/* Linux-specific packet data structure */
struct linux_packet {
	uint32_t size;
	uint8_t data[0];
};

/* Linux-specific TTL structure */
struct linux_ttl {
	uint8_t ttl;
	uint8_t tos;
	uint16_t flags;
};

/* Linux-specific traffic class structure */
struct linux_traffic_class {
	uint8_t ttl;
	uint8_t tos;
	uint16_t flags;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
};

/* Convert Linux destination address to FreeBSD destination address */
static void convert_linux_dstaddr_to_local(const struct linux_dstaddr *linux_dst, struct linux_dstaddr *local_dst) {
	local_dst->family = linux_dst->family;
	if (linux_dst->family == AF_INET) {
		local_dst->addr.ipv4 = linux_dst->addr.ipv4;
	} else if (linux_dst->family == AF_INET6) {
		local_dst->addr.ipv6 = linux_dst->addr.ipv6;
	}
}

/* Convert Linux packet data to FreeBSD packet data */
static void convert_linux_packet_to_local(const struct linux_packet *linux_pkt, struct linux_packet *local_pkt, size_t data_size) {
	local_pkt->size = linux_pkt->size;
	memcpy(local_pkt->data, linux_pkt->data, data_size - sizeof(uint32_t));
}

/* Convert Linux TTL to FreeBSD TTL */
static void convert_linux_ttl_to_local(const struct linux_ttl *linux_ttl, struct linux_ttl *local_ttl) {
	local_ttl->ttl = linux_ttl->ttl;
	local_ttl->tos = linux_ttl->tos;
	local_ttl->flags = linux_ttl->flags;
}

/* Convert Linux traffic class to FreeBSD traffic class */
static void convert_linux_traffic_class_to_local(const struct linux_traffic_class *linux_tc, struct linux_traffic_class *local_tc) {
	local_tc->ttl = linux_tc->ttl;
	local_tc->tos = linux_tc->tos;
	local_tc->flags = linux_tc->flags;
	local_tc->addr = linux_tc->addr;
}

/* Convert Linux protocol to FreeBSD protocol */
static void convert_linux_proto_to_local(const struct linux_proto *linux_proto, struct linux_proto *local_proto) {
	local_proto->protocol = linux_proto->protocol;
	local_proto->flags = linux_proto->flags;
	local_proto->reserved = linux_proto->reserved;
}

/* Convert Linux control message to FreeBSD control message */
static void convert_linux_cmsg_to_local(const struct linux_cmsg *linux_cmsg, struct linux_cmsg *local_cmsg, size_t data_size) {
	local_cmsg->cmsg_len = linux_cmsg->cmsg_len;
	local_cmsg->cmsg_level = linux_cmsg->cmsg_level;
	local_cmsg->cmsg_type = linux_cmsg->cmsg_type;
	if (data_size > sizeof(struct linux_cmsg)) {
		memcpy(local_cmsg->cmsg_data, linux_cmsg->cmsg_data, data_size - sizeof(struct linux_cmsg));
	}
}

/* Convert Linux length to FreeBSD length */
static void convert_linux_length_to_local(const struct linux_length *linux_length, struct linux_length *local_length) {
	local_length->length = linux_length->length;
	local_length->flags = linux_length->flags;
}

/* Convert Linux timeout to FreeBSD timeout */
static void convert_linux_timeout_to_local(const struct linux_timeout *linux_timeout, struct linux_timeout *local_timeout) {
	local_timeout->timeout_ms = linux_timeout->timeout_ms;
	local_timeout->flags = linux_timeout->flags;
}

/* Convert Linux resolver to FreeBSD resolver */
static void convert_linux_resolver_to_local(const struct linux_resolver *linux_resolver, struct linux_resolver *local_resolver) {
	local_resolver->resolver_id = linux_resolver->resolver_id;
	local_resolver->flags = linux_resolver->flags;
	strncpy(local_resolver->resolver_name, linux_resolver->resolver_name, sizeof(local_resolver->resolver_name) - 1);
	local_resolver->resolver_name[sizeof(local_resolver->resolver_name) - 1] = '\0';
}

/* Convert Linux read error to FreeBSD read error */
static void convert_linux_read_error_to_local(const struct linux_read_error *linux_error, struct linux_read_error *local_error) {
	local_error->error_code = linux_error->error_code;
	local_error->flags = linux_error->flags;
	strncpy(local_error->error_msg, linux_error->error_msg, sizeof(local_error->error_msg) - 1);
	local_error->error_msg[sizeof(local_error->error_msg) - 1] = '\0';
}
	

#endif /* !__linux__ */
