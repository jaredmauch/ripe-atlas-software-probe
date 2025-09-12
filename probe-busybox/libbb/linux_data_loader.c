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
		/* Handle socket name - just copy as-is */
		fprintf(stderr, "DEBUG: Processing socket name (type %d)\n", response_type);
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
		return 0;
	} else if (mapped_type == RESP_DSTADDR) {
		/* Handle destination address - just copy as-is */
		fprintf(stderr, "DEBUG: Processing destination address (type %d)\n", response_type);
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
		/* Handle socket name - just copy as-is */
		fprintf(stderr, "DEBUG: Processing socket name (type %d)\n", response_type);
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
		return 0;
	} else if (mapped_type == RESP_DSTADDR) {
		/* Handle destination address - just copy as-is */
		fprintf(stderr, "DEBUG: Processing destination address (type %d)\n", response_type);
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
		mapped_type = response_type; // Keep original response type
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
	} else if (mapped_type == RESP_DSTADDR) {
		/* Handle destination address structures */
		fprintf(stderr, "DEBUG: Processing destination address structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_dstaddr)) {
			const struct linux_dstaddr *linux_dst = (const struct linux_dstaddr *)linux_data;
			fprintf(stderr, "DEBUG: Linux dstaddr: family=%d\n", linux_dst->family);
			convert_linux_dstaddr_to_local(linux_dst, (struct linux_dstaddr *)local_data);
			*local_size = sizeof(struct linux_dstaddr);
			fprintf(stderr, "DEBUG: Converted to FreeBSD dstaddr, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_PACKET || mapped_type == RESP_SENDTO || mapped_type == RESP_DATA) {
		/* Handle packet data structures */
		fprintf(stderr, "DEBUG: Processing packet/sendto/data structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_packet)) {
			const struct linux_packet *linux_pkt = (const struct linux_packet *)linux_data;
			fprintf(stderr, "DEBUG: Linux packet/sendto/data: size=%u\n", linux_pkt->size);
			convert_linux_packet_to_local(linux_pkt, (struct linux_packet *)local_data, linux_size);
			*local_size = linux_size;
			fprintf(stderr, "DEBUG: Converted to FreeBSD packet/sendto/data, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_RCVDTCLASS) {
		/* Handle Traffic Class structures (contains address data) */
		fprintf(stderr, "DEBUG: Processing Traffic Class structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_traffic_class)) {
			const struct linux_traffic_class *linux_tc = (const struct linux_traffic_class *)linux_data;
			fprintf(stderr, "DEBUG: Linux Traffic Class: ttl=%d, tos=%d, flags=%d\n", 
				linux_tc->ttl, linux_tc->tos, linux_tc->flags);
			convert_linux_traffic_class_to_local(linux_tc, (struct linux_traffic_class *)local_data);
			*local_size = sizeof(struct linux_traffic_class);
			fprintf(stderr, "DEBUG: Converted to FreeBSD Traffic Class, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_RCVDTTL || mapped_type == RESP_TTL) {
		/* Handle TTL structures */
		fprintf(stderr, "DEBUG: Processing TTL structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_ttl)) {
			const struct linux_ttl *linux_ttl = (const struct linux_ttl *)linux_data;
			fprintf(stderr, "DEBUG: Linux TTL: ttl=%d, tos=%d, flags=%d\n", 
				linux_ttl->ttl, linux_ttl->tos, linux_ttl->flags);
			convert_linux_ttl_to_local(linux_ttl, (struct linux_ttl *)local_data);
			*local_size = sizeof(struct linux_ttl);
			fprintf(stderr, "DEBUG: Converted to FreeBSD TTL, size=%zu\n", *local_size);
			return 0;
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
	} else if (mapped_type == RESP_PROTO) {
		/* Handle protocol structures */
		fprintf(stderr, "DEBUG: Processing protocol structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_proto)) {
			const struct linux_proto *linux_proto = (const struct linux_proto *)linux_data;
			fprintf(stderr, "DEBUG: Linux proto: protocol=%d, flags=%d\n", 
				linux_proto->protocol, linux_proto->flags);
			convert_linux_proto_to_local(linux_proto, (struct linux_proto *)local_data);
			*local_size = sizeof(struct linux_proto);
			fprintf(stderr, "DEBUG: Converted to FreeBSD proto, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_CMSG) {
		/* Handle control message structures */
		fprintf(stderr, "DEBUG: Processing control message structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_cmsg)) {
			const struct linux_cmsg *linux_cmsg = (const struct linux_cmsg *)linux_data;
			fprintf(stderr, "DEBUG: Linux cmsg: len=%d, level=%d, type=%d\n", 
				linux_cmsg->cmsg_len, linux_cmsg->cmsg_level, linux_cmsg->cmsg_type);
			convert_linux_cmsg_to_local(linux_cmsg, (struct linux_cmsg *)local_data, linux_size);
			*local_size = linux_size;
			fprintf(stderr, "DEBUG: Converted to FreeBSD cmsg, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_LENGTH) {
		/* Handle length structures */
		fprintf(stderr, "DEBUG: Processing length structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_length)) {
			const struct linux_length *linux_length = (const struct linux_length *)linux_data;
			fprintf(stderr, "DEBUG: Linux length: length=%d, flags=%d\n", 
				linux_length->length, linux_length->flags);
			convert_linux_length_to_local(linux_length, (struct linux_length *)local_data);
			*local_size = sizeof(struct linux_length);
			fprintf(stderr, "DEBUG: Converted to FreeBSD length, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_TIMEOUT) {
		/* Handle timeout structures */
		fprintf(stderr, "DEBUG: Processing timeout structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_timeout)) {
			const struct linux_timeout *linux_timeout = (const struct linux_timeout *)linux_data;
			fprintf(stderr, "DEBUG: Linux timeout: timeout_ms=%d, flags=%d\n", 
				linux_timeout->timeout_ms, linux_timeout->flags);
			convert_linux_timeout_to_local(linux_timeout, (struct linux_timeout *)local_data);
			*local_size = sizeof(struct linux_timeout);
			fprintf(stderr, "DEBUG: Converted to FreeBSD timeout, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_RESOLVER) {
		/* Handle resolver structures */
		fprintf(stderr, "DEBUG: Processing resolver structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_resolver)) {
			const struct linux_resolver *linux_resolver = (const struct linux_resolver *)linux_data;
			fprintf(stderr, "DEBUG: Linux resolver: id=%d, flags=%d, name=%s\n", 
				linux_resolver->resolver_id, linux_resolver->flags, linux_resolver->resolver_name);
			convert_linux_resolver_to_local(linux_resolver, (struct linux_resolver *)local_data);
			*local_size = sizeof(struct linux_resolver);
			fprintf(stderr, "DEBUG: Converted to FreeBSD resolver, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_N_RESOLV) {
		/* Handle resolver structures (same as RESP_RESOLVER) */
		fprintf(stderr, "DEBUG: Processing resolver structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_resolver)) {
			const struct linux_resolver *linux_resolver = (const struct linux_resolver *)linux_data;
			fprintf(stderr, "DEBUG: Linux resolver: id=%d, flags=%d, name=%s\n", 
				linux_resolver->resolver_id, linux_resolver->flags, linux_resolver->resolver_name);
			convert_linux_resolver_to_local(linux_resolver, (struct linux_resolver *)local_data);
			*local_size = sizeof(struct linux_resolver);
			fprintf(stderr, "DEBUG: Converted to FreeBSD resolver, size=%zu\n", *local_size);
			return 0;
		}
	} else if (mapped_type == RESP_READ_ERROR) {
		/* Handle read error structures */
		fprintf(stderr, "DEBUG: Processing read error structure (type %d)\n", response_type);
		if (linux_size >= sizeof(struct linux_read_error)) {
			const struct linux_read_error *linux_error = (const struct linux_read_error *)linux_data;
			fprintf(stderr, "DEBUG: Linux read error: code=%d, flags=%d, msg=%s\n", 
				linux_error->error_code, linux_error->flags, linux_error->error_msg);
			convert_linux_read_error_to_local(linux_error, (struct linux_read_error *)local_data);
			*local_size = sizeof(struct linux_read_error);
			fprintf(stderr, "DEBUG: Converted to FreeBSD read error, size=%zu\n", *local_size);
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

#endif /* !__linux__ */
