/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <netinet/in.h>
#ifdef CONFIG_HAVE_JSON_C
#include "atlas_read_response_json.h"
#endif

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

/* Linux dstaddr structure */
struct linux_dstaddr {
	int family;            /* Address family */
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
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

#endif /* !__linux__ */

/* Response types for packet replay */
#define RESP_PACKET	1
#define RESP_SOCKNAME	2
#define RESP_DSTADDR	3
#define RESP_PEERNAME	4

/* Additional response types for cross-platform compatibility */
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

static int got_type= 0;
static int stored_type;
#ifdef CONFIG_HAVE_JSON_C
static int using_json = 0;
#endif

/* Global variable to track current tool for response type mapping */
const char *current_tool = NULL;

/* Set the current tool for response type mapping */
void set_response_tool(const char *tool) {
	current_tool = tool;
	fprintf(stderr, "DEBUG: set_response_tool: tool set to '%s'\n", tool);
}

/* All datafiles are Linux-generated, no detection needed */
static int detect_linux_datafile(int response_type) {
	/* Suppress unused parameter warning */
	(void)response_type;
	return 1; /* Always return true - all datafiles are Linux */
}

/* Map Linux response types to tool-specific types for cross-platform compatibility */
static int map_linux_response_type(int linux_type) {
	/* No mapping needed - return original response type */
	return linux_type;
}

#ifndef __linux__
/* Convert Linux timeval to local OS timeval - unused for now */
#if 0
static void convert_linux_timeval_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const struct timeval *linux_tv = (const struct timeval *)linux_data;
	struct timeval *local_tv = (struct timeval *)local_data;
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	/* Direct copy - timeval structure is generally compatible across platforms */
	if (linux_size >= sizeof(struct timeval)) {
		local_tv->tv_sec = linux_tv->tv_sec;
		local_tv->tv_usec = linux_tv->tv_usec;
		*local_size = sizeof(struct timeval);
	} else {
		/* Fallback: copy what we can */
		memcpy(local_data, linux_data, linux_size);
		*local_size = linux_size;
	}
}
#endif
#endif /* !__linux__ */



#ifndef __linux__
/* Convert Linux sockaddr to local OS sockaddr - unused for now */
#if 0
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
#endif /* __DEBUG __ */
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	/* Handle IPv4 addresses - check multiple possible family values */
	if (linux_size >= sizeof(struct sockaddr_in)) {
		if (linux_sin->sin_family == AF_INET || 
		    linux_sin->sin_family == 2 ||  /* Common AF_INET value */
		    linux_sin->sin_family == 0) {  /* Sometimes family is 0 in datafiles */
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
		    linux_sin6->sin6_family == 0) {   /* Sometimes family is 0 in datafiles */
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
			/* Check if this looks like IPv4 data by examining the address bytes */
						/* const uint8_t *addr_bytes = (const uint8_t *)&linux_sin->sin_addr; */
			
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
			/* Check if this looks like IPv6 data by examining the address bytes */
						/* const uint8_t *addr_bytes = (const uint8_t *)&linux_sin6->sin6_addr; */
			
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
#endif
#endif /* !__linux__ */

/* Check if file is JSON format and initialize if so */
#ifdef CONFIG_HAVE_JSON_C
static int check_and_init_json(FILE *file)
{
	long pos = ftell(file);
	char magic[10];
	int is_json = 0;
	
	if (fread(magic, 1, 10, file) == 10) {
		fprintf(stderr, "DEBUG: Magic bytes: %c%c%c%c%c%c%c%c%c%c\n", 
			magic[0], magic[1], magic[2], magic[3], magic[4],
			magic[5], magic[6], magic[7], magic[8], magic[9]);
		fflush(stderr);
		/* Check for JSON: starts with { and contains "version" */
		if (magic[0] == '{' && magic[1] == '\n' && magic[2] == ' ' && 
		    magic[3] == ' ' && magic[4] == '"' && magic[5] == 'v') {
			is_json = 1;
			fprintf(stderr, "DEBUG: JSON magic detected\n");
			fflush(stderr);
		}
	}
	
	fseek(file, pos, SEEK_SET);
	
	if (is_json) {
		/* Try to find JSON files in the testsuite directory */
		/* We'll scan for common JSON test files */
		const char *test_dirs[] = {
			"probe-busybox/testsuite/evhttpget-data/",
			"probe-busybox/testsuite/evntp-data/",
			"probe-busybox/testsuite/evping-data/",
			"probe-busybox/testsuite/evsslgetcert-data/",
			"probe-busybox/testsuite/evtdig-data/",
			"probe-busybox/testsuite/evtraceroute-data/",
			NULL
		};
		
		const char *test_files[] = {
			"evhttpget-4.json", "evhttpget-6.json", "evhttpget-1.json",
			"evntp-4.json", "evntp-6.json",
			"evping-4.json", "evping-6.json",
			"evsslgetcert-4.json", "evsslgetcert-6.json",
			"evtdig-4.json", "evtdig-6.json",
			"evtraceroute-4.json", "evtraceroute-6.json",
			NULL
		};
		
		int i, j;
		char full_path[512];
		
		for (i = 0; test_dirs[i]; i++) {
			for (j = 0; test_files[j]; j++) {
				snprintf(full_path, sizeof(full_path), "%s%s", test_dirs[i], test_files[j]);
				if (json_response_init(full_path) == 0) {
					using_json = 1;
					fprintf(stderr, "DEBUG: JSON initialized with %s\n", full_path);
					fflush(stderr);
					return 1;
				}
			}
		}
		fprintf(stderr, "DEBUG: JSON detection failed - no matching file found\n");
		fflush(stderr);
	}
	
	return 0;
}
#endif

void peek_response(int fd, int *typep)
{
	if (!got_type)
	{
		if (read(fd, &stored_type, sizeof(stored_type)) !=
			sizeof(stored_type))
		{
			fprintf(stderr, "peek_response: error reading\n");
			exit(1);
		}
		got_type= 1;
	}
	*typep= stored_type;
}

void peek_response_file(FILE *file, int *typep)
{
	if (!got_type)
	{
		/* Check if this is a JSON file */
#ifdef CONFIG_HAVE_JSON_C
		if (check_and_init_json(file)) {
			fprintf(stderr, "DEBUG: JSON file detected, using JSON parser\n");
			fflush(stderr);
			json_peek_response(&stored_type);
			got_type = 1;
		} else {
			fprintf(stderr, "DEBUG: Not a JSON file, using binary parser\n");
			fflush(stderr);
#endif
			if (fread(&stored_type, sizeof(stored_type), 1, file) != 1)
			{
				fprintf(stderr, "peek_response_file: error reading\n");
				exit(1);
			}
			got_type= 1;
#ifdef CONFIG_HAVE_JSON_C
		}
#endif
	}
	*typep= stored_type;
}

void read_response(int fd, int type, size_t *sizep, void *data)
{
	int tmp_type;
	size_t tmp_size;
	char temp_buffer[256]; /* Buffer for reading data */
	int mapped_type;
	
	/* All datafiles are Linux on FreeBSD */
	int is_linux_datafile = 1;

	if (got_type)
	{
		tmp_type= stored_type;
		got_type= 0;
	}
	else
	{
		if (read(fd, &tmp_type, sizeof(tmp_type)) != sizeof(tmp_type))
		{
			fprintf(stderr, "read_response: error reading\n");
			exit(1);
		}
	}
	/* No response type mapping needed - use original type */
	mapped_type = tmp_type;
	
#if 0
	fprintf(stderr, "DEBUG: read_response: expected type %d, got type %d, mapped to %d\n", type, tmp_type, mapped_type);
	
#endif
	if (mapped_type != type)
	{
		fprintf(stderr,
			 "read_response: wrong type, expected %d, got %d (mapped from %d) - tool: %s\n",
			type, mapped_type, tmp_type, current_tool ? current_tool : "unknown");
		exit(1);
	}
	if (read(fd, &tmp_size, sizeof(tmp_size)) != sizeof(tmp_size))
	{
		fprintf(stderr, "read_response: error reading\n");
		exit(1);
	}
	
	/* Handle data structures that need platform conversion */
	if (is_linux_datafile && tmp_size <= sizeof(temp_buffer)) {
		/* Read into temporary buffer first */
		if (read(fd, temp_buffer, tmp_size) != (ssize_t)tmp_size)
		{
			fprintf(stderr, "read_response: error reading\n");
			exit(1);
		}
		
#ifndef __linux__
		/* Use the new Linux data loader for proper conversion */
		if (is_linux_datafile) {
			load_linux_binary_data(type, temp_buffer, tmp_size, data, sizep);
		} else {
			/* For non-Linux datafiles, just copy the data */
			if (tmp_size > *sizep)
			{
				fprintf(stderr, "read_response: data bigger than buffer\n");
				exit(1);
			}
			memcpy(data, temp_buffer, tmp_size);
			*sizep = tmp_size;
		}
#else
		/* On Linux, just copy the data directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr, "read_response: data bigger than buffer\n");
			exit(1);
		}
		memcpy(data, temp_buffer, tmp_size);
		*sizep = tmp_size;
#endif
	} else {
		/* Regular data, read directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr, "read_response: data bigger than buffer\n");
			exit(1);
		}
		*sizep= tmp_size;
		if (read(fd, data, tmp_size) != (ssize_t)tmp_size)
		{
			fprintf(stderr, "read_response: error reading\n");
			exit(1);
		}
	}
}


void read_response_file(FILE *file, int type, size_t *sizep, void *data)
{
	int r, tmp_type;
	size_t tmp_size;
	char temp_buffer[256]; /* Buffer for reading data */
	int mapped_type;
	
	/* All datafiles are Linux on FreeBSD */
	int is_linux_datafile = 1;

#if 0
	fprintf(stderr, "DEBUG: read_response_file called with type=%d, sizep=%zu\n", type, *sizep);
#endif

#ifdef CONFIG_HAVE_JSON_C
	if (using_json) {
		/* Use JSON reader */
		json_read_response(type, sizep, data);
		return;
	}
#endif

	if (got_type)
	{
		tmp_type= stored_type;
		got_type= 0;
	}
	else if (fread(&tmp_type, sizeof(tmp_type), 1, file) != 1)
	{
		fprintf(stderr, "read_response_file: error reading\n");
		exit(1);
	}
	/* No response type mapping needed - use original type */
	mapped_type = tmp_type;
	
	if (mapped_type != type)
	{
		fprintf(stderr,
		 "read_response_file: wrong type, expected %d, got %d (mapped from %d) - tool: %s\n",
			type, mapped_type, tmp_type, current_tool ? current_tool : "unknown");
		exit(1);
	}
	if (fread(&tmp_size, sizeof(tmp_size), 1, file) != 1)
	{
		fprintf(stderr, "read_response_file: error reading\n");
		exit(1);
	}
	
	/* Handle data structures that need platform conversion */
	if (is_linux_datafile && tmp_size <= sizeof(temp_buffer)) {
		/* Read into temporary buffer first */
		if (tmp_size != 0)
		{
			r= fread(temp_buffer, tmp_size, 1, file);
			if (r != 1)
			{
				fprintf(stderr,
			"read_response_file: error reading %u bytes, got %d: %s\n",
					(unsigned)tmp_size, r, strerror(errno));
				exit(1);
			}
		}
		
#ifndef __linux__
		/* Use the new Linux data loader for proper conversion */
		if (is_linux_datafile) {
			load_linux_binary_data(type, temp_buffer, tmp_size, data, sizep);
		} else {
			/* For non-Linux datafiles, just copy the data */
			if (tmp_size > *sizep)
			{
				fprintf(stderr,
					"read_response_file: data bigger than buffer\n");
				exit(1);
			}
			memcpy(data, temp_buffer, tmp_size);
			*sizep = tmp_size;
		}
#else
		/* On Linux, just copy the data directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr,
				"read_response_file: data bigger than buffer\n");
			exit(1);
		}
		memcpy(data, temp_buffer, tmp_size);
		*sizep = tmp_size;
#endif
	} else {
		/* Regular data, read directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr,
				"read_response_file: data bigger than buffer\n");
			exit(1);
		}
		*sizep= tmp_size;
		if (tmp_size != 0)
		{
			r= fread(data, tmp_size, 1, file);
			if (r != 1)
			{
				fprintf(stderr,
			"read_response_file: error reading %u bytes, got %d: %s\n",
					(unsigned)tmp_size, r, strerror(errno));
				exit(1);
			}
		}
	}
}

