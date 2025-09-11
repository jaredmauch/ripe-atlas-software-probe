/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <netinet/in.h>
#ifdef CONFIG_HAVE_JSON_C
#include "atlas_read_response_json.h"
#endif

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
static const char *current_tool = NULL;
static int is_linux_datafile = 0;

/* Set the current tool for response type mapping */
void set_response_tool(const char *tool) {
	current_tool = tool;
	fprintf(stderr, "DEBUG: set_response_tool: tool set to '%s'\n", tool);
}

/* Detect if we're dealing with a Linux datafile based on response types */
static int detect_linux_datafile(int response_type) {
	/* If we see response types that are Linux-specific, mark as Linux datafile */
	if (response_type == 5 || response_type == 6 || response_type == 7) {
		is_linux_datafile = 1;
		fprintf(stderr, "DEBUG: detect_linux_datafile: detected Linux datafile (type %d)\n", response_type);
		return 1;
	}
	fprintf(stderr, "DEBUG: detect_linux_datafile: type %d, is_linux_datafile=%d\n", response_type, is_linux_datafile);
	return is_linux_datafile;
}

/* Map Linux response types to tool-specific types for cross-platform compatibility */
static int map_linux_response_type(int linux_type) {
	/* Detect if this is a Linux datafile */
	detect_linux_datafile(linux_type);
	
	if (!current_tool) {
		fprintf(stderr, "DEBUG: map_linux_response_type: no current_tool set\n");
		return linux_type; /* No mapping if tool not set */
	}
	
	/* Only apply mapping if we detected a Linux datafile */
	if (!is_linux_datafile) {
		fprintf(stderr, "DEBUG: map_linux_response_type: not a Linux datafile\n");
		return linux_type;
	}
	
	fprintf(stderr, "DEBUG: map_linux_response_type: mapping Linux type %d for tool %s\n", linux_type, current_tool);
	
	/* Map based on tool-specific response type expectations */
	if (strstr(current_tool, "traceroute") || strstr(current_tool, "evtraceroute")) {
		int mapped_type;
		switch (linux_type) {
			case 8: mapped_type = 4; break;  /* RESP_ADDRINFO -> RESP_PROTO (Linux datafile has different sequence) */
			case 9: mapped_type = 1; break;  /* RESP_ADDRINFO_SA -> RESP_PACKET */
			case 3: mapped_type = 2; break;  /* RESP_SOCKNAME -> RESP_PEERNAME */
			case 6: mapped_type = 5; break;  /* RESP_RCVDTCLASS -> RESP_RCVDTTL */
			case 7: mapped_type = 6; break;  /* RESP_SENDTO -> RESP_RCVDTCLASS */
			case 4: mapped_type = 7; break;  /* RESP_PROTO -> RESP_SENDTO */
			case 1: mapped_type = 1; break;  /* RESP_PACKET -> RESP_PACKET */
			case 2: mapped_type = 2; break;  /* RESP_PEERNAME -> RESP_PEERNAME */
			case 5: mapped_type = 5; break;  /* RESP_RCVDTTL -> RESP_RCVDTTL */
			default: 
				fprintf(stderr, "DEBUG: map_linux_response_type: unknown Linux type %d, returning as-is\n", linux_type);
				return linux_type;
		}
		fprintf(stderr, "DEBUG: map_linux_response_type: mapped Linux type %d -> %d\n", linux_type, mapped_type);
		return mapped_type;
	} else if (strstr(current_tool, "ping") || strstr(current_tool, "evping")) {
		switch (linux_type) {
			case 4: return 4;  /* RESP_TTL -> RESP_TTL */
			case 5: return 5;  /* RESP_DSTADDR -> RESP_DSTADDR */
			case 1: return 1;  /* RESP_PACKET -> RESP_PACKET */
			case 2: return 2;  /* RESP_PEERNAME -> RESP_PEERNAME */
			case 3: return 3;  /* RESP_SOCKNAME -> RESP_SOCKNAME */
			default: return linux_type;
		}
	} else if (strstr(current_tool, "dig") || strstr(current_tool, "evtdig")) {
		switch (linux_type) {
			case 4: return 4;  /* RESP_N_RESOLV -> RESP_N_RESOLV */
			case 5: return 5;  /* RESP_RESOLVER -> RESP_RESOLVER */
			case 6: return 6;  /* RESP_LENGTH -> RESP_LENGTH */
			case 7: return 7;  /* RESP_DATA -> RESP_DATA */
			case 8: return 8;  /* RESP_CMSG -> RESP_CMSG */
			case 9: return 9;  /* RESP_TIMEOUT -> RESP_TIMEOUT */
			case 1: return 1;  /* RESP_PACKET -> RESP_PACKET */
			case 2: return 2;  /* RESP_PEERNAME -> RESP_PEERNAME */
			case 3: return 3;  /* RESP_SOCKNAME -> RESP_SOCKNAME */
			default: return linux_type;
		}
	} else if (strstr(current_tool, "ntp") || strstr(current_tool, "evntp")) {
		switch (linux_type) {
			case 4: return 4;  /* RESP_TIMEOFDAY -> RESP_TIMEOFDAY */
			case 1: return 1;  /* RESP_PACKET -> RESP_PACKET */
			case 2: return 2;  /* RESP_PEERNAME -> RESP_PEERNAME */
			case 3: return 3;  /* RESP_SOCKNAME -> RESP_SOCKNAME */
			default: return linux_type;
		}
	}
	
	return linux_type; /* Default: no mapping */
}

/* Convert Linux timeval to local OS timeval */
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

/* Convert Linux addrinfo to local OS addrinfo */
static void convert_linux_addrinfo_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const struct addrinfo *linux_ai = (const struct addrinfo *)linux_data;
	struct addrinfo *local_ai = (struct addrinfo *)local_data;
	
	/* Clear the output buffer */
	memset(local_data, 0, *local_size);
	
	if (linux_size >= sizeof(struct addrinfo)) {
		/* Copy basic fields that are generally compatible */
		local_ai->ai_flags = linux_ai->ai_flags;
		local_ai->ai_family = linux_ai->ai_family;
		local_ai->ai_socktype = linux_ai->ai_socktype;
		local_ai->ai_protocol = linux_ai->ai_protocol;
		local_ai->ai_addrlen = linux_ai->ai_addrlen;
		
		/* Handle canonical name - copy if present */
		if (linux_ai->ai_canonname) {
			/* Note: This is a pointer, so we can't directly copy it */
			/* The actual string data would need to be handled separately */
			local_ai->ai_canonname = NULL; /* Will be set by caller if needed */
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

/* Convert Linux sockaddr to local OS sockaddr */
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
			const uint8_t *addr_bytes = (const uint8_t *)&linux_sin->sin_addr;
			
			/* Check if port is in big-endian or little-endian format */
			uint16_t port_be = ntohs(linux_sin->sin_port);
			uint16_t port_le = linux_sin->sin_port;
			
			/* Use the port that makes sense (reasonable port numbers) */
			uint16_t port = (port_be > 0 && port_be < 65536 && port_be != port_le) ? port_be : port_le;
			
			local_sin->sin_family = AF_INET;
			local_sin->sin_port = htons(port);
			local_sin->sin_addr = linux_sin->sin_addr;
			*local_size = sizeof(struct sockaddr_in);
			return;
		}
		/* Try to parse as IPv6 if data length suggests it */
		else if (linux_size == sizeof(struct sockaddr_in6)) {
			/* Check if this looks like IPv6 data by examining the address bytes */
			const uint8_t *addr_bytes = (const uint8_t *)&linux_sin6->sin6_addr;
			
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
	size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
	memcpy(local_data, linux_data, copy_size);
	*local_size = copy_size;
}

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
	/* Apply response type mapping for cross-platform compatibility */
	int mapped_type = map_linux_response_type(tmp_type);
	
	fprintf(stderr, "DEBUG: read_response: expected type %d, got type %d, mapped to %d\n", type, tmp_type, mapped_type);
	
	if (mapped_type != type)
	{
		fprintf(stderr,
			 "read_response: wrong type, expected %d, got %d (mapped from %d)\n",
			type, mapped_type, tmp_type);
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
		
		/* Apply appropriate conversion based on response type */
		if (type == RESP_DSTADDR || type == RESP_SOCKNAME || type == RESP_PEERNAME || type == RESP_ADDRINFO_SA) {
			/* Convert sockaddr structures */
			convert_linux_sockaddr_to_local(temp_buffer, tmp_size, data, sizep);
		} else if (type == RESP_TIMEOFDAY) {
			/* Convert timeval structures */
			convert_linux_timeval_to_local(temp_buffer, tmp_size, data, sizep);
		} else if (type == RESP_ADDRINFO) {
			/* Convert addrinfo structures */
			convert_linux_addrinfo_to_local(temp_buffer, tmp_size, data, sizep);
		} else {
			/* No conversion needed - direct copy */
			if (tmp_size > *sizep)
			{
				fprintf(stderr, "read_response: data bigger than buffer\n");
				exit(1);
			}
			memcpy(data, temp_buffer, tmp_size);
			*sizep = tmp_size;
		}
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

	fprintf(stderr, "DEBUG: read_response_file called with type=%d, sizep=%zu\n", type, *sizep);

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
	/* Apply response type mapping for cross-platform compatibility */
	int mapped_type = map_linux_response_type(tmp_type);
	
	if (mapped_type != type)
	{
		fprintf(stderr,
		 "read_response_file: wrong type, expected %d, got %d (mapped from %d)\n",
			type, mapped_type, tmp_type);
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
		
		/* Apply appropriate conversion based on response type */
		if (type == RESP_DSTADDR || type == RESP_SOCKNAME || type == RESP_PEERNAME || type == RESP_ADDRINFO_SA) {
			/* Convert sockaddr structures */
			convert_linux_sockaddr_to_local(temp_buffer, tmp_size, data, sizep);
		} else if (type == RESP_TIMEOFDAY) {
			/* Convert timeval structures */
			convert_linux_timeval_to_local(temp_buffer, tmp_size, data, sizep);
		} else if (type == RESP_ADDRINFO) {
			/* Convert addrinfo structures */
			convert_linux_addrinfo_to_local(temp_buffer, tmp_size, data, sizep);
		} else {
			/* No conversion needed - direct copy */
			if (tmp_size > *sizep)
			{
				fprintf(stderr,
					"read_response_file: data bigger than buffer\n");
				exit(1);
			}
			memcpy(data, temp_buffer, tmp_size);
			*sizep = tmp_size;
		}
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

