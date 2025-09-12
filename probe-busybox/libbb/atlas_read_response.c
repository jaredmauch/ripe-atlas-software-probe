/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <netinet/in.h>
#include <sys/stat.h>
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

/* Note: Conversion functions moved to linux_data_loader.c to avoid duplication */

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
#define RESP_ADDRINFO_10	10

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
/*	fprintf(stderr, "DEBUG: set_response_tool: tool set to '%s'\n", tool); */
}

/* Helper function to get file size once */
static off_t get_file_size(FILE *file) {
	struct stat file_stat;
	if (fstat(fileno(file), &file_stat) != 0) {
		fprintf(stderr, "ERROR: Failed to get file size: %s\n", strerror(errno));
		exit(1);
	}
	return file_stat.st_size;
}

/* All datafiles are Linux-generated, no detection needed */

#ifndef __linux__
/* Note: Conversion functions moved to linux_data_loader.c to avoid duplication */
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
	int mapped_type;
	
	/* All datafiles are Linux */
	int is_linux_datafile = 1;
	printf("DEBUG: read_response: is_linux_datafile=%d, type=%d\n", is_linux_datafile, type);

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
		/* Convert from little-endian (Linux) to host byte order */
		tmp_type = le32toh(tmp_type);
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
	/* Convert from little-endian (Linux) to host byte order */
	tmp_size = le32toh(tmp_size);
	
	/* Handle data structures that need platform conversion */
	if (is_linux_datafile) {
		char *linux_buffer;
		
		/* Allocate buffer for Linux data conversion with reasonable limits */
		if (tmp_size > 1024 * 1024) { /* 1MB limit */
			fprintf(stderr, "ERROR: Linux data too large (%zu > 1MB)\n", tmp_size);
			exit(1);
		}
		
		linux_buffer = malloc(tmp_size);
		if (!linux_buffer) {
			fprintf(stderr, "ERROR: Failed to allocate %zu bytes for Linux data\n", tmp_size);
			exit(1);
		}
		
		/* Read the full data structure */
		if (read(fd, linux_buffer, tmp_size) != (ssize_t)tmp_size)
		{
			fprintf(stderr, "ERROR: Failed to read %zu bytes of Linux data\n", tmp_size);
			free(linux_buffer);
			exit(1);
		}
		
#ifndef __linux__
		/* Use the Linux data loader for proper conversion */
		if (load_linux_binary_data(type, linux_buffer, tmp_size, data, sizep) != 0) {
			fprintf(stderr, "ERROR: Failed to convert Linux data for type %d\n", type);
			free(linux_buffer);
			exit(1);
		}
		free(linux_buffer);
#else
		/* On Linux, just copy the data directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr, "ERROR: Data bigger than buffer (%zu > %zu)\n", tmp_size, *sizep);
			free(linux_buffer);
			exit(1);
		}
		memcpy(data, linux_buffer, tmp_size);
		*sizep = tmp_size;
		free(linux_buffer);
#endif
	} else {
		/* Regular data, read directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr, "ERROR: Data bigger than buffer (%zu > %zu)\n", tmp_size, *sizep);
			exit(1);
		}
		*sizep= tmp_size;
		if (read(fd, data, tmp_size) != (ssize_t)tmp_size)
		{
			fprintf(stderr, "ERROR: Failed to read %zu bytes\n", tmp_size);
			exit(1);
		}
	}
}


void read_response_file(FILE *file, int type, size_t *sizep, void *data)
{
	int r, tmp_type;
	size_t tmp_size;
	int mapped_type;
	
	/* All datafiles are Linux on FreeBSD */
	int is_linux_datafile = 1;
	off_t file_size;
	
	/* Get file size once at the beginning */
	file_size = get_file_size(file);

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
	else 	if (fread(&tmp_type, sizeof(tmp_type), 1, file) != 1)
	{
		fprintf(stderr, "read_response_file: error reading\n");
		exit(1);
	}
	/* Convert from little-endian (Linux) to host byte order */
	tmp_type = le32toh(tmp_type);
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
	/* Convert from little-endian (Linux) to host byte order */
	tmp_size = le32toh(tmp_size);
	
	/* Handle data structures that need platform conversion */
	if (is_linux_datafile) {
		char *linux_buffer;
		
		/* Use already-obtained file size to validate data size */
		if (tmp_size > file_size) {
			fprintf(stderr, "ERROR: Data size %zu exceeds file size %ld\n", tmp_size, file_size);
			exit(1);
		}
		
		/* Check reasonable limits */
		if (tmp_size > 1024 * 1024) { /* 1MB limit */
			fprintf(stderr, "ERROR: Data size %zu exceeds 1MB limit\n", tmp_size);
			exit(1);
		}
		
		linux_buffer = malloc(tmp_size);
		if (!linux_buffer) {
			fprintf(stderr, "ERROR: Failed to allocate %zu bytes for Linux data\n", tmp_size);
			exit(1);
		}
		
		/* Read the full data structure */
		if (tmp_size != 0)
		{
			r= fread(linux_buffer, tmp_size, 1, file);
			if (r != 1)
			{
				fprintf(stderr,
			"ERROR: Failed to read %zu bytes of Linux data, got %d: %s\n",
					tmp_size, r, strerror(errno));
				free(linux_buffer);
				exit(1);
			}
		}
		
#ifndef __linux__
		/* Use the Linux data loader for proper conversion */
		if (load_linux_binary_data(type, linux_buffer, tmp_size, data, sizep) != 0) {
			fprintf(stderr, "ERROR: Failed to convert Linux data for type %d\n", type);
			free(linux_buffer);
			exit(1);
		}
		free(linux_buffer);
#else
		/* On Linux, just copy the data directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr,
				"ERROR: Data bigger than buffer (%zu > %zu)\n", tmp_size, *sizep);
			free(linux_buffer);
			exit(1);
		}
		memcpy(data, linux_buffer, tmp_size);
		*sizep = tmp_size;
		free(linux_buffer);
#endif
	} else {
		/* Regular data, read directly */
		if (tmp_size > *sizep)
		{
			fprintf(stderr,
				"ERROR: Data bigger than buffer (%zu > %zu)\n", tmp_size, *sizep);
			exit(1);
		}
		*sizep= tmp_size;
		if (tmp_size != 0)
		{
			r= fread(data, tmp_size, 1, file);
			if (r != 1)
			{
				fprintf(stderr,
			"ERROR: Failed to read %zu bytes, got %d: %s\n",
					tmp_size, r, strerror(errno));
				exit(1);
			}
		}
	}
}

