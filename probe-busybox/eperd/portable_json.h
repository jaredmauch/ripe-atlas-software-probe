/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#ifndef PORTABLE_JSON_H
#define PORTABLE_JSON_H

#include <sys/socket.h>

/* Convert address family constants to portable string representation */
static inline const char *af_to_string(int af)
{
	switch (af) {
		case AF_INET:
			return "AF_INET";
		case AF_INET6:
			return "AF_INET6";
		case AF_UNSPEC:
			return "AF_UNSPEC";
		default:
			return "AF_UNKNOWN";
	}
}

/* Convert address family constants to portable string representation for numeric values */
static inline const char *af_num_to_string(int af_num)
{
	switch (af_num) {
		case 4:
			return "AF_INET";
		case 6:
			return "AF_INET6";
		case 0:
			return "AF_UNSPEC";
		default:
			return "AF_UNKNOWN";
	}
}

#endif /* PORTABLE_JSON_H */
