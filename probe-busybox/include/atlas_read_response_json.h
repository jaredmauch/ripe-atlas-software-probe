/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#ifndef ATLAS_READ_RESPONSE_JSON_H
#define ATLAS_READ_RESPONSE_JSON_H

/* JSON-based response reader functions */
int json_response_init(const char *filename);
void json_response_cleanup(void);
void json_peek_response(int *typep);
void json_read_response(int type, size_t *sizep, void *data);

#endif /* ATLAS_READ_RESPONSE_JSON_H */
