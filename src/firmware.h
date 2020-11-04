/**
 * @file firmware.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for firmware.c.
 *
 * @copyright
 * Copyright (C) 2017 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FIRMWARE_H
#define FIRMWARE_H

#define SET_STR(VAR, DATA)                  \
	do {                                    \
		if (VAR != NULL) {                  \
			free(VAR);                      \
		}                                   \
		if (DATA != NULL) {                 \
			VAR = strdup(DATA ? DATA : ""); \
		} else {                            \
			VAR = NULL;                     \
		}                                   \
	} while (0)

#define SET_MEM_STR(VAR, DATA)               \
	do {                                     \
		if (DATA != NULL) {                  \
			memcpy(VAR, DATA, sizeof(DATA)); \
		}                                    \
	} while (0)

#include <sysrepo.h>
#include "sysrepo/xpath.h"

typedef enum proto_type_e {
	PROTO_HTTP = 0,
	PROTO_HTTPS,
	PROTO_FTP,
	PROTO_SCP,
} proto_type_t;

typedef enum cred_type_e {
	CRED_PASSWD = 0,
	CRED_CERT,
	CRED_SSH_KEY,
} cred_type_t;

typedef enum cksum_type_e {
	CKSUM_MD5 = 0,
	CKSUM_SHA1,
	CKSUM_SHA2,
	CKSUM_SHA3,
	CKSUM_SHA256,
} cksum_type_t;

typedef struct firmware_s {
	struct source {
		proto_type_t proto;
		char *uri;
	} source;
	struct credentials {
		cred_type_t type;
		char *value;
	} credentials;
	struct cksum {
		cksum_type_t type;
		char *value;
	} checksum;
	bool preserve_configuration;
	struct download_policy {
		uint32_t download_attempts;
		uint32_t retry_interval;
		uint32_t retry_randomness;
	} policy;
	// TODO     struct upgrade_policy {
} firmware_t;

typedef struct oper_s {
	char *uri;
	char *version;
	char *status;
	char *message;
} oper_t;

typedef struct plugin_ctx_s {
	const char *model;

	sr_session_ctx_t *session;
	sr_subscription_ctx_t *subscription;
	sr_conn_ctx_t *startup_connection;
	sr_session_ctx_t *startup_session;
	firmware_t firmware;

	oper_t installing_software;
	oper_t running_software;
} plugin_ctx_t;

#endif /* FIRMWARE_H */
