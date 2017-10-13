/**
 * @file firmwae.h
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
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FIRMWARE_H
#define FIRMWARE_H

#define YANG "terastream-software-hack"

#include <sysrepo.h>
#include "sysrepo/xpath.h"
#include <sysrepo/plugins.h>

size_t sysupgrade_pid;

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
    char *name;
    struct source {
        proto_type_t proto;
        char *uri;
    } source;
    struct credentials {
        cred_type_t type;
        char *val;
    } credentials;
    struct cksum {
        cksum_type_t type;
        char *val;
    } cksum;
    bool preserve_configuration;
    struct download_policy {
        uint32_t download_attempts;
        uint32_t retry_interval;
        uint32_t retry_randomness;
    } policy;
    // TODO 	struct upgrade_policy {
} firmware_t;

typedef struct ctx_s {
    const char *yang_model;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    sr_conn_ctx_t *startup_conn;
    sr_session_ctx_t *startup_sess;
    firmware_t firmware;
    struct software_oper {
        char *name;
        char *uri;
        char *version;
        char *status;
        char *message;
	} oper;
} ctx_t;

#endif /* FIRMWARE_H */
