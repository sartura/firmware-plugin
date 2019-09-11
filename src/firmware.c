#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "common.h"
#include "firmware.h"
#include "parse.h"
#include "version.h"

static int install_firmware(ctx_t *);
static int update_firmware(ctx_t *, sr_val_t *);

static const char *xpath_download_policy =
    "/ietf-system:system/" YANG ":software/download-policy";
static const char *xpath_system_software =
    "/ietf-system:system/" YANG ":software/software";

bool can_restart(ctx_t *ctx) {
  if (access("/var/sysupgrade.lock", F_OK) != -1) {
    return false;
  }

  if (0 == strcmp(ctx->installing_software.status, "upgrade-in-progress")) {
    return false;
  } else if (0 == strcmp(ctx->installing_software.status, "upgrade-done")) {
    return false;
  }

  return true;
}

void sig_handler(int signum) {
  INF_MSG("kill chdild process");
  kill(sysupgrade_pid, SIGKILL);
}

int load_startup_datastore(ctx_t *ctx) {
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  sr_val_t *values = NULL;
  size_t count = 0;
  int rc = SR_ERR_OK;

  /* connect to sysrepo */
  rc = sr_connect(SR_CONN_DEFAULT, &connection);
  CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

  /* start session */
  rc = sr_session_start(connection, SR_DS_STARTUP, &session);
  CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

  ctx->startup_sess = session;
  ctx->startup_conn = connection;

  if (!can_restart(ctx)) {
    INF_MSG("could not run a new sysupgrade process");
    return rc;
  }

  // load the startup firmware data into plugin
  char *xpath = "/ietf-system:system/" YANG ":software/software//*";

  rc = sr_get_items(ctx->startup_sess, xpath, &values, &count);
  if (SR_ERR_NOT_FOUND == rc) {
    INF_MSG("empty startup datastore for firmware data");
    return SR_ERR_OK;
  } else if (SR_ERR_OK != rc) {
    goto cleanup;
  }

  size_t i;
  for (i = 0; i < count; i++) {
    if (0 == strncmp(values[i].xpath, xpath_system_software,
                     strlen(xpath_system_software))) {
      rc = update_firmware(ctx, &values[i]);
      CHECK_RET(rc, cleanup, "failed to update firmware: %s", sr_strerror(rc));
    } else if (0 == strncmp(values[i].xpath, xpath_download_policy,
                            strlen(xpath_download_policy))) {
      rc = update_firmware(ctx, &values[i]);
      CHECK_RET(rc, cleanup, "failed to update firmware: %s", sr_strerror(rc));
    }
    sr_print_val(&values[i]);
  }
  if (NULL != values && 0 < count) {
    sr_free_values(values, count);
  }

  if (true == compare_checksum(ctx, &ctx->firmware)) {
    INF_MSG("the firmware has the same checksum as the installed one");
    INF_MSG("don't perform sysupgrade");
    return rc;
  }

  (void)signal(SIGUSR1, sig_handler);
  sysupgrade_pid = fork();
  INF("sysupgrade_pid %d", sysupgrade_pid);
  if (-1 == sysupgrade_pid) {
    ERR_MSG("failed to fork()");
    rc = SR_ERR_INTERNAL;
    goto cleanup;
  } else if (0 == sysupgrade_pid) {
    int rc = SR_ERR_OK;
    while (true) {
      rc = install_firmware(ctx);
      if (SR_ERR_OK == rc) {
        INF_MSG("firmware successfully installed");
        break;
      } else {
        INF_MSG("failed to install firmware");
        exit(EXIT_FAILURE);
      }
    }
    INF_MSG("exit child process");
    exit(EXIT_SUCCESS);
  }

  return rc;
cleanup:
  if (NULL != values && 0 < count) {
    sr_free_values(values, count);
  }
  if (NULL != session) {
    sr_session_stop(session);
  }
  if (NULL != connection) {
    sr_disconnect(connection);
  }

  return rc;
}

static int update_firmware(ctx_t *ctx, sr_val_t *value) {
  int rc = SR_ERR_OK;
  sr_xpath_ctx_t state = {0, 0, 0, 0};
  char *node = sr_xpath_last_node(value->xpath, &state);

  if (0 == strncmp(node, "source", strlen(node)) &&
      SR_STRING_T == value->type) {
    SET_STR(ctx->firmware.source.uri, value->data.string_val);
    SET_STR(ctx->installing_software.uri, ctx->firmware.source.uri);
  } else if (0 == strncmp(node, "password", strlen(node)) &&
             SR_STRING_T == value->type) {
    ctx->firmware.credentials.type = CRED_PASSWD;
    SET_STR(ctx->firmware.credentials.val, value->data.string_val);
  } else if (0 == strncmp(node, "certificate", strlen(node)) &&
             SR_STRING_T == value->type) {
    ctx->firmware.credentials.type = CRED_CERT;
    SET_STR(ctx->firmware.credentials.val, value->data.string_val);
  } else if (0 == strncmp(node, "ssh-key", strlen(node)) &&
             SR_STRING_T == value->type) {
    ctx->firmware.credentials.type = CRED_SSH_KEY;
    SET_STR(ctx->firmware.credentials.val, value->data.string_val);
  } else if (0 == strncmp(node, "preserve-configuration", strlen(node)) &&
             SR_BOOL_T == value->type) {
    ctx->firmware.preserve_configuration = value->data.bool_val;
  } else if (0 == strncmp(node, "type", strlen(node)) &&
             SR_ENUM_T == value->type) {
    const char *type = value->data.string_val;
    if (0 == strcmp("md5", type)) {
      ctx->firmware.cksum.type = CKSUM_MD5;
    } else if (0 == strcmp("sha-1", type)) {
      ctx->firmware.cksum.type = CKSUM_SHA1;
    } else if (0 == strcmp("sha-2", type)) {
      ctx->firmware.cksum.type = CKSUM_SHA2;
    } else if (0 == strcmp("sha-3", type)) {
      ctx->firmware.cksum.type = CKSUM_SHA3;
    } else if (0 == strcmp("sha-256", type)) {
      ctx->firmware.cksum.type = CKSUM_SHA256;
    } else {
      rc = SR_ERR_VALIDATION_FAILED;
      goto cleanup;
    }
  } else if (0 == strncmp(node, "value", strlen(node)) &&
             SR_STRING_T == value->type) {
    SET_STR(ctx->firmware.cksum.val, value->data.string_val);
  } else if (0 == strncmp(node, "download-attempts", strlen(node)) &&
             SR_UINT32_T == value->type) {
    ctx->firmware.policy.download_attempts = value->data.uint32_val;
  } else if (0 == strncmp(node, "retry-interval", strlen(node)) &&
             SR_UINT32_T == value->type) {
    ctx->firmware.policy.retry_interval = value->data.uint32_val;
  } else if (0 == strncmp(node, "retry-randomness", strlen(node)) &&
             SR_UINT32_T == value->type) {
    ctx->firmware.policy.retry_randomness = value->data.uint32_val;
  }

cleanup:
  sr_xpath_recover(&state);
  return rc;
}

static int install_firmware(ctx_t *ctx) {
  int rc = SR_ERR_OK;

  // download the firmware
  INF_MSG("dl-planned");
  SET_MEM_STR(ctx->installing_software.status, "dl-planned");
  rc = firmware_download(ctx);
  CHECK_RET(rc, cleanup, "failed to download firmware: %s", sr_strerror(rc));
  INF_MSG("dl-done");
  SET_MEM_STR(ctx->installing_software.status, "dlownload-done");

  INF_MSG("upgrade-in-progress");
  SET_MEM_STR(ctx->installing_software.status, "upgrade-in-progress");
  // run sysupgrade
  rc = sysupgrade(ctx);
  CHECK_RET(rc, cleanup, "failed to sysupgrade: %s", sr_strerror(rc));

  if (SR_ERR_INTERNAL == rc) {
    char *filename = "/var/sysupgrade.lock";
    if (access(filename, F_OK) != -1) {
      remove(filename);
    }
  }

cleanup:
  return rc;
}

static void default_download_policy(struct download_policy *policy) {
  policy->download_attempts = 0;
  policy->retry_interval = 600;
  policy->retry_randomness = 300;
}

static void clean_configuration_data(firmware_t *firmware) {
  SET_STR(firmware->credentials.val, NULL);
  SET_STR(firmware->cksum.val, NULL);
  SET_STR(firmware->source.uri, NULL);
}

static void init_operational_data(struct software_oper *oper) {
  SET_STR(oper->version, NULL);
  SET_STR(oper->uri, NULL);
  oper->status =
      mmap(NULL, 12, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
  oper->message =
      mmap(NULL, 120, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
}

static void clean_operational_data(struct software_oper *oper) {
  SET_STR(oper->version, NULL);
  SET_STR(oper->uri, NULL);
}

static int parse_change(sr_session_ctx_t *session, const char *xpath,
                        ctx_t *ctx, sr_event_t event) {
  int rc = SR_ERR_OK;
  sr_change_oper_t oper;
  sr_change_iter_t *it = NULL;
  sr_val_t *old_value = NULL;
  sr_val_t *new_value = NULL;
  char change_path[XPATH_MAX_LEN] = {
      0,
  };

  snprintf(change_path, XPATH_MAX_LEN, "%s//*", xpath);

  rc = sr_get_changes_iter(session, xpath, &it);
  if (SR_ERR_OK != rc) {
    printf("Get changes iter failed for xpath %s", xpath);
    goto error;
  }

  bool software_changed = false;
  bool software_deleted = false;
  while (SR_ERR_OK ==
         sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
    if ((SR_OP_MODIFIED == oper || SR_OP_CREATED == oper) && new_value &&
        0 == strncmp(new_value->xpath, xpath_system_software,
                     strlen(xpath_system_software))) {
      INF_MSG("configuration has changed");
      rc = update_firmware(ctx, new_value);
      CHECK_RET(rc, error, "failed to update firmware: %s", sr_strerror(rc));
      software_changed = true;
    } else if ((SR_OP_MODIFIED == oper || SR_OP_CREATED == oper) && old_value &&
               0 == strncmp(old_value->xpath, xpath_system_software,
                            strlen(xpath_system_software))) {
      software_deleted = true;
    } else if ((SR_OP_MODIFIED == oper || SR_OP_CREATED == oper) && new_value &&
               0 == strncmp(new_value->xpath, xpath_download_policy,
                            strlen(xpath_download_policy))) {
      rc = update_firmware(ctx, new_value);
    } else if ((SR_OP_DELETED == oper) && old_value &&
               0 == strstr(old_value->xpath, "preserve-configuration")) {
      ctx->firmware.preserve_configuration = true;
      software_changed = true;
    }
    sr_free_val(old_value);
    sr_free_val(new_value);
  }

  if (true == compare_checksum(ctx, &ctx->firmware)) {
    INF_MSG("the firmware has the same checksum as the installed one");
    INF_MSG("don't perform sysupgrade");
    goto error;
  }

  // creat fork if it doesn't exist, if yes close it and create a new one
  if (software_changed || software_deleted) {
    if (0 < sysupgrade_pid) {
      if (can_restart(ctx)) {
        INF_MSG("kill old sysupgrade process");
        kill(sysupgrade_pid, SIGKILL);
        sysupgrade_pid = 0;
      } else {
        /* don't accept the changes */
        rc = SR_ERR_INTERNAL;
        goto error;
      }
    }
  }

  if (software_changed) {
    (void)signal(SIGUSR1, sig_handler);
    sysupgrade_pid = fork();
    INF("sysupgrade_pid %d", sysupgrade_pid);
    if (-1 == sysupgrade_pid) {
      ERR_MSG("failed to fork()");
      rc = SR_ERR_INTERNAL;
      goto error;
    } else if (0 == sysupgrade_pid) {
      int rc = SR_ERR_OK;
      while (true) {
        rc = install_firmware(ctx);
        if (SR_ERR_OK == rc) {
          INF_MSG("firmware successfully installed");
          break;
        } else {
          INF_MSG("failed to install firmware");
          exit(EXIT_FAILURE);
        }
      }
      INF_MSG("exit child process");
      exit(EXIT_SUCCESS);
    }
  }

  INF_MSG("exit change_cb");
error:
  if (NULL != it) {
    sr_free_change_iter(it);
  }
  return rc;
}

static int change_cb(sr_session_ctx_t *session, const char *module_name,
                     const char *xpath, sr_event_t event, uint32_t request_id,
                     void *private_data) {
  int rc = SR_ERR_OK;
  ctx_t *ctx = private_data;
  INF("%s configuration has changed.", YANG);

  ctx->sess = session;

  /* copy ietf-sytem running to startup */
  if (SR_EV_DONE == event) {
    /* copy running datastore to startup */

    rc = sr_copy_config(ctx->startup_sess, "ietf-system", SR_DS_RUNNING,
                        SR_DS_STARTUP);
    if (SR_ERR_OK != rc) {
      WRN_MSG("Failed to copy running datastore to startup");
      /* TODO handle this error */
      return rc;
    }
    return SR_ERR_OK;
  }

  rc = parse_change(session, xpath, ctx, event);
  CHECK_RET(rc, error, "failed to apply sysrepo: %s", sr_strerror(rc));

error:
  return rc;
}

static int running_software_cb(sr_session_ctx_t *session,
                               const char *module_name, const char *path,
                               const char *request_xpath, uint32_t request_id,
                               struct lyd_node **parent, void *private_data) {
  int rc = SR_ERR_OK;
  ctx_t *ctx = private_data;
  sr_val_t *values = NULL;
  size_t values_cnt = 0;
  char *xpath = "/ietf-system:system-state/" YANG ":running-software";
  char *value_string = NULL;
  const struct ly_ctx *ly_ctx = NULL;

  if (NULL == ctx->running_software.uri) {
    return rc;
  }
  if (NULL == ctx->running_software.status) {
    return rc;
  }
  if (0 != strcmp(ctx->running_software.status, "installed")) {
    return rc;
  }

  values_cnt = 1;
  rc = sr_new_values(values_cnt, &values);
  CHECK_RET(rc, error, "failed sr_new_values: %s", sr_strerror(rc));

  sr_val_set_xpath(&values[0], xpath);
  sr_val_set_str_data(&values[0], SR_STRING_T,
                      (char *)ctx->running_software.uri);

  sr_print_val(&values[0]);

  if (*parent == NULL) {
    ly_ctx = sr_get_context(sr_session_get_connection(session));
    CHECK_NULL_MSG(ly_ctx, &rc, error,
                   "sr_get_context error: libyang context is NULL");
    *parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
  }

  for (size_t i = 0; i < values_cnt; i++) {
    value_string = sr_val_to_str(&values[i]);
    lyd_new_path(*parent, NULL, values[i].xpath, value_string, 0, 0);
    free(value_string);
    value_string = NULL;
  }

error:
  if (values != NULL) {
    sr_free_values(values, values_cnt);
    values = NULL;
    values_cnt = 0;
  }
  return rc;
}

static int state_data_cb(sr_session_ctx_t *session, const char *module_name,
                         const char *path, const char *request_xpath,
                         uint32_t request_id, struct lyd_node **parent,
                         void *private_data) {
  int rc = SR_ERR_OK;
  ctx_t *ctx = private_data;
  int counter = 0;
  sr_val_t *values = NULL;
  size_t values_cnt = 0;
  char *xpath_base = "/ietf-system:system-state/" YANG ":software";
  char *xpath_list = NULL;
  char *xpath = NULL;
  char *value_string = NULL;
  const struct ly_ctx *ly_ctx = NULL;

  /* currently running software */
  if (NULL != ctx->running_software.uri) {
    if (NULL != ctx->running_software.version)
      counter++;
    if (NULL != ctx->running_software.message &&
        0 < strlen(ctx->running_software.message))
      counter++;
    if (NULL != ctx->running_software.status &&
        0 < strlen(ctx->running_software.status))
      counter++;
  }

  /* installing software */
  if (NULL != ctx->installing_software.uri) {
    if (NULL != ctx->installing_software.version)
      counter++;
    if (NULL != ctx->installing_software.message &&
        0 < strlen(ctx->installing_software.message))
      counter++;
    if (NULL != ctx->installing_software.status &&
        0 < strlen(ctx->installing_software.status))
      counter++;
  }

  values_cnt = counter;
  rc = sr_new_values(values_cnt, &values);
  CHECK_RET(rc, error, "failed sr_new_values: %s", sr_strerror(rc));

  counter = 0;

  int inst_size =
      ctx->installing_software.uri ? strlen(ctx->installing_software.uri) : 0;
  int runn_size =
      ctx->running_software.uri ? strlen(ctx->running_software.uri) : 0;
  int uri_size = inst_size > runn_size ? inst_size : runn_size;
  int xpath_len = uri_size + XPATH_MAX_LEN;
  xpath_list = (char *)malloc(sizeof(char) * xpath_len);
  xpath = (char *)malloc(sizeof(char) * xpath_len);

  if (NULL != ctx->installing_software.uri) {
    snprintf(xpath_list, xpath_len, "%s[source='%s']", xpath_base,
             ctx->installing_software.uri);
    if (ctx->installing_software.version) {
      snprintf(xpath, xpath_len, "%s/%s", xpath_list, "version");
      sr_val_set_xpath(&values[counter], xpath);
      sr_val_set_str_data(&values[counter], SR_STRING_T,
                          (char *)ctx->installing_software.version);
      counter++;
    }
    if (ctx->installing_software.status &&
        0 < strlen(ctx->installing_software.status)) {
      snprintf(xpath, xpath_len, "%s/%s", xpath_list, "status");
      sr_val_set_xpath(&values[counter], xpath);
      sr_val_set_str_data(&values[counter], SR_ENUM_T,
                          (char *)ctx->installing_software.status);
      counter++;
    }
    if (ctx->installing_software.message &&
        0 < strlen(ctx->installing_software.message)) {
      snprintf(xpath, xpath_len, "%s/%s", xpath_list, "message");
      sr_val_set_xpath(&values[counter], xpath);
      sr_val_set_str_data(&values[counter], SR_STRING_T,
                          (char *)ctx->installing_software.message);
      counter++;
    }
  }

  /* running software */
  if (NULL != ctx->running_software.uri) {
    snprintf(xpath_list, xpath_len, "%s[source='%s']", xpath_base,
             ctx->running_software.uri);
    if (ctx->running_software.version) {
      snprintf(xpath, xpath_len, "%s/%s", xpath_list, "version");
      sr_val_set_xpath(&values[counter], xpath);
      sr_val_set_str_data(&values[counter], SR_STRING_T,
                          (char *)ctx->running_software.version);
      counter++;
    }
    if (ctx->running_software.status &&
        0 < strlen(ctx->running_software.status)) {
      snprintf(xpath, xpath_len, "%s/%s", xpath_list, "status");
      sr_val_set_xpath(&values[counter], xpath);
      sr_val_set_str_data(&values[counter], SR_ENUM_T,
                          (char *)ctx->running_software.status);
      counter++;
    }
    if (ctx->running_software.message &&
        0 < strlen(ctx->running_software.message)) {
      snprintf(xpath, xpath_len, "%s/%s", xpath_list, "message");
      sr_val_set_xpath(&values[counter], xpath);
      sr_val_set_str_data(&values[counter], SR_STRING_T,
                          (char *)ctx->running_software.message);
      counter++;
    }
  }

  // if (*values_cnt > 0) {
  //    INF("Debug sysrepo values printout: %zu", *values_cnt);
  //    for (size_t i = 0; i < *values_cnt; i++) {
  //        sr_print_val(&(*values)[i]);
  //    }
  //}

  if (*parent == NULL) {
    ly_ctx = sr_get_context(sr_session_get_connection(session));
    CHECK_NULL_MSG(ly_ctx, &rc, error,
                   "sr_get_context error: libyang context is NULL");
    *parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
  }

  for (size_t i = 0; i < values_cnt; i++) {
    value_string = sr_val_to_str(&values[i]);
    lyd_new_path(*parent, NULL, values[i].xpath, value_string, 0, 0);
    free(value_string);
    value_string = NULL;
  }

error:
  if (NULL != xpath) {
    free(xpath);
  }
  if (NULL != xpath_list) {
    free(xpath_list);
  }
  if (values != NULL) {
    sr_free_values(values, values_cnt);
    values = NULL;
    values_cnt = 0;
  }
  return rc;
}

static void serial_number_ubus_cb(struct ubus_request *req, int type,
                                  struct blob_attr *msg) {
  ubus_ctx_t *ubus_ctx = req->priv;
  struct json_object *jobj_parent = NULL, *jobj_system = NULL,
                     *jobj_serial = NULL;
  char *json_string = NULL;
  const char *result_string = NULL;
  int rc = SR_ERR_OK;

  if (msg) {
    json_string = blobmsg_format_json(msg, true);
    jobj_parent = json_tokener_parse(json_string);
  } else {
    goto cleanup;
  }

  json_object_object_get_ex(jobj_parent, "system", &jobj_system);
  if (NULL == jobj_system) {
    goto cleanup;
  }
  json_object_object_get_ex(jobj_system, "serialno", &jobj_serial);
  if (NULL == jobj_serial) {
    goto cleanup;
  }

  result_string = json_object_get_string(jobj_serial);

  *ubus_ctx->values_cnt = 1;
  rc = sr_new_val("/ietf-system:system-state/ietf-system:platform/" YANG
                  ":serial-number",
                  ubus_ctx->values);
  CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
  sr_val_set_str_data(*ubus_ctx->values, SR_STRING_T, result_string);

cleanup:
  if (NULL != jobj_parent) {
    json_object_put(jobj_parent);
  }
  if (NULL != json_string) {
    free(json_string);
  }
  return;
}

static int serial_number_cb(sr_session_ctx_t *session, const char *module_name,
                            const char *path, const char *request_xpath,
                            uint32_t request_id, struct lyd_node **parent,
                            void *private_data) {
  int rc = SR_ERR_OK;
  ctx_t *ctx = private_data;
  uint32_t id = 0;
  struct blob_buf buf = {0};
  ubus_ctx_t ubus_ctx = {0, 0, 0};
  int u_rc = UBUS_STATUS_OK;
  sr_val_t *values = NULL;
  size_t values_cnt = 0;
  char *value_string = NULL;
  const struct ly_ctx *ly_ctx = NULL;

  struct ubus_context *u_ctx = ubus_connect(NULL);
  if (u_ctx == NULL) {
    ERR_MSG("Could not connect to ubus");
    rc = SR_ERR_INTERNAL;
    goto cleanup;
  }

  blob_buf_init(&buf, 0);
  u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
  if (UBUS_STATUS_OK != u_rc) {
    ERR("ubus [%d]: no object router.system\n", u_rc);
    rc = SR_ERR_INTERNAL;
    goto cleanup;
  }

  ubus_ctx.ctx = ctx;
  ubus_ctx.values = &values;
  ubus_ctx.values_cnt = &values_cnt;
  u_rc = ubus_invoke(u_ctx, id, "info", buf.head, serial_number_ubus_cb,
                     &ubus_ctx, 0);
  if (UBUS_STATUS_OK != u_rc) {
    ERR("ubus [%d]: no object info\n", u_rc);
    rc = SR_ERR_INTERNAL;
    goto cleanup;
  }

  if (*parent == NULL) {
    ly_ctx = sr_get_context(sr_session_get_connection(session));
    CHECK_NULL_MSG(ly_ctx, &rc, cleanup,
                   "sr_get_context error: libyang context is NULL");
    *parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
  }

  for (size_t i = 0; i < values_cnt; i++) {
    value_string = sr_val_to_str(&values[i]);
    lyd_new_path(*parent, NULL, values[i].xpath, value_string, 0, 0);
    free(value_string);
    value_string = NULL;
  }

cleanup:
  if (NULL != u_ctx) {
    ubus_free(u_ctx);
    blob_buf_free(&buf);
  }

  if (values != NULL) {
    sr_free_values(values, values_cnt);
    values = NULL;
    values_cnt = 0;
  }
  return rc;
}

static void software_version_ubus_cb(struct ubus_request *req, int type,
                                     struct blob_attr *msg) {
  ubus_ctx_t *ubus_ctx = req->priv;
  struct json_object *jobj_parent = NULL, *jobj_system = NULL,
                     *jobj_firmware = NULL;
  char *json_string = NULL;
  const char *result_string = NULL;
  int rc = SR_ERR_OK;

  if (msg) {
    json_string = blobmsg_format_json(msg, true);
    jobj_parent = json_tokener_parse(json_string);
  } else {
    goto cleanup;
  }

  json_object_object_get_ex(jobj_parent, "system", &jobj_system);
  if (NULL == jobj_system) {
    goto cleanup;
  }
  json_object_object_get_ex(jobj_system, "firmware", &jobj_firmware);
  if (NULL == jobj_firmware) {
    goto cleanup;
  }

  result_string = json_object_get_string(jobj_firmware);

  *ubus_ctx->values_cnt = 1;
  rc = sr_new_val("/ietf-system:system-state/ietf-system:platform/" YANG
                  ":software-version",
                  ubus_ctx->values);
  CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));
  sr_val_set_str_data(*ubus_ctx->values, SR_STRING_T, result_string);

cleanup:
  if (NULL != jobj_parent) {
    json_object_put(jobj_parent);
  }
  if (NULL != json_string) {
    free(json_string);
  }
  return;
}

static int software_version_cb(sr_session_ctx_t *session,
                               const char *module_name, const char *path,
                               const char *request_xpath, uint32_t request_id,
                               struct lyd_node **parent, void *private_data) {
  int rc = SR_ERR_OK;
  ctx_t *ctx = private_data;
  uint32_t id = 0;
  struct blob_buf buf = {0};
  ubus_ctx_t ubus_ctx = {0, 0, 0};
  int u_rc = UBUS_STATUS_OK;
  sr_val_t *values = NULL;
  size_t values_cnt = 0;
  char *value_string = NULL;
  const struct ly_ctx *ly_ctx = NULL;

  INF_MSG("Getting oper data: software version");

  struct ubus_context *u_ctx = ubus_connect(NULL);
  if (u_ctx == NULL) {
    ERR_MSG("Could not connect to ubus");
    rc = SR_ERR_INTERNAL;
    goto cleanup;
  }

  blob_buf_init(&buf, 0);
  u_rc = ubus_lookup_id(u_ctx, "router.system", &id);
  if (UBUS_STATUS_OK != u_rc) {
    ERR("ubus [%d]: no object router.system\n", u_rc);
    rc = SR_ERR_INTERNAL;
    goto cleanup;
  }

  ubus_ctx.ctx = ctx;
  ubus_ctx.values = &values;
  ubus_ctx.values_cnt = &values_cnt;
  u_rc = ubus_invoke(u_ctx, id, "info", buf.head, software_version_ubus_cb,
                     &ubus_ctx, 0);
  if (UBUS_STATUS_OK != u_rc) {
    ERR("ubus [%d]: no object info\n", u_rc);
    rc = SR_ERR_INTERNAL;
    goto cleanup;
  }

  if (*parent == NULL) {
    ly_ctx = sr_get_context(sr_session_get_connection(session));
    CHECK_NULL_MSG(ly_ctx, &rc, cleanup,
                   "sr_get_context error: libyang context is NULL");
    *parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
  }

  for (size_t i = 0; i < values_cnt; i++) {
    value_string = sr_val_to_str(&values[i]);
    lyd_new_path(*parent, NULL, values[i].xpath, value_string, 0, 0);
    free(value_string);
    value_string = NULL;
  }

cleanup:
  if (NULL != u_ctx) {
    ubus_free(u_ctx);
    blob_buf_free(&buf);
  }

  if (values != NULL) {
    sr_free_values(values, values_cnt);
    values = NULL;
    values_cnt = 0;
  }
  return rc;
}

static int rpc_firstboot_cb(sr_session_ctx_t *session, const char *op_path,
                            const sr_val_t *input, const size_t input_cnt,
                            sr_event_t event, uint32_t request_id,
                            sr_val_t **output, size_t *output_cnt,
                            void *private_data) {
  (void)signal(SIGUSR1, sig_handler);
  size_t rpcd_pid = fork();

  INF("rpcd_pid %d", rpcd_pid);
  if (-1 == sysupgrade_pid) {
    ERR_MSG("failed to fork()");
    return SR_ERR_INTERNAL;
  } else if (0 == rpcd_pid) {
    /* wait for sysrepo/netopeer2 to finish the RPC call */
    sleep(3);

    INF_MSG("rpc callback rpc_firstboot_cb has been called");
    struct blob_buf buf = {0};
    uint32_t id = 0;
    int u_rc = 0;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
      ERR_MSG("Could not connect to ubus");
      goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "juci.system", &id);
    if (UBUS_STATUS_OK != u_rc) {
      ERR("ubus [%d]: no object juci.system", u_rc);
      goto cleanup;
    }

    u_rc = ubus_invoke(u_ctx, id, "defaultreset", buf.head, NULL, NULL, 0);
    if (UBUS_STATUS_OK != u_rc) {
      ERR("ubus [%d]: no object defaultreset", u_rc);
      goto cleanup;
    }

  cleanup:
    if (NULL != u_ctx) {
      ubus_free(u_ctx);
      blob_buf_free(&buf);
    }

    if (UBUS_STATUS_OK != u_rc) {
      return SR_ERR_INTERNAL;
    }
    exit(EXIT_SUCCESS);
  }

  return SR_ERR_OK;
}

static int rpc_reboot_cb(sr_session_ctx_t *session, const char *op_path,
                         const sr_val_t *input, const size_t input_cnt,
                         sr_event_t event, uint32_t request_id,
                         sr_val_t **output, size_t *output_cnt,
                         void *private_data) {
  (void)signal(SIGUSR1, sig_handler);
  size_t rpcd_pid = fork();

  INF("rpcd_pid %d", rpcd_pid);
  if (-1 == sysupgrade_pid) {
    ERR_MSG("failed to fork()");
    return SR_ERR_INTERNAL;
  } else if (0 == rpcd_pid) {
    /* wait for sysrepo/netopeer2 to finish the RPC call */
    sleep(3);

    INF_MSG("rpc callback rpc_reboot_cb has been called");
    struct blob_buf buf = {0};
    uint32_t id = 0;
    int u_rc = 0;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
      ERR_MSG("Could not connect to ubus");
      goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "juci.system", &id);
    if (UBUS_STATUS_OK != u_rc) {
      ERR("ubus [%d]: no object juci.system", u_rc);
      goto cleanup;
    }

    u_rc = ubus_invoke(u_ctx, id, "reboot", buf.head, NULL, NULL, 0);
    if (UBUS_STATUS_OK != u_rc) {
      ERR("ubus [%d]: no object reboot", u_rc);
      goto cleanup;
    }

  cleanup:
    if (NULL != u_ctx) {
      ubus_free(u_ctx);
      blob_buf_free(&buf);
    }

    if (UBUS_STATUS_OK != u_rc) {
      return SR_ERR_INTERNAL;
    }
    exit(EXIT_SUCCESS);
  }
  return SR_ERR_OK;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {
  int rc = SR_ERR_OK;
  sysupgrade_pid = 0;

  /* INF("sr_plugin_init_cb for sysrepo-plugin-dt-network"); */

  ctx_t *ctx = calloc(1, sizeof(*ctx));
  ctx->sub = NULL;
  ctx->sess = session;
  ctx->startup_conn = NULL;
  ctx->startup_sess = NULL;
  ctx->yang_model = YANG;
  *private_ctx = ctx;
  clean_configuration_data(&ctx->firmware);
  init_operational_data(&ctx->installing_software);
  init_operational_data(&ctx->running_software);
  default_download_policy(&ctx->firmware.policy);

  /* load the startup datastore */
  INF_MSG("load sysrepo startup datastore");
  rc = load_startup_datastore(ctx);
  CHECK_RET(rc, error, "failed to load startup datastore: %s", sr_strerror(rc));

  rc = sr_module_change_subscribe(
      ctx->sess, "ietf-system", "/ietf-system:system/" YANG ":software",
      change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &ctx->sub);
  CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

  rc = sr_oper_get_items_subscribe(
      ctx->sess, "ietf-system",
      "/ietf-system:system-state/ietf-system:platform/" YANG
      ":software-version",
      software_version_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
  CHECK_RET(rc, error, "failed sr_oper_get_items_subscribe: %s",
            sr_strerror(rc));

  rc = sr_oper_get_items_subscribe(
      ctx->sess, "ietf-system",
      "/ietf-system:system-state/ietf-system:platform/" YANG ":serial-number",
      serial_number_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
  CHECK_RET(rc, error, "failed sr_oper_get_items_subscribe: %s",
            sr_strerror(rc));

  rc = sr_oper_get_items_subscribe(
      ctx->sess, "ietf-system", "/ietf-system:system-state/" YANG ":software",
      state_data_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
  CHECK_RET(rc, error, "failed sr_oper_get_items_subscribe: %s",
            sr_strerror(rc));

  rc = sr_oper_get_items_subscribe(
      ctx->sess, "ietf-system",
      "/ietf-system:system-state/" YANG ":running-software",
      running_software_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
  CHECK_RET(rc, error, "failed sr_oper_get_items_subscribe: %s",
            sr_strerror(rc));

  rc = sr_rpc_subscribe(ctx->sess, "/" YANG ":system-reset-restart",
                        rpc_firstboot_cb, ctx, 0, SR_SUBSCR_CTX_REUSE,
                        &ctx->sub);
  CHECK_RET(rc, error, "failed sr_rpc_subscribe: %s", sr_strerror(rc));

  rc = sr_rpc_subscribe(ctx->sess, "/ietf-system:system-restart", rpc_reboot_cb,
                        ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->sub);
  CHECK_RET(rc, error, "failed sr_rpc_subscribe: %s", sr_strerror(rc));

  INF_MSG("Plugin initialization successfull");

  return SR_ERR_OK;

error:
  ERR("Plugin initialization failed: %s", sr_strerror(rc));
  if (NULL != ctx->sub) {
    sr_unsubscribe(ctx->sub);
    ctx->sub = NULL;
  }
  return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {
  INF("Plugin cleanup called, private_ctx is %s available.",
      private_ctx ? "" : "not");
  if (!private_ctx)
    return;

  ctx_t *ctx = private_ctx;
  if (NULL == ctx) {
    return;
  }
  /* clean startup datastore */
  if (NULL != ctx->startup_sess) {
    sr_session_stop(ctx->startup_sess);
  }
  if (NULL != ctx->startup_conn) {
    sr_disconnect(ctx->startup_conn);
  }
  if (NULL != ctx->sub) {
    sr_unsubscribe(ctx->sub);
  }
  clean_configuration_data(&ctx->firmware);
  clean_operational_data(&ctx->installing_software);
  clean_operational_data(&ctx->running_software);

  if (can_restart(ctx) && sysupgrade_pid > 0) {
    INF_MSG("kill background sysupgrade process");
    INF("kill pid %d", sysupgrade_pid);
    kill(sysupgrade_pid, SIGKILL);
    sysupgrade_pid = 0;
  }

  free(ctx);

  DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum) {
  INF_MSG("Sigint called, exiting...");
  exit_application = 1;
}

int main() {
  INF_MSG("Plugin application mode initialized");
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  void *private_ctx = NULL;
  int rc = SR_ERR_OK;

  ENABLE_LOGGING(SR_LL_DBG);

  /* connect to sysrepo */
  rc = sr_connect(SR_CONN_DEFAULT, &connection);
  CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

  /* start session */
  rc = sr_session_start(connection, SR_DS_RUNNING, &session);
  CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

  rc = sr_plugin_init_cb(session, &private_ctx);
  CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

  /* loop until ctrl-c is pressed / SIGINT is received */
  signal(SIGINT, sigint_handler);
  signal(SIGPIPE, SIG_IGN);
  while (!exit_application) {
    sleep(1); /* or do some more useful work... */
  }

cleanup:
  sr_plugin_cleanup_cb(session, private_ctx);
  if (NULL != session) {
    sr_session_stop(session);
  }
  if (NULL != connection) {
    sr_disconnect(connection);
  }
}
#endif
