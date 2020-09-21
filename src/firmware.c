#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>

#include <srpo_ubus.h>

#include "firmware.h"
#include "upgrade.h"
#include "utils/memory.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define BASE_YANG_MODEL "ietf-system"
#define SOFTWARE_YANG_MODEL "terastream-software"

#define RESTART_YANG_PATH "/" BASE_YANG_MODEL ":system-restart"
#define SOFTWARE_YANG_PATH "/" BASE_YANG_MODEL ":system/" SOFTWARE_YANG_MODEL ":software"
#define RESET_YANG_PATH "/" SOFTWARE_YANG_MODEL ":system-reset-restart"

#define SOFTWARE_YANG_STATE_PATH "/ietf-system:system-state/" SOFTWARE_YANG_MODEL ":software"
#define RUNNING_YANG_STATE_PATH "/ietf-system:system-state/" SOFTWARE_YANG_MODEL ":running-software"
#define VERSION_YANG_STATE_PATH "/ietf-system:system-state/platform/" SOFTWARE_YANG_MODEL ":software-version"
#define SERIAL_YANG_STATE_PATH "/ietf-system:system-state/platform/" SOFTWARE_YANG_MODEL ":serial-number"

static const char *SOFTWARE_XPATH = SOFTWARE_YANG_PATH "/software";
static const char *DOWNLOAD_POLICY_XPATH = SOFTWARE_YANG_PATH "/download-policy";
static const char *RUNNING_XPATH = RUNNING_YANG_STATE_PATH;

static void sigusr1_handler(__attribute__((unused)) int signum);

static int firmware_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);
static int firmware_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
static int firmware_state_software_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
static int firmware_state_running_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
static int firmware_rpc_cb(sr_session_ctx_t *session, const char *op_path,
						   const sr_val_t *input, const size_t input_cnt,
						   sr_event_t event, uint32_t request_id,
						   sr_val_t **output, size_t *output_cnt, void *private_data);

static void init_operational_data(oper_t *operational);
static void clean_operational_data(oper_t *operational);
static void clean_configuration_data(firmware_t *firmware);
static void default_download_policy(struct download_policy *policy);

static int update_firmware_context_value(plugin_ctx_t *ctx, const struct lyd_node *node);

static int can_restart(plugin_ctx_t *ctx);
static int run_firmware_install_steps(plugin_ctx_t *ctx);
static int load_startup_datastore(plugin_ctx_t *session);

static void firmware_ubus_version(const char *ubus_json, srpo_ubus_result_values_t *values);
static void firmware_ubus_serial(const char *ubus_json, srpo_ubus_result_values_t *values);
static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent);

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	plugin_ctx_t *ctx = NULL;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	*private_data = NULL;

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	/* create private plugin context */
	ctx = xcalloc(1, sizeof(plugin_ctx_t));
	*ctx = (plugin_ctx_t){
		.model = SOFTWARE_YANG_MODEL,
		.startup_connection = connection,
		.session = session,
		.startup_session = startup_session,
		.subscription = NULL,
	};
	*private_data = ctx;

	clean_configuration_data(&ctx->firmware);
	init_operational_data(&ctx->installing_software);
	init_operational_data(&ctx->running_software);
	default_download_policy(&ctx->firmware.policy);

	error = load_startup_datastore(ctx);
	if (error != SR_ERR_OK) {
		SRP_LOG_ERR("load_startup_datastore error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to module change");

	error = sr_module_change_subscribe(session, BASE_YANG_MODEL, SOFTWARE_YANG_PATH, firmware_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to get oper items");

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, SOFTWARE_YANG_STATE_PATH, firmware_state_software_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, RUNNING_YANG_STATE_PATH, firmware_state_running_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, VERSION_YANG_STATE_PATH, firmware_state_data_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, SERIAL_YANG_STATE_PATH, firmware_state_data_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to rpc");

	error = sr_rpc_subscribe(session, RESTART_YANG_PATH, firmware_rpc_cb, *private_data, 0, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_rpc_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_rpc_subscribe(session, RESET_YANG_PATH, firmware_rpc_cb, *private_data, 0, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_rpc_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("plugin init done");

	goto out;

error_out:
	sr_unsubscribe(subscription);

out:

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	plugin_ctx_t *ctx = (plugin_ctx_t *) private_data;

	if (ctx->startup_session) {
		sr_session_stop(ctx->startup_session);
	}

	clean_configuration_data(&ctx->firmware);
	clean_operational_data(&ctx->installing_software);
	clean_operational_data(&ctx->running_software);

	if (can_restart(ctx) && sysupgrade_pid > 0) {
		kill(sysupgrade_pid, SIGKILL);
		sysupgrade_pid = 0;
	}

	FREE_SAFE(ctx);

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int firmware_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = 0;
	plugin_ctx_t *ctx = (plugin_ctx_t *) private_data;
	sr_change_iter_t *firmware_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const struct lyd_node *node = NULL;
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	bool prev_default = false;
	char *node_xpath = NULL;
	bool software_changed = false;
	bool software_deleted = false;

	SRP_LOG_INF("module_name: %s, xpath: %s, event: %d, request_id: %" PRIu32, module_name, xpath, event, request_id);

	if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto out;
	}

	if (event == SR_EV_DONE) {
		error = sr_copy_config(ctx->startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto out;
		}
	}

	if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &firmware_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto out;
		}

		while (sr_get_change_tree_next(session, firmware_change_iter, &operation, &node,
									   &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = lyd_path(node);

			if ((operation == SR_OP_MODIFIED || operation == SR_OP_CREATED) &&
				strncmp(node_xpath, SOFTWARE_XPATH, strlen(SOFTWARE_XPATH)) == 0) {
				error = update_firmware_context_value(ctx, node);
				if (error != SR_ERR_OK) {
					SRP_LOG_ERR("update_firmware_context_value error (%d): %s", error, sr_strerror(error));
					goto out;
				}

				software_changed = true;

			} else if ((operation == SR_OP_MODIFIED || operation == SR_OP_CREATED) &&
					   strncmp(node_xpath, SOFTWARE_XPATH, strlen(SOFTWARE_XPATH)) == 0) {
				software_deleted = true;

			} else if ((operation == SR_OP_MODIFIED || operation == SR_OP_CREATED) &&
					   strncmp(node_xpath, DOWNLOAD_POLICY_XPATH, strlen(DOWNLOAD_POLICY_XPATH)) == 0) {
				error = update_firmware_context_value(ctx, node);
				if (error != SR_ERR_OK) {
					SRP_LOG_ERR("update_firmware_context_value error (%d): %s", error, sr_strerror(error));
					goto out;
				}

			} else if ((operation == SR_OP_DELETED) && strstr(node_xpath, "preserve-configuration") == 0) {
				ctx->firmware.preserve_configuration = true;

				software_changed = true;
			}
		}

		if (compare_firmware_checksum(ctx, &ctx->firmware) == true) {
			SRP_LOG_ERRMSG("update_firmware_context_value error: installed firmware has the same checksum");
			goto out;
		}

		// create fork if it doesn't exist, if yes close it and create a new one
		if ((software_changed || software_deleted) && sysupgrade_pid > 0) {
			if (can_restart(ctx)) {
				kill(sysupgrade_pid, SIGKILL);
				sysupgrade_pid = 0;
			} else {
				/* don't accept the changes */
				error = SR_ERR_INTERNAL;
				goto out;
			}
		}

		if (software_changed) {
			signal(SIGUSR1, sigusr1_handler);

			sysupgrade_pid = fork();
			if (sysupgrade_pid < 0) {
				SRP_LOG_ERRMSG("firmware_module_change_cb: unable to fork");
				error = SR_ERR_INTERNAL;
				goto out;
			}

			if (sysupgrade_pid == 0) {
				/* continuously attempt to install firmware */
				while (true) {
					error = run_firmware_install_steps(ctx);
					if (error == SR_ERR_OK) {
						SRP_LOG_INFMSG("firmware_module_change_cb: update successful");
						break;
					} else {
						SRP_LOG_ERRMSG("firmware_module_change_cb error: unable to install firmware");
						exit(EXIT_FAILURE);
					}
				}

				SRP_LOG_INFMSG("firmware_module_change_cb: update process exit");
				exit(EXIT_SUCCESS);
			}
		}
	}

out:
	sr_free_change_iter(firmware_change_iter);

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int firmware_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	int error = SRPO_UBUS_ERR_OK;
	srpo_ubus_result_values_t *values = NULL;
	srpo_ubus_call_data_t ubus_call_data = {.lookup_path = NULL, .method = NULL, .transform_data_cb = NULL, .timeout = 0, .json_call_arguments = NULL};

	ubus_call_data.lookup_path = "router.system";
	ubus_call_data.method = "info";

	if (strcmp(path, VERSION_YANG_STATE_PATH) == 0) {
		ubus_call_data.transform_data_cb = firmware_ubus_version;
	} else if (strcmp(path, SERIAL_YANG_STATE_PATH) == 0) {
		ubus_call_data.transform_data_cb = firmware_ubus_serial;
	} else {
		SRP_LOG_ERR("firmware_state_data_cb: invalid path %s", path);
		goto out;
	}

	srpo_ubus_init_result_values(&values);

	error = srpo_ubus_call(values, &ubus_call_data);
	if (error != SRPO_UBUS_ERR_OK) {
		SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
		goto out;
	}

	error = store_ubus_values_to_datastore(session, request_xpath, values, parent);
	// TODO fix error handling here
	if (error) {
		SRP_LOG_ERR("store_ubus_values_to_datastore error (%d)", error);
		goto out;
	}

out:
	if (values) {
		srpo_ubus_free_result_values(values);
	}

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int firmware_state_software_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	int error = SR_ERR_OK;
	plugin_ctx_t *ctx = (plugin_ctx_t *) private_data;
	char *xpath_list = NULL;
	char *xpath = NULL;

	size_t inst_size = ctx->installing_software.uri ? strlen(ctx->installing_software.uri) : 0;
	size_t runn_size = ctx->running_software.uri ? strlen(ctx->running_software.uri) : 0;
	size_t uri_size = inst_size > runn_size ? inst_size : runn_size;
	size_t xpath_len = uri_size + 100;

	xpath_list = (char *) xmalloc(sizeof(char) * xpath_len);
	xpath = (char *) xmalloc(sizeof(char) * xpath_len);

	if (ctx->installing_software.uri != NULL) {
		snprintf(xpath_list, xpath_len, "%s[source='%s']", SOFTWARE_XPATH, ctx->installing_software.uri);

		if (ctx->installing_software.version) {
			snprintf(xpath, xpath_len, "%s/%s", xpath_list, "version");

			error = sr_set_item_str(session, xpath, (char *) ctx->installing_software.version, NULL, SR_EDIT_DEFAULT);
			if (error) {
				SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
				goto cleanup;
			}
		}

		if (ctx->installing_software.status && strlen(ctx->installing_software.status) > 0) {
			snprintf(xpath, xpath_len, "%s/%s", xpath_list, "status");

			error = sr_set_item_str(session, xpath, (char *) ctx->installing_software.status, NULL, SR_EDIT_DEFAULT);
			if (error) {
				SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
				goto cleanup;
			}
		}

		if (ctx->installing_software.message && strlen(ctx->installing_software.message) > 0) {
			snprintf(xpath, xpath_len, "%s/%s", xpath_list, "message");

			error = sr_set_item_str(session, xpath, (char *) ctx->installing_software.message, NULL, SR_EDIT_DEFAULT);
			if (error) {
				SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
				goto cleanup;
			}
		}
	}

	if (ctx->running_software.uri != NULL) {
		snprintf(xpath_list, xpath_len, "%s[source='%s']", SOFTWARE_XPATH, ctx->running_software.uri);

		if (ctx->running_software.version) {
			snprintf(xpath, xpath_len, "%s/%s", xpath_list, "version");

			error = sr_set_item_str(session, xpath, (char *) ctx->running_software.version, NULL, SR_EDIT_DEFAULT);
			if (error) {
				SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
				goto cleanup;
			}
		}

		if (ctx->running_software.status && strlen(ctx->running_software.status) > 0) {
			snprintf(xpath, xpath_len, "%s/%s", xpath_list, "status");

			error = sr_set_item_str(session, xpath, (char *) ctx->running_software.status, NULL, SR_EDIT_DEFAULT);
			if (error) {
				SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
				goto cleanup;
			}
		}

		if (ctx->running_software.message && strlen(ctx->running_software.message) > 0) {
			snprintf(xpath, xpath_len, "%s/%s", xpath_list, "message");

			error = sr_set_item_str(session, xpath, (char *) ctx->running_software.message, NULL, SR_EDIT_DEFAULT);
			if (error) {
				SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
				goto cleanup;
			}
		}
	}

	error = sr_apply_changes(session, 0, 0);
	if (error) {
		SRP_LOG_ERR("sr_apply_changes error (%d): %s", error, sr_strerror(error));
		goto cleanup;
	}

cleanup:
	FREE_SAFE(xpath);
	FREE_SAFE(xpath_list);

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int firmware_state_running_cb(sr_session_ctx_t *session, const char *module_name,
									 const char *path, const char *request_xpath, uint32_t request_id,
									 struct lyd_node **parent, void *private_data)
{
	int error = SR_ERR_OK;
	plugin_ctx_t *ctx = (plugin_ctx_t *) private_data;

	if (ctx->running_software.uri == NULL ||
		ctx->running_software.status == NULL ||
		strcmp(ctx->running_software.status, "installed") != 0) {
		goto cleanup;
	}

	error = sr_set_item_str(session, RUNNING_XPATH, (char *) ctx->running_software.uri, NULL, SR_EDIT_DEFAULT);
	if (error) {
		SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
		goto cleanup;
	}

	error = sr_apply_changes(session, 0, 0);
	if (error) {
		SRP_LOG_ERR("sr_apply_changes error (%d): %s", error, sr_strerror(error));
		goto cleanup;
	}

cleanup:
	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int firmware_rpc_cb(sr_session_ctx_t *session, const char *op_path, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int error = 0;
	srpo_ubus_call_data_t ubus_call_data = {.lookup_path = NULL, .method = NULL, .transform_data_cb = NULL, .timeout = 0, .json_call_arguments = NULL};

	signal(SIGUSR1, sigusr1_handler);

	restart_pid = fork();
	if (restart_pid < 0) {
		SRP_LOG_ERRMSG("firmware_rpc_cb: unable to fork");
		return SR_ERR_CALLBACK_FAILED;
	}

	if (restart_pid == 0) {
		sleep(3);

		ubus_call_data.lookup_path = "juci.system";

		if (strcmp(op_path, RESTART_YANG_PATH) == 0) {
			ubus_call_data.method = "reboot";
		} else if (strcmp(op_path, RESET_YANG_PATH) == 0) {
			ubus_call_data.method = "defaultreset";
		} else {
			SRP_LOG_ERR("firmware_rpc_cb: invalid path %s", op_path);
			exit(EXIT_FAILURE);
		}

		error = srpo_ubus_call(NULL, &ubus_call_data);
		if (error != SRPO_UBUS_ERR_OK) {
			SRP_LOG_ERR("srpo_ubus_call error (%d): %s", error, srpo_ubus_error_description_get(error));
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	} else {
		SRP_LOG_DBG("firmware_rpc_cb: child in %d", restart_pid);
	}

	return SR_ERR_OK;
}

static void clean_configuration_data(firmware_t *firmware)
{
	SET_STR(firmware->credentials.value, NULL);
	SET_STR(firmware->checksum.value, NULL);
	SET_STR(firmware->source.uri, NULL);
}

static void init_operational_data(oper_t *operational)
{
	SET_STR(operational->version, NULL);
	SET_STR(operational->uri, NULL);

	operational->status = mmap(NULL, 12, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
	operational->message = mmap(NULL, 120, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
}

static void clean_operational_data(oper_t *operational)
{
	SET_STR(operational->version, NULL);
	SET_STR(operational->uri, NULL);
}

static void default_download_policy(struct download_policy *policy)
{
	policy->download_attempts = 0;
	policy->retry_interval = 600;
	policy->retry_randomness = 300;
}

static int update_firmware_context_value(plugin_ctx_t *ctx, const struct lyd_node *node)
{
	int error = SR_ERR_OK;
	struct lyd_node_leaf_list *node_list = NULL;
	const char *node_name = NULL;
	const char *node_value = NULL;

	node_name = node->schema->name;
	if (node->schema->nodetype != LYS_LEAF && node->schema->nodetype != LYS_LEAFLIST)
		return SR_ERR_OK;

	node_list = (struct lyd_node_leaf_list *) node;

	if (strncmp(node_name, "source", strlen(node_name)) == 0 &&
		node_list->value_type == LY_TYPE_STRING) {
		SET_STR(ctx->firmware.source.uri, node_list->value_str);
		SET_STR(ctx->installing_software.uri, ctx->firmware.source.uri);

	} else if (strncmp(node_name, "password", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_STRING) {
		ctx->firmware.credentials.type = CRED_PASSWD;
		SET_STR(ctx->firmware.credentials.value, node_list->value_str);

	} else if (strncmp(node_name, "certificate", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_STRING) {
		ctx->firmware.credentials.type = CRED_CERT;
		SET_STR(ctx->firmware.credentials.value, node_list->value_str);

	} else if (strncmp(node_name, "ssh-key", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_STRING) {
		ctx->firmware.credentials.type = CRED_SSH_KEY;
		SET_STR(ctx->firmware.credentials.value, node_list->value_str);

	} else if (strncmp(node_name, "preserve-configuration", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_BOOL) {
		ctx->firmware.preserve_configuration =
			(strcmp(node_list->value_str, "true") == 0) ? true : false;

	} else if (strncmp(node_name, "type", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_ENUM) {
		node_value = node_list->value_str;

		if (strcmp("md5", node_value) == 0) {
			ctx->firmware.checksum.type = CKSUM_MD5;

		} else if (strcmp("sha-1", node_value) == 0) {
			ctx->firmware.checksum.type = CKSUM_SHA1;

		} else if (strcmp("sha-2", node_value) == 0) {
			ctx->firmware.checksum.type = CKSUM_SHA2;

		} else if (strcmp("sha-3", node_value) == 0) {
			ctx->firmware.checksum.type = CKSUM_SHA3;

		} else if (strcmp("sha-256", node_value) == 0) {
			ctx->firmware.checksum.type = CKSUM_SHA256;

		} else {
			error = SR_ERR_VALIDATION_FAILED;
			goto cleanup;
		}
	} else if (strncmp(node_name, "value", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_STRING) {
		SET_STR(ctx->firmware.checksum.value, node_list->value_str);

	} else if (strncmp(node_name, "download-attempts", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_UINT32) {
		ctx->firmware.policy.download_attempts = node_list->value.uint32;

	} else if (strncmp(node_name, "retry-interval", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_UINT32) {
		ctx->firmware.policy.retry_interval = node_list->value.uint32;

	} else if (strncmp(node_name, "retry-randomness", strlen(node_name)) == 0 &&
			   node_list->value_type == LY_TYPE_UINT32) {
		ctx->firmware.policy.retry_randomness = node_list->value.uint32;
	}

cleanup:

	return error;
}

static void firmware_ubus_version(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	json_object *result = NULL;
	json_object *system = NULL;
	json_object *firmware = NULL;
	const char *string = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);
	json_object_object_get_ex(result, "system", &system);
	json_object_object_get_ex(system, "firmware", &firmware);
	string = json_object_get_string(firmware);

	error = srpo_ubus_result_values_add(values, string, strlen(string),
										VERSION_YANG_STATE_PATH, strlen(VERSION_YANG_STATE_PATH),
										" ", strlen(" "));
	if (error != SRPO_UBUS_ERR_OK) {
		goto cleanup;
	}

cleanup:
	json_object_put(result);

	return;
}

static void firmware_ubus_serial(const char *ubus_json, srpo_ubus_result_values_t *values)
{
	json_object *result = NULL;
	json_object *system = NULL;
	json_object *firmware = NULL;
	const char *string = NULL;
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;

	result = json_tokener_parse(ubus_json);
	json_object_object_get_ex(result, "system", &system);
	json_object_object_get_ex(system, "serialno", &firmware);
	string = json_object_get_string(firmware);

	error = srpo_ubus_result_values_add(values, string, strlen(string),
										SERIAL_YANG_STATE_PATH, strlen(SERIAL_YANG_STATE_PATH),
										" ", strlen(" "));
	if (error != SRPO_UBUS_ERR_OK) {
		goto cleanup;
	}

cleanup:
	json_object_put(result);
	return;
}

static int can_restart(plugin_ctx_t *ctx)
{
	if (access("/var/sysupgrade.lock", F_OK) != -1)
		return false;

	if (strcmp(ctx->installing_software.status, "upgrade-in-progress") == 0)
		return false;

	if (strcmp(ctx->installing_software.status, "upgrade-done") == 0)
		return false;

	return true;
}

static int run_firmware_install_steps(plugin_ctx_t *ctx)
{
	int error = SR_ERR_OK;
	char *sysupgrade_lock_file = "/var/sysupgrade.lock";

	SRP_LOG_INFMSG("install_firmware: starting download");
	SET_MEM_STR(ctx->installing_software.status, "dl-planned");

	error = download_firmware(ctx);
	if (error != SR_ERR_OK) {
		SRP_LOG_INFMSG("install_firmware error: failed to download firmware");
		goto cleanup;
	}

	SRP_LOG_INFMSG("install_firmware: download complete");
	SET_MEM_STR(ctx->installing_software.status, "dlownload-done");

	SRP_LOG_INFMSG("install_firmware: starting upgrade");
	SET_MEM_STR(ctx->installing_software.status, "upgrade-in-progress");

	error = install_firmware(ctx);
	if (error != SR_ERR_OK) {
		SRP_LOG_INFMSG("install_firmware error: failed to install firmware");
		goto cleanup;
	}

	if (error == SR_ERR_INTERNAL) {
		if (access(sysupgrade_lock_file, F_OK) != -1) {
			remove(sysupgrade_lock_file);
		}
	}

cleanup:
	return error;
}

static int load_startup_datastore(plugin_ctx_t *ctx)
{
	int error = SR_ERR_OK;
	struct lyd_node *root = NULL;
	struct lyd_node *child = NULL;
	struct lyd_node *next = NULL;
	struct lyd_node *node = NULL;

	if (!can_restart(ctx)) {
		SRP_LOG_INFMSG("load_startup_datastore: cannot run new upgrade process");
		return SR_ERR_OK;
	}

	error = sr_get_data(ctx->startup_session, SOFTWARE_YANG_PATH "//*", 0, 0, SR_OPER_DEFAULT, &root);
	if (error == SR_ERR_NOT_FOUND) {
		SRP_LOG_INFMSG("load_startup_datastore: empty startup datastore");
		return SR_ERR_OK;
	} else if (error != SR_ERR_OK) {
		goto cleanup;
	}

	if (!root)
		goto cleanup;

	LY_TREE_FOR(root->child, child)
	{
		LY_TREE_DFS_BEGIN(child, next, node)
		{
			update_firmware_context_value(ctx, node);
			LY_TREE_DFS_END(child, next, node)
		};
	}

cleanup:
	lyd_free(node);
	lyd_free(next);
	lyd_free(child);
	lyd_free(root);

	return error;
}

static int store_ubus_values_to_datastore(sr_session_ctx_t *session, const char *request_xpath, srpo_ubus_result_values_t *values, struct lyd_node **parent)
{
	const struct ly_ctx *ly_ctx = NULL;
	if (*parent == NULL) {
		ly_ctx = sr_get_context(sr_session_get_connection(session));
		if (ly_ctx == NULL) {
			return -1;
		}
		*parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
	}

	for (size_t i = 0; i < values->num_values; i++) {
		lyd_new_path(*parent, NULL, values->values[i].xpath, values->values[i].value, 0, 0);
	}

	return 0;
}

static void sigusr1_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("SIGUSR1 called, killing children...");

	kill(sysupgrade_pid, SIGKILL);
	sysupgrade_pid = 0;

	kill(restart_pid, SIGKILL);
	restart_pid = 0;
}

#ifndef PLUGIN
#include <signal.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

int main()
{
	int error = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_data = NULL;

	sr_log_stderr(SR_LL_DBG);

	/* connect to sysrepo */
	error = sr_connect(SR_CONN_DEFAULT, &connection);
	if (error) {
		SRP_LOG_ERR("sr_connect error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sr_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("sr_plugin_init_cb error");
		goto out;
	}

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);
	}

out:
	sr_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
