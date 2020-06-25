#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include <srpo_uci.h>
#include <srpo_ubus.h>

#include "transform_data.h"
#include "utils/memory.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define BASE_YANG_MODEL     "ietf-system"
#define SOFTWARE_YANG_MODEL "terastream-software"

#define RESTART_YANG_PATH  "/ietf-system:system-restart"
#define SOFTWARE_YANG_PATH "/ietf-system:system/terastream-software:software"
#define RESET_YANG_PATH    "/terastream-software:system-reset-restart"

#define SOFTWARE_YANG_STATE_PATH "/ietf-system:system-state/" SOFTWARE_YANG_MODEL ":software"
#define RUNNING_YANG_STATE_PATH  "/ietf-system:system-state/" SOFTWARE_YANG_MODEL ":running-software"
#define VERSION_YANG_STATE_PATH  "/ietf-system:system-state/platform/" SOFTWARE_YANG_MODEL ":software-version"
#define SERIALNO_YANG_STATE_PATH "/ietf-system:system-state/platform/" SOFTWARE_YANG_MODEL ":serial-number"

static void sigusr1_handler(__attribute__((unused)) int signum);

int firmware_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void firmware_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int firmware_module_change_cb(sr_session_ctx_t *session, const char *module_name,
				     const char *xpath, sr_event_t event,
				     uint32_t request_id, void *private_data);
static int firmware_state_data_cb(sr_session_ctx_t *session, const char *module_name,
				  const char *path, const char *request_xpath,
				  uint32_t request_id, struct lyd_node **parent,
				  void *private_data);
static int firmware_rpc_cb(sr_session_ctx_t *session, const char *op_path,
			   const sr_val_t *input, const size_t input_cnt,
			   sr_event_t event, uint32_t request_id,
			   sr_val_t **output, size_t *output_cnt,
			   void *private_data);

pid_t sysupgrade_pid;
pid_t restart_pid;


int firmware_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	*private_data = NULL;

	error = srpo_uci_init();
	if (error) {
		SRP_LOG_ERR("srpo_uci_init error (%d): %s", error, srpo_uci_error_description_get(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	*private_data = startup_session;

	// if (!firmware_can_restart()) {
	// 	SRP_LOG_INFMSG("subscribing to module change");
	// 	goto error_out;
	// }

	SRP_LOG_INFMSG("subscribing to module change");

	error = sr_module_change_subscribe(session, BASE_YANG_MODEL, SOFTWARE_YANG_PATH,
					   firmware_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to get oper items");

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, SOFTWARE_YANG_STATE_PATH,
					    firmware_state_data_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, RUNNING_YANG_STATE_PATH,
					    firmware_state_data_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, VERSION_YANG_STATE_PATH,
					    firmware_state_data_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, SERIALNO_YANG_STATE_PATH,
					    firmware_state_data_cb, *private_data, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to rpc");

	error = sr_rpc_subscribe(session, RESTART_YANG_PATH,
				 firmware_rpc_cb, *private_data, 0, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_rpc_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	error = sr_rpc_subscribe(session, RESET_YANG_PATH,
				 firmware_rpc_cb, *private_data, 0, SR_SUBSCR_CTX_REUSE, &subscription);
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

void firmware_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	srpo_uci_cleanup();

	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;

	if (startup_session) {
		sr_session_stop(startup_session);
	}

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int firmware_module_change_cb(sr_session_ctx_t *session, const char *module_name,
				     const char *xpath, sr_event_t event,
				     uint32_t request_id, void *private_data)
{
	return SR_ERR_CALLBACK_FAILED;
}

static int firmware_state_data_cb(sr_session_ctx_t *session, const char *module_name,
				  const char *path, const char *request_xpath,
				  uint32_t request_id, struct lyd_node **parent,
				  void *private_data)
{
	return SR_ERR_CALLBACK_FAILED;
}

static int firmware_rpc_cb(sr_session_ctx_t *session, const char *op_path,
			   const sr_val_t *input, const size_t input_cnt,
			   sr_event_t event, uint32_t request_id,
			   sr_val_t **output, size_t *output_cnt,
			   void *private_data)
{
	int error = 0;
	srpo_ubus_call_data_t ubus_call_data = {
		.lookup_path = NULL, .method = NULL, .transform_data_cb = NULL,
		.timeout = 0, .json_call_arguments = NULL
	};

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

static void sigusr1_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("SIGUSR1 called, killing children...");
	kill(sysupgrade_pid, SIGKILL);
	kill(restart_pid, SIGKILL);
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

	error = firmware_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("firmware_plugin_init_cb error");
		goto out;
	}

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);
	}

out:
	firmware_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
