/**
 * @file snabb.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for macros.
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

#ifndef __COMMON_H__
#define __COMMON_H__

#define XPATH_MAX_LEN 100

#define ARR_SIZE(a) sizeof a / sizeof a[0]

#ifdef PLUGIN
#define ENABLE_LOGGING(LOG_LEVEL) sr_log_syslog((LOG_LEVEL))
#else
#define ENABLE_LOGGING(LOG_LEVEL) sr_log_stderr((LOG_LEVEL))
#endif

#define ERR(MSG, ...) SRP_LOG_ERR(MSG, __VA_ARGS__)
#define ERR_MSG(MSG) SRP_LOG_ERRMSG(MSG)
#define WRN(MSG, ...) SRP_LOG_WRN(MSG, __VA_ARGS__)
#define WRN_MSG(MSG) SRP_LOG_WRNMSG(MSG)
#define INF(MSG, ...) SRP_LOG_INF(MSG, __VA_ARGS__)
#define INF_MSG(MSG) SRP_LOG_INFMSG(MSG)
#define DBG(MSG, ...) SRP_LOG_DBG(MSG, __VA_ARGS__)
#define DBG_MSG(MSG) SRP_LOG_DBGMSG(MSG)

#define CHECK_RET_MSG(RET, LABEL, MSG)                                         \
  do {                                                                         \
    if (SR_ERR_OK != RET) {                                                    \
      ERR_MSG(MSG);                                                            \
      goto LABEL;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_RET(RET, LABEL, MSG, ...)                                        \
  do {                                                                         \
    if (SR_ERR_OK != RET) {                                                    \
      ERR(MSG, __VA_ARGS__);                                                   \
      goto LABEL;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_NULL_MSG(VALUE, RET, LABEL, MSG)                                 \
  do {                                                                         \
    if (NULL == VALUE) {                                                       \
      *RET = SR_ERR_INTERNAL;                                                  \
      ERR_MSG(MSG);                                                            \
      goto LABEL;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_NULL(VALUE, RET, LABEL, MSG, ...)                                \
  do {                                                                         \
    if (NULL == VALUE) {                                                       \
      *RET = SR_ERR_INTERNAL;                                                  \
      ERR(MSG, __VA_ARGS__);                                                   \
      goto LABEL;                                                              \
    }                                                                          \
  } while (0)

#define UCI_CHECK_RET_MSG(UCI_RET, SR_RET, LABEL, MSG)                         \
  do {                                                                         \
    if (UCI_OK != UCI_RET) {                                                   \
      ERR_MSG(MSG)                                                             \
      *SR_RET = SR_ERR_INTERNAL;                                               \
      goto LABEL;                                                              \
    }                                                                          \
  } while (0)

#define UCI_CHECK_RET(UCI_RET, SR_RET, LABEL, MSG, ...)                        \
  do {                                                                         \
    if (UCI_OK != UCI_RET) {                                                   \
      ERR(MSG, __VA_ARGS__);                                                   \
      *SR_RET = SR_ERR_INTERNAL;                                               \
      goto LABEL;                                                              \
    }                                                                          \
  } while (0)

#define SET_STR(VAR, DATA)                                                     \
  do {                                                                         \
    if (VAR != NULL) {                                                         \
      free(VAR);                                                               \
    }                                                                          \
    if (DATA != NULL) {                                                        \
      VAR = strdup(DATA ? DATA : "");                                          \
    } else {                                                                   \
      VAR = NULL;                                                              \
    }                                                                          \
  } while (0)

#define SET_MEM_STR(VAR, DATA)                                                 \
  do {                                                                         \
    if (DATA != NULL) {                                                        \
      memcpy(VAR, DATA, sizeof(DATA));                                         \
    }                                                                          \
  } while (0)

#endif /* __COMMON_H__ */
