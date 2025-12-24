// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * GPT Logging Interface - Production-Ready Syslog-based Logging
 */

#ifndef __GPT_LOGGING_H__
#define __GPT_LOGGING_H__

#include <syslog.h>

/* Log levels mapped to syslog priorities */
typedef enum {
    GPT_LOG_LEVEL_ERROR = LOG_ERR,      /* 3 - Error conditions */
    GPT_LOG_LEVEL_WARN  = LOG_WARNING,  /* 4 - Warning conditions */
    GPT_LOG_LEVEL_INFO  = LOG_INFO,     /* 6 - Informational messages */
    GPT_LOG_LEVEL_DEBUG = LOG_DEBUG     /* 7 - Debug-level messages */
} gpt_log_level_t;

/* Current log level (can be configured) */
extern gpt_log_level_t g_gpt_log_level;

/* Core logging macros */
#define GPT_LOG_ERROR(fmt, ...) \
    gpt_log(GPT_LOG_LEVEL_ERROR, "GPT_ERROR: " fmt, ##__VA_ARGS__)

#define GPT_LOG_WARN(fmt, ...) \
    gpt_log(GPT_LOG_LEVEL_WARN, "GPT_WARN: " fmt, ##__VA_ARGS__)

#define GPT_LOG_INFO(fmt, ...) \
    gpt_log(GPT_LOG_LEVEL_INFO, "GPT_INFO: " fmt, ##__VA_ARGS__)

#define GPT_LOG_DEBUG(fmt, ...) \
    gpt_log(GPT_LOG_LEVEL_DEBUG, "GPT_DEBUG: " fmt, ##__VA_ARGS__)

/**
 * Initialize logging subsystem
 * @param ident: Program identification for syslog
 */
void gpt_log_init(const char *ident);

/**
 * Cleanup logging subsystem
 */
void gpt_log_cleanup(void);

/**
 * Core logging function - uses syslog
 * @param level: Log level (syslog priority)
 * @param format: Printf-style format string
 * @param ...: Format arguments
 */
void gpt_log(gpt_log_level_t level, const char *format, ...);

/**
 * Set log level
 * @param level: New log level
 */
void gpt_set_log_level(gpt_log_level_t level);

/**
 * Get current log level
 * @return: Current log level
 */
gpt_log_level_t gpt_get_log_level(void);

#endif /* __GPT_LOGGING_H__ */
