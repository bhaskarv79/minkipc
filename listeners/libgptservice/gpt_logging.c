// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * GPT Logging Implementation - Production-Ready Syslog-based Logging
 */

#define _GNU_SOURCE  /* For vsyslog */

#include <stdarg.h>
#include <string.h>
#include <stdbool.h>

#include "gpt_logging.h"

/* Global log level - defaults to INFO for production */
gpt_log_level_t g_gpt_log_level = GPT_LOG_LEVEL_INFO;

/* Logging state */
static bool g_log_initialized = false;

void gpt_log_init(const char *ident)
{
    if (g_log_initialized) {
        return;
    }

    /* Initialize syslog */
    openlog(ident ? ident : "gpt_service", LOG_PID | LOG_CONS, LOG_DAEMON);

    g_log_initialized = true;

    /* Log initialization message */
    syslog(LOG_INFO, "GPT logging initialized");
}

void gpt_log_cleanup(void)
{
    if (!g_log_initialized) {
        return;
    }

    syslog(LOG_INFO, "GPT logging cleanup");
    closelog();
    g_log_initialized = false;
}

void gpt_log(gpt_log_level_t level, const char *format, ...)
{
    va_list args;

    /* Check if we should log this level */
    if (level > g_gpt_log_level) {
        return;
    }

    /* Initialize logging if not done yet */
    if (!g_log_initialized) {
        gpt_log_init(NULL);
    }

    /* Log to syslog */
    va_start(args, format);
    vsyslog(level, format, args);
    va_end(args);
}

void gpt_set_log_level(gpt_log_level_t level)
{
    /* Validate log level */
    if (level != LOG_ERR && level != LOG_WARNING &&
        level != LOG_INFO && level != LOG_DEBUG) {
        return;
    }

    g_gpt_log_level = level;

    /* Set syslog mask to filter messages */
    setlogmask(LOG_UPTO(level));

    syslog(LOG_INFO, "GPT log level set to: %d", level);
}

gpt_log_level_t gpt_get_log_level(void)
{
    return g_gpt_log_level;
}
