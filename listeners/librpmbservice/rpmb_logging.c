// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "rpmb_logging.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

static rpmb_log_level_t rpmb_log_level = RPMB_LOG_LEVEL_INFO;
static int rpmb_log_to_console = 0;

void rpmb_log_init(const char *ident)
{
	// Don't call openlog() - let qtee_supplicant handle it
	// Just initialize our local state
	(void)ident; // Unused when running as shared library
	
	// Check environment for console logging
	const char *console_env = getenv("RPMB_LOG_CONSOLE");
	if (console_env && strcmp(console_env, "1") == 0) {
		rpmb_log_to_console = 1;
	}
	
	// Check environment for log level
	const char *level_env = getenv("RPMB_LOG_LEVEL");
	if (level_env) {
		int level = atoi(level_env);
		if (level >= RPMB_LOG_LEVEL_ERROR && level <= RPMB_LOG_LEVEL_DEBUG) {
			rpmb_log_level = level;
		}
	}
}

void rpmb_log(rpmb_log_level_t level, const char *format, ...)
{
	if (level > rpmb_log_level)
		return;

	va_list args;
	char msg[512];
	char full_msg[600];
	
	va_start(args, format);
	vsnprintf(msg, sizeof(msg), format, args);
	va_end(args);

	// Prefix with service name for identification
	snprintf(full_msg, sizeof(full_msg), "[RPMB] %s", msg);

	if (rpmb_log_to_console) {
		fprintf(stderr, "%s\n", full_msg);
	}

	// Map our log levels to syslog priorities
	int syslog_priority;
	switch (level) {
	case RPMB_LOG_LEVEL_ERROR:
		syslog_priority = LOG_ERR;
		break;
	case RPMB_LOG_LEVEL_INFO:
		syslog_priority = LOG_INFO;
		break;
	case RPMB_LOG_LEVEL_DEBUG:
		syslog_priority = LOG_DEBUG;
		break;
	default:
		syslog_priority = LOG_INFO;
	}

	syslog(syslog_priority, "%s", full_msg);
}

void rpmb_log_message(int level, const char *file, int line, const char *func,
		      const char *fmt, ...)
{
	if (level > (int)rpmb_log_level)
		return;

	va_list args;
	char msg[512];
	char full_msg[600];
	
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	// Prefix with service name for identification
	snprintf(full_msg, sizeof(full_msg), "[RPMB] %s:%d %s: %s",
		 file, line, func, msg);

	if (rpmb_log_to_console) {
		fprintf(stderr, "%s\n", full_msg);
	}

	// Map our log levels to syslog priorities
	int syslog_priority;
	switch (level) {
	case RPMB_LOG_LEVEL_ERROR:
		syslog_priority = LOG_ERR;
		break;
	case RPMB_LOG_LEVEL_INFO:
		syslog_priority = LOG_INFO;
		break;
	case RPMB_LOG_LEVEL_DEBUG:
		syslog_priority = LOG_DEBUG;
		break;
	default:
		syslog_priority = LOG_INFO;
	}

	syslog(syslog_priority, "%s", full_msg);
}

void rpmb_set_log_level(rpmb_log_level_t level)
{
	rpmb_log_level = level;
}

rpmb_log_level_t rpmb_get_log_level(void)
{
	return rpmb_log_level;
}

void rpmb_log_cleanup(void)
{
	// Nothing to cleanup when not calling openlog()
}
