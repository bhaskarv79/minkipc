// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * RPMB Core Implementation - Clean, Platform-Independent
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rpmb_core.h"
#include "rpmb_logging.h"

/* Global RPMB context */
static rpmb_context_t g_rpmb_context = {0};

/* Device operations table */
static const rpmb_device_ops_t *g_device_ops = NULL;

/* Forward declarations for device-specific operations */
extern const rpmb_device_ops_t rpmb_ufs_ops;
extern const rpmb_device_ops_t rpmb_emmc_ops;

/* Device operations lookup table */
static const struct {
	rpmb_device_type_t device_type;
	const rpmb_device_ops_t *ops;
} device_ops_table[] = {
	{ RPMB_DEVICE_UFS,  &rpmb_ufs_ops },
	{ RPMB_DEVICE_EMMC, &rpmb_emmc_ops },
};

/* Wakelock management */
static struct {
	int lock_fd;
	int unlock_fd;
	bool initialized;
} wakelock_ctx = { -1, -1, false };

#define WAKELOCK_PATH       "/sys/power/wake_lock"
#define WAKEUNLOCK_PATH     "/sys/power/wake_unlock"
#define WAKELOCK_NAME       "rpmb_access"

/* Utility function implementations */
const char *rpmb_device_type_to_string(rpmb_device_type_t device_type)
{
	switch (device_type) {
		case RPMB_DEVICE_NONE: return "NONE";
		case RPMB_DEVICE_EMMC: return "eMMC";
		case RPMB_DEVICE_UFS:  return "UFS";
		default: return "UNKNOWN";
	}
}

const char *rpmb_result_to_string(rpmb_result_t result)
{
	switch (result) {
		case RPMB_RESULT_OK: return "OK";
		case RPMB_RESULT_GENERAL_FAILURE: return "General Failure";
		case RPMB_RESULT_AUTH_FAILURE: return "Authentication Failure";
		case RPMB_RESULT_COUNTER_FAILURE: return "Counter Failure";
		case RPMB_RESULT_ADDRESS_FAILURE: return "Address Failure";
		case RPMB_RESULT_WRITE_FAILURE: return "Write Failure";
		case RPMB_RESULT_READ_FAILURE: return "Read Failure";
		case RPMB_RESULT_KEY_NOT_PROGRAMMED: return "Key Not Programmed";
		case RPMB_RESULT_INVALID_DEVICE: return "Invalid Device";
		case RPMB_RESULT_NOT_INITIALIZED: return "Not Initialized";
		case RPMB_RESULT_INVALID_PARAMETER: return "Invalid Parameter";
		default: return "Unknown Error";
	}
}

/* Wakelock management functions */
static rpmb_result_t wakelock_init(void)
{
	if (wakelock_ctx.initialized) {
		return RPMB_RESULT_OK;
	}

	wakelock_ctx.lock_fd = open(WAKELOCK_PATH, O_WRONLY | O_APPEND);
	if (wakelock_ctx.lock_fd < 0) {
		RPMB_LOG_WARN("Failed to open wakelock file: %s", strerror(errno));
		return RPMB_RESULT_GENERAL_FAILURE;
	}

	wakelock_ctx.unlock_fd = open(WAKEUNLOCK_PATH, O_WRONLY | O_APPEND);
	if (wakelock_ctx.unlock_fd < 0) {
		RPMB_LOG_WARN("Failed to open wakeunlock file: %s", strerror(errno));
		close(wakelock_ctx.lock_fd);
		wakelock_ctx.lock_fd = -1;
		return RPMB_RESULT_GENERAL_FAILURE;
	}

	wakelock_ctx.initialized = true;
	RPMB_LOG_DEBUG("Wakelock initialized successfully");
	return RPMB_RESULT_OK;
}

static void wakelock_cleanup(void)
{
	if (wakelock_ctx.lock_fd >= 0) {
		close(wakelock_ctx.lock_fd);
		wakelock_ctx.lock_fd = -1;
	}

	if (wakelock_ctx.unlock_fd >= 0) {
		close(wakelock_ctx.unlock_fd);
		wakelock_ctx.unlock_fd = -1;
	}

	wakelock_ctx.initialized = false;
}

static void wakelock_acquire(void)
{
	if (!wakelock_ctx.initialized || wakelock_ctx.lock_fd < 0) {
		return;
	}

	ssize_t ret = write(wakelock_ctx.lock_fd, WAKELOCK_NAME, strlen(WAKELOCK_NAME));
	if (ret != (ssize_t)strlen(WAKELOCK_NAME)) {
		RPMB_LOG_WARN("Failed to acquire wakelock: %s", strerror(errno));
	}
}

static void wakelock_release(void)
{
	if (!wakelock_ctx.initialized || wakelock_ctx.unlock_fd < 0) {
		return;
	}

	ssize_t ret = write(wakelock_ctx.unlock_fd, WAKELOCK_NAME, strlen(WAKELOCK_NAME));
	if (ret != (ssize_t)strlen(WAKELOCK_NAME)) {
		RPMB_LOG_WARN("Failed to release wakelock: %s", strerror(errno));
	}
}

/* Device operations lookup */
static const rpmb_device_ops_t *get_device_ops(rpmb_device_type_t device_type)
{
	for (size_t i = 0; i < sizeof(device_ops_table) / sizeof(device_ops_table[0]); i++) {
		if (device_ops_table[i].device_type == device_type) {
			return device_ops_table[i].ops;
		}
	}
	return NULL;
}

/* Core API implementations */
rpmb_result_t rpmb_core_init(rpmb_device_info_t *info)
{
	rpmb_result_t result;

	if (!info) {
		return RPMB_RESULT_INVALID_PARAMETER;
	}

	/* Check if already initialized */
	if (g_rpmb_context.device_info.initialized) {
		*info = g_rpmb_context.device_info;
		return RPMB_RESULT_OK;
	}

	/* Initialize logging first */
	rpmb_log_init("rpmb_service");

	RPMB_LOG_DEBUG("Initializing RPMB core");

	/* Initialize wakelock */
	result = wakelock_init();
	if (result != RPMB_RESULT_OK) {
		RPMB_LOG_WARN("Wakelock initialization failed, continuing without wakelock");
	}
	g_rpmb_context.wakelock_initialized = (result == RPMB_RESULT_OK);

	/* Detect RPMB device */
	rpmb_device_type_t device_type = rpmb_detect_device();
	if (device_type == RPMB_DEVICE_NONE) {
		RPMB_LOG_ERROR("No RPMB device detected");
		wakelock_cleanup();
		return RPMB_RESULT_INVALID_DEVICE;
	}

	RPMB_LOG_DEBUG("Detected RPMB device: %s", rpmb_device_type_to_string(device_type));

	/* Get device operations */
	g_device_ops = get_device_ops(device_type);
	if (!g_device_ops) {
		RPMB_LOG_ERROR("No operations available for device type: %s",
				rpmb_device_type_to_string(device_type));
		wakelock_cleanup();
		return RPMB_RESULT_INVALID_DEVICE;
	}

	/* Initialize device */
	result = g_device_ops->init(&g_rpmb_context.device_info);
	if (result != RPMB_RESULT_OK) {
		RPMB_LOG_ERROR("Device initialization failed: %s", rpmb_result_to_string(result));
		wakelock_cleanup();
		return result;
	}

	g_rpmb_context.device_info.initialized = true;
	*info = g_rpmb_context.device_info;

	RPMB_LOG_DEBUG("RPMB core initialized successfully - Device: %s, Size: %u sectors, RWC: %u",
			rpmb_device_type_to_string(g_rpmb_context.device_info.device_type),
			g_rpmb_context.device_info.size_sectors,
			g_rpmb_context.device_info.reliable_write_count);

	return RPMB_RESULT_OK;
}

void rpmb_core_cleanup(void)
{
	if (!g_rpmb_context.device_info.initialized) {
		return;
	}

	RPMB_LOG_DEBUG("Cleaning up RPMB core");

	if (g_device_ops && g_device_ops->cleanup) {
		g_device_ops->cleanup();
	}

	wakelock_cleanup();

	memset(&g_rpmb_context, 0, sizeof(g_rpmb_context));
	g_device_ops = NULL;

	RPMB_LOG_DEBUG("RPMB core cleanup completed");

	/* Cleanup logging last */
	rpmb_log_cleanup();
}

rpmb_result_t rpmb_core_read(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len)
{
	if (!request_buf || !response_buf || !response_len || block_count == 0) {
		return RPMB_RESULT_INVALID_PARAMETER;
	}

	if (!g_rpmb_context.device_info.initialized || !g_device_ops) {
		return RPMB_RESULT_NOT_INITIALIZED;
	}

	RPMB_LOG_DEBUG("RPMB read: blocks=%u", block_count);

	wakelock_acquire();
	rpmb_result_t result = g_device_ops->read(request_buf, block_count,
			response_buf, response_len);
	wakelock_release();

	RPMB_LOG_DEBUG("RPMB read result: %s, response_len=%u",
			rpmb_result_to_string(result), *response_len);

	return result;
}

rpmb_result_t rpmb_core_write(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len,
		uint32_t frames_per_operation)
{
	if (!request_buf || !response_buf || !response_len ||
			block_count == 0 || frames_per_operation == 0) {
		return RPMB_RESULT_INVALID_PARAMETER;
	}

	if (!g_rpmb_context.device_info.initialized || !g_device_ops) {
		return RPMB_RESULT_NOT_INITIALIZED;
	}

	RPMB_LOG_DEBUG("RPMB write: blocks=%u, frames_per_op=%u",
			block_count, frames_per_operation);

	wakelock_acquire();
	rpmb_result_t result = g_device_ops->write(request_buf, block_count,
			response_buf, response_len,
			frames_per_operation);
	wakelock_release();

	RPMB_LOG_DEBUG("RPMB write result: %s, response_len=%u",
			rpmb_result_to_string(result), *response_len);

	return result;
}

rpmb_result_t rpmb_core_get_device_info(rpmb_device_info_t *info)
{
	if (!info) {
		return RPMB_RESULT_INVALID_PARAMETER;
	}

	if (!g_rpmb_context.device_info.initialized) {
		return RPMB_RESULT_NOT_INITIALIZED;
	}

	*info = g_rpmb_context.device_info;
	return RPMB_RESULT_OK;
}
