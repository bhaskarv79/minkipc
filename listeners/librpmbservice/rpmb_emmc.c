// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/*
 * RPMB eMMC Implementation
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/mmc/ioctl.h>
#include <dirent.h>

#include "rpmb_core.h"
#include "rpmb_logging.h"
#include "rpmb.h"

#define LOG_TAG "rpmb_emmc"

/* eMMC RPMB specific constants */
#define EMMC_RPMB_BLOCK_SIZE    512
#define EMMC_RPMB_FRAME_SIZE    512
#define EMMC_MAX_DEVICE_PATH    256

/* eMMC device context */
typedef struct {
	char device_path[EMMC_MAX_DEVICE_PATH];
	int fd;
	bool initialized;
} emmc_context_t;

static emmc_context_t g_emmc_ctx = {0};

/* Forward declarations */
static rpmb_result_t emmc_init_impl(rpmb_device_info_t *info);
static void emmc_cleanup_impl(void);
static rpmb_result_t emmc_read_impl(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len);
static rpmb_result_t emmc_write_impl(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len,
		uint32_t frames_per_operation);

/* eMMC device operations structure */
const rpmb_device_ops_t rpmb_emmc_ops = {
	.init = emmc_init_impl,
	.cleanup = emmc_cleanup_impl,
	.read = emmc_read_impl,
	.write = emmc_write_impl,
};

/* Helper function to find eMMC RPMB device */
static rpmb_result_t find_emmc_rpmb_device(char *device_path, size_t path_size)
{
	DIR *dir;
	struct dirent *ent;
	char test_path[EMMC_MAX_DEVICE_PATH];

	/* Common eMMC RPMB device paths */
	const char *rpmb_paths[] = {
		"/dev/mmcblk0rpmb",
		"/dev/mmcblk1rpmb",
		"/dev/mmcblk2rpmb",
		NULL
	};

	/* Try common paths first */
	for (int i = 0; rpmb_paths[i] != NULL; i++) {
		if (access(rpmb_paths[i], R_OK | W_OK) == 0) {
			strncpy(device_path, rpmb_paths[i], path_size - 1);
			device_path[path_size - 1] = '\0';
			RPMB_LOG_INFO("Found eMMC RPMB device: %s", device_path);
			return RPMB_RESULT_OK;
		}
	}

	/* Search in /dev for rpmb devices */
	dir = opendir("/dev");
	if (dir != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			if (strstr(ent->d_name, "rpmb") != NULL) {
				/* Ensure we don't exceed buffer size - be more conservative */
				size_t name_len = strlen(ent->d_name);
				if (name_len > 0 && name_len < (sizeof(test_path) - 10)) {
					int ret = snprintf(test_path, sizeof(test_path), "/dev/%s", ent->d_name);
					if (ret > 0 && ret < (int)sizeof(test_path)) {
						if (access(test_path, R_OK | W_OK) == 0) {
							/* Use snprintf with proper bounds checking */
							int copy_ret = snprintf(device_path, path_size, "%s", test_path);
							if (copy_ret > 0 && copy_ret < (int)path_size) {
								closedir(dir);
								RPMB_LOG_INFO("Found eMMC RPMB device: %s", device_path);
								return RPMB_RESULT_OK;
							}
						}
					}
				}
			}
		}
		closedir(dir);
	}

	RPMB_LOG_ERROR("No eMMC RPMB device found");
	return RPMB_RESULT_INVALID_DEVICE;
}

/* Get eMMC RPMB parameters */
static rpmb_result_t get_emmc_rpmb_parameters(rpmb_device_info_t *info)
{
	/* For now, use default values since eMMC RPMB parameter detection
	 * requires specific ioctl calls that may vary by kernel version */

	info->device_type = RPMB_DEVICE_EMMC;
	info->size_sectors = 128;  /* Default 128 sectors (64KB) */
	info->reliable_write_count = 1;  /* eMMC typically supports 1 frame per operation */
	info->initialized = true;

	RPMB_LOG_INFO("eMMC RPMB parameters: size=%u sectors, rwc=%u",
			info->size_sectors, info->reliable_write_count);

	return RPMB_RESULT_OK;
}

/* eMMC initialization implementation */
static rpmb_result_t emmc_init_impl(rpmb_device_info_t *info)
{
	rpmb_result_t result;

	if (!info) {
		return RPMB_RESULT_INVALID_PARAMETER;
	}

	if (g_emmc_ctx.initialized) {
		*info = (rpmb_device_info_t){
			.device_type = RPMB_DEVICE_EMMC,
				.size_sectors = 128,
				.reliable_write_count = 1,
				.initialized = true
		};
		return RPMB_RESULT_OK;
	}

	RPMB_LOG_INFO("Initializing eMMC RPMB device");

	/* Find eMMC RPMB device */
	result = find_emmc_rpmb_device(g_emmc_ctx.device_path,
			sizeof(g_emmc_ctx.device_path));
	if (result != RPMB_RESULT_OK) {
		return result;
	}

	/* Get device parameters */
	result = get_emmc_rpmb_parameters(info);
	if (result != RPMB_RESULT_OK) {
		return result;
	}

	g_emmc_ctx.initialized = true;
	g_emmc_ctx.fd = -1;  /* Will be opened on demand */

	RPMB_LOG_INFO("eMMC RPMB initialized successfully: %s", g_emmc_ctx.device_path);
	return RPMB_RESULT_OK;
}

/* eMMC cleanup implementation */
static void emmc_cleanup_impl(void)
{
	if (g_emmc_ctx.fd >= 0) {
		close(g_emmc_ctx.fd);
		g_emmc_ctx.fd = -1;
	}

	memset(&g_emmc_ctx, 0, sizeof(g_emmc_ctx));
	g_emmc_ctx.fd = -1;

	RPMB_LOG_INFO("eMMC RPMB cleanup completed");
}

/* Open eMMC device */
static rpmb_result_t emmc_device_open(void)
{
	if (g_emmc_ctx.fd >= 0) {
		return RPMB_RESULT_OK;  /* Already open */
	}

	g_emmc_ctx.fd = open(g_emmc_ctx.device_path, O_RDWR);
	if (g_emmc_ctx.fd < 0) {
		RPMB_LOG_ERROR("Failed to open eMMC RPMB device %s: %s",
				g_emmc_ctx.device_path, strerror(errno));
		return RPMB_RESULT_INVALID_DEVICE;
	}

	return RPMB_RESULT_OK;
}

/* Close eMMC device */
static void emmc_device_close(void)
{
	if (g_emmc_ctx.fd >= 0) {
		close(g_emmc_ctx.fd);
		g_emmc_ctx.fd = -1;
	}
}

/* eMMC read implementation */
static rpmb_result_t emmc_read_impl(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len)
{
	rpmb_result_t result;
	ssize_t bytes_read;
	size_t total_bytes;

	if (!request_buf || !response_buf || !response_len || block_count == 0) {
		return RPMB_RESULT_INVALID_PARAMETER;
	}

	if (!g_emmc_ctx.initialized) {
		return RPMB_RESULT_NOT_INITIALIZED;
	}

	RPMB_LOG_DEBUG("eMMC RPMB read: blocks=%u", block_count);

	result = emmc_device_open();
	if (result != RPMB_RESULT_OK) {
		return result;
	}

	total_bytes = block_count * EMMC_RPMB_BLOCK_SIZE;

	/* For eMMC RPMB, we would typically use ioctl calls with MMC_IOC_CMD
	 * For now, implement a basic read operation */
	bytes_read = read(g_emmc_ctx.fd, response_buf, total_bytes);

	if (bytes_read < 0) {
		RPMB_LOG_ERROR("eMMC RPMB read failed: %s", strerror(errno));
		emmc_device_close();
		return RPMB_RESULT_READ_FAILURE;
	}

	*response_len = (uint32_t)bytes_read;

	RPMB_LOG_DEBUG("eMMC RPMB read completed: %u bytes", *response_len);
	return RPMB_RESULT_OK;
}

/* eMMC write implementation */
static rpmb_result_t emmc_write_impl(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len,
		uint32_t frames_per_operation)
{
	rpmb_result_t result;
	ssize_t bytes_written;
	size_t total_bytes;

	if (!request_buf || !response_buf || !response_len ||
			block_count == 0 || frames_per_operation == 0) {
		return RPMB_RESULT_INVALID_PARAMETER;
	}

	if (!g_emmc_ctx.initialized) {
		return RPMB_RESULT_NOT_INITIALIZED;
	}

	RPMB_LOG_DEBUG("eMMC RPMB write: blocks=%u, frames_per_op=%u",
			block_count, frames_per_operation);

	result = emmc_device_open();
	if (result != RPMB_RESULT_OK) {
		return result;
	}

	total_bytes = block_count * EMMC_RPMB_BLOCK_SIZE;

	/* For eMMC RPMB, we would typically use ioctl calls with MMC_IOC_CMD
	 * For now, implement a basic write operation */
	bytes_written = write(g_emmc_ctx.fd, request_buf, total_bytes);

	if (bytes_written < 0) {
		RPMB_LOG_ERROR("eMMC RPMB write failed: %s", strerror(errno));
		emmc_device_close();
		return RPMB_RESULT_WRITE_FAILURE;
	}

	/* For eMMC RPMB, the response would typically contain the result frame */
	*response_len = EMMC_RPMB_FRAME_SIZE;
	memset(response_buf, 0, *response_len);

	RPMB_LOG_DEBUG("eMMC RPMB write completed: %u bytes", (uint32_t)bytes_written);
	return RPMB_RESULT_OK;
}

/* Legacy function implementations for backward compatibility */
int rpmb_emmc_init(rpmb_init_info_t *rpmb_info)
{
	rpmb_device_info_t device_info = {0};
	rpmb_result_t result = emmc_init_impl(&device_info);

	if (result == RPMB_RESULT_OK && rpmb_info) {
		rpmb_info->dev_type = (device_id_type)device_info.device_type;
		rpmb_info->size = device_info.size_sectors;
		rpmb_info->rel_wr_count = device_info.reliable_write_count;
	}

	return (result == RPMB_RESULT_OK) ? 0 : -1;
}

int rpmb_emmc_read(uint32_t *req_buf, uint32_t blk_cnt,
		uint32_t *resp_buf, uint32_t *resp_len)
{
	rpmb_result_t result = emmc_read_impl(req_buf, blk_cnt, resp_buf, resp_len);
	return (result == RPMB_RESULT_OK) ? 0 : -1;
}

int rpmb_emmc_write(uint32_t *req_buf, uint32_t blk_cnt,
		uint32_t *resp_buf, uint32_t *resp_len,
		uint32_t frames_per_rpmb_op)
{
	rpmb_result_t result = emmc_write_impl(req_buf, blk_cnt, resp_buf, resp_len, frames_per_rpmb_op);
	return (result == RPMB_RESULT_OK) ? 0 : -1;
}

void rpmb_emmc_exit(void)
{
	emmc_cleanup_impl();
}
