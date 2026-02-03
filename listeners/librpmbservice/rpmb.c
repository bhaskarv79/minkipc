// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

#define LOG_TAG "rpmb"

#include <errno.h>
#include <fcntl.h>
#include <linux/major.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rpmb.h"
#include "rpmb_logging.h"

/* Utility macros */
#define UNUSED(x) ((void)(x))

/* Device detection constants */
#define CMDLINE  "/proc/cmdline"
#define EMMC_DEV "root=/dev/mmcblk"
#define UFS_DEV  "root=/dev/sd"
#define BOOT_DEV_KEY  "bootdevice="

#define RPMB_WAKE_LOCK_FILE     "/sys/power/wake_lock"
#define RPMB_WAKE_UNLOCK_FILE	"/sys/power/wake_unlock"
#define RPMB_WAKE_LOCK_STRING	"rpmb_access_wakelock"

/*shared struct variable for rpmb*/
struct rpmb_stats rpmb;

static struct rpmb_wake_lock
{
	int lock_fd;
	int unlock_fd;
	ssize_t write_size;
} wakelock = {-1, -1, 0};

/**
 * get_rpmb_dev() - Detect and identify the RPMB device type
 *
 * This function analyzes /proc/cmdline to determine whether the system
 * is using eMMC or UFS storage, and returns the appropriate RPMB device type.
 * Falls back to UFS if detection fails.
 *
 * Return: device_id_type indicating EMMC_RPMB, UFS_RPMB, or NO_DEVICE
 */
static device_id_type get_rpmb_dev(void)
{
	RPMB_LOG_INFO("RPMB device detection starting...\n");

	/* Unified device detection using /proc/cmdline */
	int fd;
	char *cmdline_buf = NULL;
	ssize_t ret;
	ssize_t byte_count = 0;
	char *bootdev;
	char cmdline_segment[101];
	device_id_type status_ret = NO_DEVICE;

	fd = open(CMDLINE, O_RDONLY);
	if (fd < 0) {
		RPMB_LOG_ERROR("Error unable to open the file /proc/cmdline: (err no: %d)\n", errno);
		/* Fallback to UFS for testing environments */
		RPMB_LOG_INFO("Fallback to UFS RPMB for testing environment\n");
		return UFS_RPMB;
	}

	do{
		ret = read(fd, cmdline_segment, 100);
		byte_count = ret > 0 ? (byte_count + ret) : byte_count;
	} while(ret > 0);
	if(ret < 0) {
		RPMB_LOG_ERROR("Error reading the file /proc/cmdline: (err no: %d)\n", errno);
		close(fd);
		/* Fallback to UFS for testing environments */
		RPMB_LOG_INFO("Fallback to UFS RPMB for testing environment\n");
		return UFS_RPMB;
	}

	do {
		if (lseek(fd, 0, SEEK_SET)) {
			RPMB_LOG_ERROR("Error reading the file /proc/cmdline: (err no: %d)\n", errno);
			status_ret = NO_DEVICE;
			break;
		}
		cmdline_buf = malloc (byte_count + 1);
		if (cmdline_buf == NULL) {
			RPMB_LOG_ERROR("Error rpmb services run out of memory.\n");
			status_ret = NO_DEVICE;
			break;
		}
		ret = read(fd, cmdline_buf, byte_count);
		if (ret != byte_count) {
			RPMB_LOG_ERROR("Error reading the file /proc/cmdline fail: size of /proc/cmdline is %ld and"
				" return size is %ld\n", (long)byte_count, (long)ret);
			status_ret = NO_DEVICE;
			break;
		}
		cmdline_buf[ret] = '\0';

		if(strstr(cmdline_buf, EMMC_DEV)) {
			RPMB_LOG_DEBUG("RPMB partition exists on EMMC device\n");
			status_ret = EMMC_RPMB;
			break;
		}

		if(strstr(cmdline_buf, UFS_DEV)) {
			RPMB_LOG_DEBUG("RPMB partition exists on UFS device\n");
			status_ret = UFS_RPMB;
			break;
		}

		/* If dm-verity is enabled */
		bootdev = strstr(cmdline_buf, BOOT_DEV_KEY);
		if(bootdev != NULL) {
			bootdev = bootdev + strlen(BOOT_DEV_KEY);
			if (*bootdev != '\0') {
				if (strstr(bootdev, "sdhci")) {
					RPMB_LOG_DEBUG("RPMB partition exists on EMMC device");
					status_ret = EMMC_RPMB;
					break;
				} else if (strstr(bootdev, "ufshc")){
					RPMB_LOG_DEBUG("RPMB partition exists on UFS device");
					status_ret = UFS_RPMB;
					break;
				}
			}
		}

		/* Default to UFS if no clear detection */
		RPMB_LOG_INFO("No clear device detection from cmdline, defaulting to UFS\n");
		status_ret = UFS_RPMB;
	} while(0);

	if (cmdline_buf)
		free(cmdline_buf);
	close(fd);

	/* Final fallback - force UFS */
	if (status_ret == NO_DEVICE) {
		RPMB_LOG_INFO("Forcing UFS RPMB detection for testing environment\n");
		status_ret = UFS_RPMB;
	}

	RPMB_LOG_INFO("RPMB device detection result: %s\n",
		 (status_ret == UFS_RPMB) ? "UFS_RPMB" :
		 (status_ret == EMMC_RPMB) ? "EMMC_RPMB" : "NO_DEVICE");

	return status_ret;
}

/**
 * rpmb_default_init() - Initialize RPMB with default/no-device settings
 * @rpmb_info: Pointer to RPMB initialization info structure (unused)
 *
 * This function initializes the RPMB subsystem with default values when
 * no valid RPMB device is detected. Sets device type to NO_DEVICE.
 *
 * Return: 0 on success
 */
int rpmb_default_init(rpmb_init_info_t *rpmb_info)
{
	UNUSED(rpmb_info);

	rpmb.info.size = 0;
	rpmb.info.rel_wr_count = 0;
	rpmb.info.dev_type = NO_DEVICE;
	rpmb.init_done = 1;

	return 0;
}

/**
 * rpmb_init() - Initialize the RPMB subsystem
 * @rpmb_info: Pointer to structure to receive RPMB device information
 *
 * This function detects the RPMB device type (eMMC or UFS) and calls the
 * appropriate device-specific initialization function. If already initialized,
 * returns cached information.
 *
 * Return: 0 on success, negative error code on failure
 */
int rpmb_init(rpmb_init_info_t *rpmb_info)
{
	device_id_type device;
	int ret = 0;

	if (rpmb.init_done) {
		rpmb_info->size = rpmb.info.size;
		rpmb_info->rel_wr_count = rpmb.info.rel_wr_count;
		rpmb_info->dev_type = rpmb.info.dev_type;
		return ret;
	}

	device = get_rpmb_dev();

	if (device == EMMC_RPMB)
		ret = rpmb_emmc_init(rpmb_info);
	else if (device == UFS_RPMB)
		ret = rpmb_ufs_init(rpmb_info);
	else
		ret = rpmb_default_init(rpmb_info);

	return ret;
}

/**
 * rpmb_exit() - Clean up and close RPMB resources
 *
 * This function closes any open file descriptors and cleans up RPMB resources.
 * Intended for use with testing applications where rpmb_init() may be called
 * multiple times.
 */
void rpmb_exit(void)
{
	if (rpmb.init_done && rpmb.fd)
		close(rpmb.fd);

	if (rpmb.init_done && rpmb.fd_ufs_bsg)
		close(rpmb.fd_ufs_bsg);
}

/**
 * rpmb_read() - Read data from RPMB device
 * @req_buf: Pointer to request buffer containing RPMB frames
 * @blk_cnt: Number of blocks to read
 * @resp_buf: Pointer to response buffer to receive data
 * @resp_len: Pointer to variable to receive response length
 *
 * This function dispatches the read operation to the appropriate device-specific
 * implementation based on the detected RPMB device type (eMMC or UFS).
 *
 * Return: 0 on success, negative error code on failure
 */
int rpmb_read(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf, uint32_t *resp_len)
{
	if (rpmb.info.dev_type == EMMC_RPMB)
		return rpmb_emmc_read(req_buf, blk_cnt, resp_buf, resp_len);
	else if (rpmb.info.dev_type == UFS_RPMB)
		return rpmb_ufs_read(req_buf, blk_cnt, resp_buf, resp_len);

	RPMB_LOG_ERROR("rpmb read operation on invalid RPMB device!!");
	return -1;
}

/**
 * rpmb_write() - Write data to RPMB device
 * @req_buf: Pointer to request buffer containing RPMB frames
 * @blk_cnt: Number of blocks to write
 * @resp_buf: Pointer to response buffer to receive response
 * @resp_len: Pointer to variable to receive response length
 * @frames_per_rpmb_trans: Number of frames per RPMB transaction
 *
 * This function dispatches the write operation to the appropriate device-specific
 * implementation based on the detected RPMB device type (eMMC or UFS).
 *
 * Return: 0 on success, negative error code on failure
 */
int rpmb_write(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf, uint32_t *resp_len,
		uint32_t frames_per_rpmb_trans)
{
	if (rpmb.info.dev_type == EMMC_RPMB)
		return rpmb_emmc_write(req_buf, blk_cnt, resp_buf, resp_len, frames_per_rpmb_trans);
	else if (rpmb.info.dev_type == UFS_RPMB)
		return rpmb_ufs_write(req_buf, blk_cnt, resp_buf, resp_len, frames_per_rpmb_trans);

	RPMB_LOG_ERROR("rpmb write operation on invalid RPMB device!!");
	return -1;
}

/**
 * rpmb_open_wakelock_files() - Open wakelock control files
 *
 * This function opens the system wakelock files for acquiring and releasing
 * wakelocks during RPMB operations. Wakelocks prevent the system from
 * entering deep sleep during critical RPMB transactions.
 *
 * Return: 0 on success, -1 on failure
 */
static int rpmb_open_wakelock_files (void)
{
	wakelock.unlock_fd = -1;
	wakelock.lock_fd = -1;

	wakelock.lock_fd = open(RPMB_WAKE_LOCK_FILE, O_WRONLY|O_APPEND);
	if(wakelock.lock_fd < 0)
		return -1;

	wakelock.unlock_fd = open(RPMB_WAKE_UNLOCK_FILE, O_WRONLY|O_APPEND);
	if(wakelock.unlock_fd < 0) {
		close(wakelock.lock_fd);
		wakelock.lock_fd = -1;
		return -1;
	}

	return 0;
}

/**
 * rpmb_init_wakelock() - Initialize the wakelock subsystem
 *
 * This function initializes the wakelock mechanism used to prevent the system
 * from entering deep sleep during RPMB operations. If wakelock files are not
 * available, the function gracefully handles the failure and continues without
 * wakelock support.
 */
void rpmb_init_wakelock(void)
{
	int result = -1;

	memset (&wakelock, 0, sizeof(wakelock));
	result = rpmb_open_wakelock_files();
	if(result != 0) {
		/* Set invalid FDs to indicate wakelock is not available */
		wakelock.lock_fd = -1;
		wakelock.unlock_fd = -1;
		wakelock.write_size = 0;
		return;
	}
	wakelock.write_size = strlen(RPMB_WAKE_LOCK_STRING);
}

/**
 * rpmb_wakelock() - Acquire a wakelock to prevent system sleep
 *
 * This function acquires a wakelock to prevent the system from entering
 * deep sleep during RPMB operations. If wakelocks are not available,
 * the function returns silently without error.
 */
void rpmb_wakelock(void)
{
	ssize_t ret = -1;

	if (wakelock.lock_fd < 0) {
		/* Wakelock not available - this is normal on many systems */
		return;
	}

	ret = write(wakelock.lock_fd, RPMB_WAKE_LOCK_STRING, wakelock.write_size);
	/* Silently ignore write failures - wakelock is optional */
	(void)ret;
}

/**
 * rpmb_wakeunlock() - Release the wakelock to allow system sleep
 *
 * This function releases the wakelock acquired during RPMB operations,
 * allowing the system to enter deep sleep again. If wakelocks are not
 * available, the function returns silently without error.
 */
void rpmb_wakeunlock(void)
{
	ssize_t ret = -1;

	if (wakelock.unlock_fd < 0) {
		/* Wakelock not available - this is normal on many systems */
		return;
	}

	ret = write(wakelock.unlock_fd, RPMB_WAKE_LOCK_STRING,
					wakelock.write_size);
	/* Silently ignore write failures - wakelock is optional */
	(void)ret;
}

/* eMMC RPMB functions are now implemented in rpmb_emmc.c */
