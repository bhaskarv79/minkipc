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
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Device detection constants (used by cmdline fallback only) */
#define CMDLINE  "/proc/cmdline"
#define EMMC_DEV "root=/dev/mmcblk"
#define UFS_DEV  "root=/dev/sd"
#define BOOT_DEV_KEY  "bootdevice="

#define RPMB_WAKE_LOCK_FILE     "/sys/power/wake_lock"
#define RPMB_WAKE_UNLOCK_FILE	"/sys/power/wake_unlock"
#define RPMB_WAKE_LOCK_STRING	"rpmb_access_wakelock"

/* Shared struct variable for rpmb */
struct rpmb_stats rpmb;

static struct rpmb_wake_lock {
	int lock_fd;
	int unlock_fd;
	ssize_t write_size;
} wakelock = {-1, -1, 0};

/* -----------------------------------------------------------------------
 * RPMB driver table infrastructure
 *
 * Each storage type that supports RPMB registers a probe function.
 * get_rpmb_dev() iterates the table in priority order and returns the
 * first device type whose probe succeeds.
 *
 * To add support for a new storage type (e.g. NVMe):
 *   1. Write a static probe_<type>() function below.
 *   2. Add { "<name>", <DEV_TYPE>, probe_<type> } to rpmb_driver_table[].
 * No other code needs to change.
 * ----------------------------------------------------------------------- */

/**
 * typedef rpmb_probe_fn - RPMB driver probe callback
 *
 * A probe function scans the system for its device type and attempts to
 * open the device node to confirm it is accessible.
 *
 * Return: the device_id_type for this driver on success, NO_DEVICE otherwise
 */
typedef device_id_type (*rpmb_probe_fn)(void);

/**
 * struct rpmb_driver_desc - descriptor for one RPMB-capable storage driver
 * @name:     human-readable driver name (used in log messages)
 * @dev_type: device_id_type value returned when this driver is selected
 * @probe:    function that detects whether this device is present
 */
struct rpmb_driver_desc {
	const char     *name;
	device_id_type  dev_type;
	rpmb_probe_fn   probe;
};

/* -----------------------------------------------------------------------
 * RPMB driver table
 *
 * Drivers are probed in the order listed here.  Add new storage types
 * by appending a new row — no other code needs to change.
 * Probe functions live in the respective device files:
 *   rpmb_ufs_probe()  → rpmb_ufs.c
 *   rpmb_emmc_probe() → rpmb_emmc.c
 * ----------------------------------------------------------------------- */
static const struct rpmb_driver_desc rpmb_driver_table[] = {
	{ "UFS",  UFS_RPMB,  rpmb_ufs_probe  },
	{ "eMMC", EMMC_RPMB, rpmb_emmc_probe },
	/*
	 * Future entries, e.g.:
	 * { "NVMe", NVME_RPMB, probe_nvme },
	 */
};

/* -----------------------------------------------------------------------
 * /proc/cmdline fallback (last resort)
 * ----------------------------------------------------------------------- */

/**
 * detect_from_cmdline() - Detect RPMB device type from /proc/cmdline
 *
 * Parses the kernel command line for root= and bootdevice= hints.
 * Used only when no device node is directly accessible (e.g. some
 * test/emulation environments where /dev is not fully populated).
 *
 * Return: EMMC_RPMB, UFS_RPMB, or NO_DEVICE
 */
static device_id_type detect_from_cmdline(void)
{
	int fd;
	char *cmdline_buf = NULL;
	ssize_t ret;
	ssize_t byte_count = 0;
	char *bootdev;
	char cmdline_segment[101];
	device_id_type status_ret = NO_DEVICE;

	RPMB_LOG_DEBUG("Falling back to /proc/cmdline for device detection\n");

	fd = open(CMDLINE, O_RDONLY);
	if (fd < 0) {
		RPMB_LOG_ERROR("Cannot open /proc/cmdline (err %d)\n", errno);
		return NO_DEVICE;
	}

	do {
		ret = read(fd, cmdline_segment, 100);
		byte_count = ret > 0 ? (byte_count + ret) : byte_count;
	} while (ret > 0);

	if (ret < 0) {
		RPMB_LOG_ERROR("Error reading /proc/cmdline (err %d)\n", errno);
		close(fd);
		return NO_DEVICE;
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		RPMB_LOG_ERROR("Error seeking /proc/cmdline (err %d)\n", errno);
		close(fd);
		return NO_DEVICE;
	}

	cmdline_buf = malloc(byte_count + 1);
	if (!cmdline_buf) {
		RPMB_LOG_ERROR("Out of memory reading /proc/cmdline\n");
		close(fd);
		return NO_DEVICE;
	}

	ret = read(fd, cmdline_buf, byte_count);
	close(fd);

	if (ret != byte_count) {
		RPMB_LOG_ERROR("Short read on /proc/cmdline:"
			       " expected %ld, got %ld\n",
			       (long)byte_count, (long)ret);
		free(cmdline_buf);
		return NO_DEVICE;
	}
	cmdline_buf[ret] = '\0';

	RPMB_LOG_DEBUG("Kernel cmdline: %.100s%s\n", cmdline_buf,
		       strlen(cmdline_buf) > 100 ? "..." : "");

	if (strstr(cmdline_buf, EMMC_DEV)) {
		RPMB_LOG_DEBUG("eMMC detected from cmdline\n");
		status_ret = EMMC_RPMB;
	} else if (strstr(cmdline_buf, UFS_DEV)) {
		RPMB_LOG_DEBUG("UFS detected from cmdline\n");
		status_ret = UFS_RPMB;
	} else {
		/* Check bootdevice= key (used when dm-verity is enabled) */
		bootdev = strstr(cmdline_buf, BOOT_DEV_KEY);
		if (bootdev != NULL) {
			bootdev += strlen(BOOT_DEV_KEY);
			if (*bootdev != '\0') {
				if (strstr(bootdev, "sdhci")) {
					RPMB_LOG_DEBUG("eMMC detected from"
						       " bootdevice= key\n");
					status_ret = EMMC_RPMB;
				} else if (strstr(bootdev, "ufshc")) {
					RPMB_LOG_DEBUG("UFS detected from"
						       " bootdevice= key\n");
					status_ret = UFS_RPMB;
				}
			}
		}
	}

	free(cmdline_buf);
	return status_ret;
}

/* -----------------------------------------------------------------------
 * Main device detection entry point
 * ----------------------------------------------------------------------- */

/**
 * get_rpmb_dev() - Detect and identify the RPMB device type
 *
 * Iterates the rpmb_driver_table[], calling each driver's probe()
 * function in priority order.  The first driver that successfully
 * opens its device node wins.
 *
 * If no driver probe succeeds, falls back to parsing /proc/cmdline
 * for backward compatibility with environments where device nodes
 * may not be fully populated (e.g. some test setups).
 *
 * Adding support for a new storage type requires only:
 *   - a new probe_<type>() function
 *   - a new row in rpmb_driver_table[]
 *
 * Return: device_id_type indicating EMMC_RPMB, UFS_RPMB, or NO_DEVICE
 */
static device_id_type get_rpmb_dev(void)
{
	device_id_type device;
	size_t i;

	RPMB_LOG_INFO("RPMB device detection starting...\n");

	/* Probe each registered driver in table order */
	for (i = 0; i < ARRAY_SIZE(rpmb_driver_table); i++) {
		RPMB_LOG_DEBUG("Probing %s RPMB driver...\n",
			       rpmb_driver_table[i].name);
		device = rpmb_driver_table[i].probe();
		if (device != NO_DEVICE) {
			RPMB_LOG_INFO("RPMB device detected: %s\n",
				      rpmb_driver_table[i].name);
			return device;
		}
	}

	/* No driver matched — fall back to /proc/cmdline */
	RPMB_LOG_DEBUG("No RPMB device found via driver probing,"
		       " falling back to /proc/cmdline\n");
	device = detect_from_cmdline();

	RPMB_LOG_INFO("RPMB device detection result: %s\n",
		      (device == UFS_RPMB)  ? "UFS_RPMB"  :
		      (device == EMMC_RPMB) ? "EMMC_RPMB" : "NO_DEVICE");

	return device;
}

/* -----------------------------------------------------------------------
 * Public RPMB API
 * ----------------------------------------------------------------------- */

/**
 * rpmb_default_init() - Initialize RPMB with default/no-device settings
 * @rpmb_info: Pointer to RPMB initialization info structure (unused)
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
 * Detects the RPMB device type and calls the appropriate device-specific
 * initialization function.  If already initialized, returns cached info.
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
 * @req_buf:  Request buffer containing RPMB frames
 * @blk_cnt:  Number of blocks to read
 * @resp_buf: Response buffer
 * @resp_len: Response length (output)
 *
 * Return: 0 on success, negative error code on failure
 */
int rpmb_read(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf,
	      uint32_t *resp_len)
{
	if (rpmb.info.dev_type == EMMC_RPMB)
		return rpmb_emmc_read(req_buf, blk_cnt, resp_buf, resp_len);
	else if (rpmb.info.dev_type == UFS_RPMB)
		return rpmb_ufs_read(req_buf, blk_cnt, resp_buf, resp_len);

	RPMB_LOG_ERROR("rpmb read on invalid device type\n");
	return -1;
}

/**
 * rpmb_write() - Write data to RPMB device
 * @req_buf:              Request buffer containing RPMB frames
 * @blk_cnt:              Number of blocks to write
 * @resp_buf:             Response buffer
 * @resp_len:             Response length (output)
 * @frames_per_rpmb_trans: Frames per RPMB transaction
 *
 * Return: 0 on success, negative error code on failure
 */
int rpmb_write(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf,
	       uint32_t *resp_len, uint32_t frames_per_rpmb_trans)
{
	if (rpmb.info.dev_type == EMMC_RPMB)
		return rpmb_emmc_write(req_buf, blk_cnt, resp_buf, resp_len,
				       frames_per_rpmb_trans);
	else if (rpmb.info.dev_type == UFS_RPMB)
		return rpmb_ufs_write(req_buf, blk_cnt, resp_buf, resp_len,
				      frames_per_rpmb_trans);

	RPMB_LOG_ERROR("rpmb write on invalid device type\n");
	return -1;
}

/* -----------------------------------------------------------------------
 * Wakelock support
 * ----------------------------------------------------------------------- */

static int rpmb_open_wakelock_files(void)
{
	wakelock.unlock_fd = -1;
	wakelock.lock_fd = -1;

	wakelock.lock_fd = open(RPMB_WAKE_LOCK_FILE, O_WRONLY | O_APPEND);
	if (wakelock.lock_fd < 0)
		return -1;

	wakelock.unlock_fd = open(RPMB_WAKE_UNLOCK_FILE, O_WRONLY | O_APPEND);
	if (wakelock.unlock_fd < 0) {
		close(wakelock.lock_fd);
		wakelock.lock_fd = -1;
		return -1;
	}

	return 0;
}

void rpmb_init_wakelock(void)
{
	memset(&wakelock, 0, sizeof(wakelock));
	if (rpmb_open_wakelock_files() != 0) {
		wakelock.lock_fd = -1;
		wakelock.unlock_fd = -1;
		wakelock.write_size = 0;
		return;
	}
	wakelock.write_size = strlen(RPMB_WAKE_LOCK_STRING);
}

void rpmb_wakelock(void)
{
	ssize_t ret;

	if (wakelock.lock_fd < 0)
		return;

	ret = write(wakelock.lock_fd, RPMB_WAKE_LOCK_STRING,
		    wakelock.write_size);
	(void)ret;
}

void rpmb_wakeunlock(void)
{
	ssize_t ret;

	if (wakelock.unlock_fd < 0)
		return;

	ret = write(wakelock.unlock_fd, RPMB_WAKE_LOCK_STRING,
		    wakelock.write_size);
	(void)ret;
}

/* eMMC RPMB functions are implemented in rpmb_emmc.c */
