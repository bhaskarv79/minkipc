// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/*
 * RPMB core -- device detection, dispatch, and wakelock.
 *
 * Architecture
 * ------------
 * A static table (rpmb_driver_table[]) lists every supported storage
 * driver in probe-priority order.  At init time rpmb_init() walks the
 * table, calls each driver's probe(), and on the first match calls
 * init().  The winning driver's ops pointer is stored in g_active_ops.
 *
 * rpmb_read() / rpmb_write() forward directly to g_active_ops.
 * If no device was found g_active_ops is NULL and both return -1.
 *
 * Adding a new storage type requires only:
 *   1. Implement the rpmb_dev_ops_t callbacks in a new rpmb_<type>.c.
 *   2. Add one row to rpmb_driver_table[] below.
 *   No other file needs to change.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rpmb.h"
#include "rpmb_private.h"
#include "rpmb_logging.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* -----------------------------------------------------------------------
 * Global device state (shared with eMMC and UFS drivers via rpmb_private.h)
 * ----------------------------------------------------------------------- */

struct rpmb_stats rpmb;

/* -----------------------------------------------------------------------
 * Pre-built result-register read request frame (definition)
 * Declared extern in rpmb.h; used by rpmb_emmc.c and rpmb_ufs.c.
 * ----------------------------------------------------------------------- */

const struct rpmb_frame read_result_reg_frame = {
	.request_response = { 0x00, READ_RESULT_REG },
};

/* -----------------------------------------------------------------------
 * Registered driver table -- probed in order; first match wins.
 * ----------------------------------------------------------------------- */

static const rpmb_dev_ops_t rpmb_driver_table[] = {
	{
		.name = "UFS",
		.dev_type = UFS_RPMB,
		.probe = rpmb_ufs_probe,
		.init = rpmb_ufs_init,
		.read = rpmb_ufs_read,
		.write = rpmb_ufs_write,
		.exit = rpmb_ufs_exit,
	},
	{
		.name = "eMMC",
		.dev_type = EMMC_RPMB,
		.probe = rpmb_emmc_probe,
		.init = rpmb_emmc_init,
		.read = rpmb_emmc_read,
		.write = rpmb_emmc_write,
		.exit = rpmb_emmc_exit,
	},
};

#define RPMB_NUM_DRIVERS ARRAY_SIZE(rpmb_driver_table)

/* -----------------------------------------------------------------------
 * Module state
 * ----------------------------------------------------------------------- */

static const rpmb_dev_ops_t *g_active_ops;
static int g_init_done;

/* -----------------------------------------------------------------------
 * Wakelock
 * ----------------------------------------------------------------------- */

#define WAKELOCK_PATH "/sys/power/wake_lock"
#define WAKEUNLOCK_PATH "/sys/power/wake_unlock"
#define WAKELOCK_NAME "rpmb_access_wakelock"

static struct {
	int lock_fd;
	int unlock_fd;
	ssize_t name_len;
} g_wakelock = { -1, -1, 0 };

void rpmb_init_wakelock(void)
{
	g_wakelock.lock_fd = open(WAKELOCK_PATH, O_WRONLY | O_APPEND);
	g_wakelock.unlock_fd = open(WAKEUNLOCK_PATH, O_WRONLY | O_APPEND);

	if (g_wakelock.lock_fd < 0 || g_wakelock.unlock_fd < 0) {
		/* Non-fatal: wakelock is a best-effort optimisation */
		if (g_wakelock.lock_fd >= 0) {
			close(g_wakelock.lock_fd);
			g_wakelock.lock_fd = -1;
		}
		if (g_wakelock.unlock_fd >= 0) {
			close(g_wakelock.unlock_fd);
			g_wakelock.unlock_fd = -1;
		}
		RPMB_LOG_WARN("Wakelock unavailable -- continuing without\n");
		return;
	}
	g_wakelock.name_len = (ssize_t)strlen(WAKELOCK_NAME);
}

void rpmb_wakelock(void)
{
	if (g_wakelock.lock_fd >= 0) {
		ssize_t ret = write(g_wakelock.lock_fd, WAKELOCK_NAME,
				    (size_t)g_wakelock.name_len);
		if (ret != g_wakelock.name_len)
			RPMB_LOG_WARN("Failed to acquire wakelock\n");
	}
}

void rpmb_wakeunlock(void)
{
	if (g_wakelock.unlock_fd >= 0) {
		ssize_t ret = write(g_wakelock.unlock_fd, WAKELOCK_NAME,
				    (size_t)g_wakelock.name_len);
		if (ret != g_wakelock.name_len)
			RPMB_LOG_WARN("Failed to release wakelock\n");
	}
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int rpmb_init(rpmb_init_info_t *info)
{
	size_t i;

	if (g_init_done) {
		if (info) {
			info->size = rpmb.info.size;
			info->rel_wr_count = rpmb.info.rel_wr_count;
			info->dev_type = rpmb.info.dev_type;
		}
		return (g_active_ops != NULL) ? 0 : -1;
	}

	RPMB_LOG_INFO("RPMB device detection starting...\n");

	for (i = 0; i < RPMB_NUM_DRIVERS; i++) {
		const rpmb_dev_ops_t *ops = &rpmb_driver_table[i];

		RPMB_LOG_INFO("Probing %s...\n", ops->name);

		if (ops->probe() == NO_DEVICE)
			continue;

		RPMB_LOG_INFO("RPMB device detected: %s\n", ops->name);

		if (ops->init() != 0) {
			RPMB_LOG_ERROR("%s init failed\n", ops->name);
			continue;
		}

		g_active_ops = ops;
		break;
	}

	g_init_done = 1;

	if (!g_active_ops) {
		RPMB_LOG_WARN("No RPMB device found -- service running"
			      " without storage support\n");
		if (info) {
			memset(info, 0, sizeof(*info));
			info->dev_type = NO_DEVICE;
		}
		return -1;
	}

	if (info) {
		info->size = rpmb.info.size;
		info->rel_wr_count = rpmb.info.rel_wr_count;
		info->dev_type = rpmb.info.dev_type;
	}

	RPMB_LOG_INFO("RPMB initialised: dev=%s size=%u rel_wr_count=%u\n",
		      g_active_ops->name,
		      rpmb.info.size,
		      rpmb.info.rel_wr_count);
	return 0;
}

int rpmb_read(uint32_t *req_buf, uint32_t blk_cnt,
	      uint32_t *resp_buf, uint32_t *resp_len)
{
	if (!g_active_ops) {
		RPMB_LOG_ERROR("rpmb_read: no active device\n");
		return -1;
	}
	return g_active_ops->read(req_buf, blk_cnt, resp_buf, resp_len);
}

int rpmb_write(uint32_t *req_buf, uint32_t blk_cnt,
	       uint32_t *resp_buf, uint32_t *resp_len,
	       uint32_t frames_per_op)
{
	if (!g_active_ops) {
		RPMB_LOG_ERROR("rpmb_write: no active device\n");
		return -1;
	}
	return g_active_ops->write(req_buf, blk_cnt, resp_buf, resp_len,
				   frames_per_op);
}
