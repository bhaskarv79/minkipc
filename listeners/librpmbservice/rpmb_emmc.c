// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/*
 * RPMB eMMC Implementation
 */

#define LOG_TAG "rpmb_emmc"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/mmc/ioctl.h>
#include <dirent.h>

#include "rpmb_logging.h"
#include "rpmb.h"
#include "rpmb_private.h"

/* eMMC RPMB device paths (char device >= 4.19, block device on older
 * kernels)
 */
#define RPMB_PATH "/dev/mmcblk0rpmb"
#define RPMB_LEGACY_PATH "/dev/block/mmcblk0rpmb"

/* sysfs attribute name suffixes under /sys/block/<disk>/device/ */
#define SYSFS_RPMB_SIZE_MULT "raw_rpmb_size_mult"
#define SYSFS_REL_SECTORS "rel_sectors"
#define SYSFS_ENH_RPMB "enhanced_rpmb_supported"

/* RPMB partition minimum size: 128 KiB per eMMC spec unit */
#define RPMB_PART_MIN_SIZE (128 * 1024)

/* Maximum valid raw_rpmb_size_mult per EXT_CSD spec */
#define MAX_RPMB_SIZE_MULT 0xFF

/* Reliable-write flag for CMD25 write_flag (bit 31) */
#define SECURE_WRITE (1U << 31)

/* MMC command opcodes */
#ifndef MMC_WRITE_MULTIPLE_BLOCK
#define MMC_WRITE_MULTIPLE_BLOCK 25
#endif
#ifndef MMC_READ_MULTIPLE_BLOCK
#define MMC_READ_MULTIPLE_BLOCK 18
#endif

/* MMC response/flag bits */
#ifndef MMC_RSP_PRESENT
#define MMC_RSP_PRESENT (1 << 0)
#define MMC_RSP_CRC (1 << 2)
#define MMC_RSP_OPCODE (1 << 4)
#define MMC_CMD_ADTC (1 << 5)
#define MMC_RSP_R1 (MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE)
#endif

#define MAX_BUF_SIZE 16

/* -----------------------------------------------------------------------
 * sysfs helpers -- read rel_sectors and raw_rpmb_size_mult
* ----------------------------------------------------------------------- */

static int sysfs_read_uint(const char *path)
{
	int fd, ret, val;
	char buf[MAX_BUF_SIZE] = {0};

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		RPMB_LOG_ERROR("Unable to open %s: %s\n",
			       path, strerror(errno));
		return -1;
	}
	ret = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (ret <= 0) {
		RPMB_LOG_ERROR("Unable to read %s: %s\n",
			       path, strerror(errno));
		return -1;
	}
	buf[ret] = '\0';
	if (sscanf(buf, "%u", &val) != 1) {
		RPMB_LOG_ERROR("Failed to parse value from %s\n", path);
		return -1;
	}
	return val;
}

/*
 * Public API
 */

int rpmb_emmc_init(void)
{
	struct stat st;
	const char *rpmb_device = RPMB_PATH;
	const char *devname;
	/*
	 * RPMB disk names are always short (e.g. "mmcblk0").
	 * Cap at 32 chars so the compiler can verify snprintf bounds below.
	 */
	#define RPMB_DISK_NAME_MAX 32
	#define RPMB_DISK_NAME_MAX_STR "32"
	/* "/sys/block/" + disk_name + "/device" + "/" + longest_attr + NUL */
	#define SYSFS_BASE_MAX (sizeof("/sys/block/") + RPMB_DISK_NAME_MAX + sizeof("/device"))
	#define SYSFS_PATH_MAX (SYSFS_BASE_MAX + sizeof(SYSFS_ENH_RPMB))
	char sysfs_base[SYSFS_BASE_MAX];
	char sysfs_path[SYSFS_PATH_MAX];
	size_t len;
	int rpmb_mult, rel_sec_cnt, enh_rpmb;

	memset(&rpmb.info, 0, sizeof(rpmb.info));

	/* Locate the RPMB device node */
	if (stat(rpmb_device, &st) != 0) {
		if (stat(RPMB_LEGACY_PATH, &st) != 0) {
			RPMB_LOG_ERROR("RPMB device not found: %s\n",
				       strerror(errno));
			return -1;
		}
		rpmb_device = RPMB_LEGACY_PATH;
	}

	/*
	 * Derive the sysfs base from the device node basename.
	 * "/dev/mmcblk0rpmb"       -> disk "mmcblk0"
	 * "/dev/block/mmcblk0rpmb" -> disk "mmcblk0"
	 * Strip the "rpmb" suffix to get the parent disk name.
	 */
	devname = strrchr(rpmb_device, '/');
	devname = devname ? devname + 1 : rpmb_device;
	len = strlen(devname);
	if (len <= 4 || strcmp(devname + len - 4, "rpmb") != 0) {
		RPMB_LOG_ERROR("Cannot derive disk name from device path: %s\n",
			       rpmb_device);
		return -1;
	}
	if (len - 4 > RPMB_DISK_NAME_MAX) {
		RPMB_LOG_ERROR("RPMB disk name too long: %s\n", devname);
		return -1;
	}
	/* Use the literal macro as precision so the compiler can verify bounds. */
	snprintf(sysfs_base, sizeof(sysfs_base),
		 "/sys/block/%." RPMB_DISK_NAME_MAX_STR "s/device", devname);

	/* Read raw_rpmb_size_mult from sysfs */
	snprintf(sysfs_path, sizeof(sysfs_path), "%s/%s",
		 sysfs_base, SYSFS_RPMB_SIZE_MULT);
	rpmb_mult = sysfs_read_uint(sysfs_path);
	if (rpmb_mult <= 0 || rpmb_mult > MAX_RPMB_SIZE_MULT) {
		RPMB_LOG_ERROR("Invalid rpmb_size_mult: %d\n", rpmb_mult);
		return -1;
	}

	/*
	 * TZ expects size in 512-byte sectors.
	 * eMMC spec: each size_mult unit = 128 KiB = RPMB_PART_MIN_SIZE bytes.
	 */
	rpmb.info.size = (rpmb_mult * RPMB_PART_MIN_SIZE) / 512;

	/* Read rel_sectors from sysfs */
	snprintf(sysfs_path, sizeof(sysfs_path), "%s/%s",
		 sysfs_base, SYSFS_REL_SECTORS);
	rel_sec_cnt = sysfs_read_uint(sysfs_path);
	if (rel_sec_cnt <= 0) {
		RPMB_LOG_ERROR("Invalid rel_sectors: %d\n", rel_sec_cnt);
		return -1;
	}

	/*
	 * Check enhanced RPMB support (eMMC 5.1+).
	 * If supported, rel_wr_count is 32 regardless of rel_sectors.
	 * The sysfs file is absent on pre-5.1 devices -- that is not an error.
	 */
	snprintf(sysfs_path, sizeof(sysfs_path), "%s/%s",
		 sysfs_base, SYSFS_ENH_RPMB);
	enh_rpmb = sysfs_read_uint(sysfs_path);
	if (enh_rpmb > 0) {
		RPMB_LOG_INFO("Enhanced RPMB supported,"
			      " setting rel_wr_count=32\n");
		rel_sec_cnt = 32;
	}

	rpmb.info.rel_wr_count = rel_sec_cnt;

	RPMB_LOG_INFO("eMMC RPMB: size=%u (512B sectors), rel_wr_count=%u\n",
		      rpmb.info.size, rpmb.info.rel_wr_count);

	/* Open the RPMB device fd (kept open, stored in rpmb.fd) */
	rpmb.fd = open(rpmb_device, O_RDWR);
	if (rpmb.fd < 0) {
		RPMB_LOG_ERROR("Failed to open %s: %s\n",
			       rpmb_device, strerror(errno));
		return -1;
	}

	rpmb.info.dev_type = EMMC_RPMB;
	rpmb.init_done = 1;

	rpmb_init_wakelock();

	RPMB_LOG_INFO("eMMC RPMB initialized: %s\n", rpmb_device);
	return 0;
}

void rpmb_emmc_exit(void)
{
	if (rpmb.fd >= 0) {
		close(rpmb.fd);
		rpmb.fd = -1;
	}
}

/*
 * rpmb_emmc_read() - Authenticated read from eMMC RPMB
 *
 * 2-command ioctl sequence (matches reference rpmb_emmc.c):
 *   CMD25  write_flag=1  : send 1 request frame (nonce frame from TZ)
 *   CMD18  write_flag=0  : read blk_cnt response frames
 *
 * No CMD23 is used -- the reference does not use SET_BLOCK_COUNT for RPMB.
 */
int rpmb_emmc_read(uint32_t *req_buf, uint32_t blk_cnt,
		   uint32_t *resp_buf, uint32_t *resp_len)
{
	/*
	 * mmc_ioc_multi_cmd ends in a flexible array member (cmds[]), so it
	 * must be heap-allocated with room for the commands we use. A stack
	 * wrapper struct does not work: GCC's -Warray-bounds (under -O2)
	 * traces cmds[1] back to the fixed-size wrapper and errors out.
	 * Heap allocation sizes the array at runtime, which the static
	 * checker cannot flag. This matches the mmc-utils reference idiom.
	 */
	const uint32_t num_cmds = 2;
	struct mmc_ioc_multi_cmd *mc;
	struct mmc_ioc_cmd *cmds;
	int ret;

	mc = calloc(1, sizeof(*mc) + num_cmds * sizeof(struct mmc_ioc_cmd));
	if (!mc) {
		RPMB_LOG_ERROR("eMMC RPMB read: out of memory\n");
		*resp_len = 0;
		return -1;
	}
	cmds = mc->cmds;

	rpmb_wakelock();

	mc->num_of_cmds = num_cmds;

	/* CMD25 -- write 1 request frame */
	cmds[0].write_flag = 1;
	cmds[0].opcode = MMC_WRITE_MULTIPLE_BLOCK;
	cmds[0].arg = 0;
	cmds[0].flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmds[0].blksz = RPMB_BLK_SIZE;
	cmds[0].blocks = RPMB_MIN_BLK_CNT;
	mmc_ioc_cmd_set_data(cmds[0], req_buf);

	/* CMD18 -- read blk_cnt response frames */
	cmds[1].write_flag = 0;
	cmds[1].opcode = MMC_READ_MULTIPLE_BLOCK;
	cmds[1].arg = 0;
	cmds[1].flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmds[1].blksz = RPMB_BLK_SIZE;
	cmds[1].blocks = blk_cnt;
	mmc_ioc_cmd_set_data(cmds[1], resp_buf);

	ret = ioctl(rpmb.fd, MMC_IOC_MULTI_CMD, mc);

	if (ret) {
		RPMB_LOG_ERROR("eMMC RPMB read ioctl failed: %s\n",
			       strerror(errno));
		*resp_len = 0;
	} else {
		*resp_len = blk_cnt * RPMB_BLK_SIZE;
	}

	free(mc);
	rpmb_wakeunlock();
	return ret;
}

/*
 * rpmb_emmc_write() - Authenticated write to eMMC RPMB
 *
 * 3-command ioctl sequence per transaction (matches reference rpmb_emmc.c):
 *   CMD25  write_flag = 1|SECURE_WRITE : send frames_per_trans data frames
 *   CMD25  write_flag = 1              : send 1 result-read-request frame
 *   CMD18  write_flag = 0              : read 1 result frame
 *
 * Iterates blk_cnt/frames_per_rpmb_trans times.
 * Checks result frame after each transaction and stops on error.
 */
int rpmb_emmc_write(uint32_t *req_buf, uint32_t blk_cnt,
		    uint32_t *resp_buf, uint32_t *resp_len,
		    uint32_t frames_per_rpmb_trans)
{
	struct rpmb_frame result_frame;
	/*
	 * mmc_ioc_multi_cmd ends in a flexible array member (cmds[]), so it
	 * must be heap-allocated with room for the commands we use. See the
	 * note in rpmb_emmc_read() -- a stack wrapper trips -Warray-bounds
	 * under -O2; runtime allocation does not.
	 */
	const uint32_t num_cmds = 3;
	struct mmc_ioc_multi_cmd *mc;
	struct mmc_ioc_cmd *cmds;
	int ret = 0, i, num_rpmb_trans;

	if (frames_per_rpmb_trans == 0) {
		RPMB_LOG_ERROR("frames_per_rpmb_trans is 0\n");
		*resp_len = 0;
		return -1;
	}

	if (blk_cnt % frames_per_rpmb_trans != 0) {
		RPMB_LOG_ERROR("blk_cnt %u not a multiple of frames_per_trans %u\n",
			       blk_cnt, frames_per_rpmb_trans);
		*resp_len = 0;
		return -1;
	}

	mc = calloc(1, sizeof(*mc) + num_cmds * sizeof(struct mmc_ioc_cmd));
	if (!mc) {
		RPMB_LOG_ERROR("eMMC RPMB write: out of memory\n");
		*resp_len = 0;
		return -1;
	}
	cmds = mc->cmds;

	rpmb_wakelock();

	num_rpmb_trans = blk_cnt / frames_per_rpmb_trans;

	RPMB_LOG_INFO("eMMC RPMB write: blk_cnt=%u, num_trans=%d,"
		      " frames_per_trans=%u, rel_wr_count=%u\n",
		      blk_cnt, num_rpmb_trans,
		      frames_per_rpmb_trans, rpmb.info.rel_wr_count);

	mc->num_of_cmds = num_cmds;

	/* CMD25 -- write data frames (reliable write); data ptr set per-loop */
	cmds[0].write_flag = 1 | SECURE_WRITE;
	cmds[0].opcode = MMC_WRITE_MULTIPLE_BLOCK;
	cmds[0].arg = 0;
	cmds[0].flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmds[0].blksz = RPMB_BLK_SIZE;
	cmds[0].blocks = frames_per_rpmb_trans;

	/* CMD25 -- write result-read-request frame */
	cmds[1].write_flag = 1;
	cmds[1].opcode = MMC_WRITE_MULTIPLE_BLOCK;
	cmds[1].arg = 0;
	cmds[1].flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmds[1].blksz = RPMB_BLK_SIZE;
	cmds[1].blocks = RPMB_MIN_BLK_CNT;

	/* CMD18 -- read result frame */
	cmds[2].write_flag = 0;
	cmds[2].opcode = MMC_READ_MULTIPLE_BLOCK;
	cmds[2].arg = 0;
	cmds[2].flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmds[2].blksz = RPMB_BLK_SIZE;
	cmds[2].blocks = RPMB_MIN_BLK_CNT;

	for (i = 0; i < num_rpmb_trans; i++) {
		mmc_ioc_cmd_set_data(cmds[0], req_buf);
		mmc_ioc_cmd_set_data(cmds[1], &read_result_reg_frame);
		mmc_ioc_cmd_set_data(cmds[2], resp_buf);

		ret = ioctl(rpmb.fd, MMC_IOC_MULTI_CMD, mc);
		if (ret) {
			RPMB_LOG_ERROR("eMMC RPMB write ioctl failed at"
				       " trans %d: %s\n", i, strerror(errno));
			break;
		}

		/*
		 * Check result frame for RPMB-level errors.
		 * result[2] is big-endian: result[1] is the LSByte and holds
		 * the result code (bits[6:0]) and the write-count-expired flag
		 * (bit 7, MAXED_WR_COUNTER = 0x80).
		 */
		memcpy(&result_frame, resp_buf, sizeof(result_frame));
		if (result_frame.result[1] & MAXED_WR_COUNTER) {
			RPMB_LOG_ERROR("eMMC RPMB write: max write counter"
				       " reached\n");
			ret = -1;
			break;
		}
		if (result_frame.result[1] & ~MAXED_WR_COUNTER) {
			RPMB_LOG_ERROR("eMMC RPMB write: result error 0x%02x"
				       " at trans %d\n",
				       result_frame.result[1], i);
			ret = -1;
			break;
		}

		/* Advance to next batch of request frames */
		req_buf = (uint32_t *)((uint8_t *)req_buf +
				       frames_per_rpmb_trans * RPMB_BLK_SIZE);
	}

	if (ret != 0)
		*resp_len = 0;
	else
		*resp_len = RPMB_MIN_BLK_CNT * RPMB_BLK_SIZE;

	free(mc);
	rpmb_wakeunlock();
	return ret;
}

/*
 * emmc_scan_dev - scan /dev/ for any mmcblk*rpmb device node
 */
static device_id_type emmc_scan_dev(void)
{
	DIR *dir;
	struct dirent *ent;
	char path[PATH_MAX];
	size_t len;
	struct stat st;

	dir = opendir("/dev");
	if (!dir)
		return NO_DEVICE;

	while ((ent = readdir(dir)) != NULL) {
		len = strlen(ent->d_name);
		if (strncmp(ent->d_name, "mmcblk", 6) != 0)
			continue;
		if (len < 10 ||
		    strcmp(ent->d_name + len - 4, "rpmb") != 0)
			continue;
		snprintf(path, sizeof(path), "/dev/%s", ent->d_name);
		if (stat(path, &st) == 0) {
			RPMB_LOG_INFO("eMMC RPMB device found: %s\n", path);
			closedir(dir);
			return EMMC_RPMB;
		}
	}
	closedir(dir);
	return NO_DEVICE;
}

/*
 * rpmb_emmc_probe() - Probe for an eMMC RPMB device
 */
device_id_type rpmb_emmc_probe(void)
{
	struct stat st;

	if (stat(RPMB_PATH, &st) == 0) {
		RPMB_LOG_INFO("eMMC RPMB device found: %s\n", RPMB_PATH);
		return EMMC_RPMB;
	}

	if (stat(RPMB_LEGACY_PATH, &st) == 0) {
		RPMB_LOG_INFO("eMMC RPMB device found: %s\n", RPMB_LEGACY_PATH);
		return EMMC_RPMB;
	}

	return emmc_scan_dev();
}
