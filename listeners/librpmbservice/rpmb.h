// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __RPMB_H__
#define __RPMB_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <syslog.h>
#include <string.h>

/* As described in JEDEC eMMC 4.5 spec && JEDEC UFS 2.0 spec*/
#define RPMB_SECTOR_SIZE	256

#define RPMB_BLK_SIZE		512
#define RPMB_MIN_BLK_CNT	1

/* countof is meant only for array's not for pointers */
#define countof(a)                      (sizeof(a) / sizeof(*(a)))

/* Storage Device Types - should match with secure component */
typedef enum {
	EMMC_USER = 0,         /* User Partition in eMMC */
	EMMC_BOOT1,            /* Boot1 Partition in eMMC */
	EMMC_BOOT0,            /* Boot2 Partition in eMMC */
	EMMC_RPMB,             /* RPMB Partition in eMMC */
	EMMC_GPP1,             /* GPP1 Partition in eMMC */
	EMMC_GPP2,             /* GPP2 Partition in eMMC */
	EMMC_GPP3,             /* GPP3 Partition in eMMC */
	EMMC_GPP4,             /* GPP4 Partition in eMMC */
	EMMC_ALL,              /* Entire eMMC device */
	UFS_RPMB,              /* RPMB Partition in UFS device */
	UFS_ALL,               /* Entire UFS device */
	NO_DEVICE = 0x7FFFFFFF
} device_id_type;

/* RPMB request type */
enum request_type {
	KEY_PROVISION = 0x01,
	READ_WRITE_COUNTER,
	AUTH_WRITE,
	AUTH_READ,
	READ_RESULT_REG,
};

/* operation results via read result register */
enum rpmb_result {
	OPERATION_OK = 0x0,
	GENERAL_FAILURE,
	AUTH_FAILURE,
	COUNTER_FAILURE,
	ADDRESS_FAILURE,
	WRITE_FAILURE,
	READ_FAILURE,
	KEY_NOT_PROG,
	MAXED_WR_COUNTER = 0x80,
};


/**
 * struct rpmb_frame - RPMB data frame as defined by JEDEC specification
 *
 * This structure matches the RPMB frame format defined in:
 * - JEDEC eMMC 4.5 specification
 * - JEDEC UFS 2.0 specification
 *
 * Field names use snake_case per Linux kernel coding standards.
 * Hardware spec names are noted in comments for reference.
 *
 * @stuff_bytes: Padding bytes
 * @key_mac: Message Authentication Code (hardware spec: "Key/MAC")
 * @data: Data payload
 * @nonce: Random number for replay protection
 * @write_counter: Write counter value (hardware spec: "Write Counter")
 * @address: Block address
 * @block_count: Number of blocks (hardware spec: "Block Count")
 * @result: Operation result code
 * @request_response: Request/Response type (hardware spec: "Req/Resp")
 */
struct rpmb_frame {
	uint8_t stuff_bytes[196];
	uint8_t key_mac[32];
	uint8_t data[256];
	uint8_t nonce[16];
	uint8_t write_counter[4];
	uint8_t address[2];
	uint8_t block_count[2];
	uint8_t result[2];
	uint8_t request_response[2];
};

typedef struct rpmb_init_info {
	uint32_t size;		/* size of rpmb partition */
	uint32_t rel_wr_count;	/* reliable write sector count */
	uint32_t dev_type;	/* RPMB device type */
	uint32_t reserved;
} rpmb_init_info_t;

struct rpmb_stats {
	int fd;			/* file descriptor for the rpmb partition device file */
	int fd_ufs_bsg;		/* file descriptor ofor the ufs bsg device file */
	int init_done;		/* rpmb initialization done */
	rpmb_init_info_t info;
};
extern struct rpmb_stats rpmb;

/* will hold the result register read rpmb frame */
static struct rpmb_frame read_result_reg_frame __attribute__((unused)) = {
	.request_response[1] = READ_RESULT_REG,
};


/**
 * rpmb_init - Initialize RPMB partition
 * @rpmb_info: Pointer to be filled with RPMB init info
 *
 * This function checks for the presence of RPMB partition and if present,
 * will send size of the RPMB partition and reliable sector count information
 * back to the caller.
 *
 * Return: 0 on success, non-zero error on failure (passed to secure world
 *         via status field in tz_sd_device_init_res_t response structure)
 */
int rpmb_init(rpmb_init_info_t *rpmb_info);

/**
 * rpmb_default_init - Default RPMB initialization when no device is detected
 * @rpmb_info: Pointer to be filled with default RPMB init info
 *
 * Return: 0 on success, non-zero error on failure
 */
int rpmb_default_init(rpmb_init_info_t *rpmb_info);

/**
 * rpmb_exit - Clean up RPMB resources
 *
 * Meant to be used only with the rpmb_tester app to clean up as
 * rpmb_init can be called multiple times.
 */
void rpmb_exit(void);

/**
 * rpmb_read - Read data from RPMB partition
 * @req_buf: RPMB frames from secure world (passed via tz_rpmb_rw_req_t
 *           structure's req_buff_offset field)
 * @blk_cnt: Number of blocks to be read (passed via tz_rpmb_rw_req_t
 *           structure's num_sectors field)
 * @resp_buf: Pointer to buffer where RPMB frames from device will be stored
 *            (calculated by listener from tz_rpmb_rw_req_t structure's
 *            req_buff_offset and req_buff_len fields)
 * @resp_len: Size of data in resp_buf buffer (will be filled after function
 *            call and passed back to secure world via tz_rpmb_rw_res_t
 *            structure's res_buff_len field)
 *
 * This function reads (blk_cnt * 256) bytes of data from RPMB partition.
 *
 * Return: 0 on success, non-zero error on failure (passed to secure world
 *         via status field in tz_rpmb_rw_res_t response structure)
 */
int rpmb_read(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf, uint32_t *resp_len);

/**
 * rpmb_write - Write data to RPMB partition
 * @req_buf: RPMB frames from secure world (passed via tz_rpmb_rw_req_t
 *           structure's req_buff_offset field)
 * @blk_cnt: Number of blocks to be written (passed via tz_rpmb_rw_req_t
 *           structure's num_sectors field)
 * @resp_buf: Pointer to buffer where RPMB frames from device will be stored
 *            (calculated by listener from tz_rpmb_rw_req_t structure's
 *            req_buff_offset and req_buff_len fields)
 * @resp_len: Size of data in resp_buf buffer (will be filled after function
 *            call and passed back to secure world via tz_rpmb_rw_res_t
 *            structure's res_buff_len field)
 * @frames_per_rpmb_op: Number of frames for which MAC has been calculated
 *                      (passed from secure world via tz_rpmb_rw_req_t
 *                      structure's rel_wr_cnt field)
 *
 * This function writes (blk_cnt * 256) bytes of data to RPMB partition.
 * The frames_per_rpmb_op parameter indicates how many frames need to be
 * sent as part of a single RPMB operation.
 *
 * Return: 0 on success, non-zero error on failure (passed to secure world
 *         via status field in tz_rpmb_rw_res_t response structure)
 */
int rpmb_write(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf, uint32_t *resp_len,
		uint32_t frames_per_rpmb_op);

/*
 * eMMC rpmb functions. These are meant to be called by the rpmb wrapper
 * functions above based on the rpmb device.
 */
int rpmb_emmc_init(rpmb_init_info_t *rpmb_info);
int rpmb_emmc_read(uint32_t *req_buf, uint32_t blk_cnt,
		uint32_t *resp_buf, uint32_t *resp_len);
int rpmb_emmc_write(uint32_t *req_buf, uint32_t blk_cnt,
		uint32_t *resp_buf, uint32_t *resp_len,
		uint32_t frames_per_rpmb_op);
void rpmb_emmc_exit(void);

/*
 * UFS rpmb functions. These are meant to be called by the rpmb wrapper
 * functions above based on the rpmb device.
 */
int32_t rpmb_ufs_init(rpmb_init_info_t *rpmb_info);
int32_t rpmb_ufs_read(uint32_t *req_buf, uint32_t blk_cnt,
		uint32_t *resp_buf, uint32_t *resp_len);
int32_t rpmb_ufs_write(uint32_t *req_buf, uint32_t blk_cnt,
		uint32_t *resp_buf, uint32_t *resp_len,
		uint32_t frames_per_rpmb_op);
void rpmb_ufs_exit(void);

/*
 * RPMB Wakelock functions. Prevent system suspend during RPMB operations.
 * UFS and eMMC share these functions.
 */
void rpmb_wakelock(void);
void rpmb_wakeunlock(void);
void rpmb_init_wakelock(void);

#endif /* __RPMB_H__ */
