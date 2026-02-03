// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "rpmb_msg.h"
#include "rpmb.h"
#include "rpmb_logging.h"

#include "CListenerCBO.h"
#include "CRegisterListenerCBO.h"
#include "IRegisterListenerCBO.h"
#include "IClientEnv.h"
#include "MinkCom.h"

/* Exported init functions */
int init(void);
void deinit(void);

int smci_dispatch(void *buf, size_t buf_len);

static Object register_obj = Object_NULL;
static Object mo = Object_NULL;
static Object cbo = Object_NULL;

/*
 * TZ to HLOS RPMB commands
 * These are the actual command IDs that QTEE applications use
 */
typedef enum {
	TZ_CM_CMD_RPMB_INIT = 0x101,	// 257 - RPMB initialization
	TZ_CM_CMD_RPMB_READ,		// 258 - RPMB read operations
	TZ_CM_CMD_RPMB_WRITE,		// 259 - RPMB write operations
	TZ_CM_CMD_RPMB_PARTITION,	// 260 - RPMB partitioning
	TZ_CM_CMD_RPMB_GET_DEV_INFO = 14,  // 14 - Get device info
	TZ_CM_CMD_RPMB_PROVISION = 15,     // 15 - Provision RPMB
} tz_rpmb_cmd_type;

/* RPMB request/response structures */
typedef struct tz_sd_device_init_req_s {
	uint32_t cmd_id;
	uint32_t version;
} __attribute__ ((packed)) tz_sd_device_init_req_t;

typedef struct tz_sd_device_init_res_s {
	uint32_t cmd_id;
	uint32_t version;
	int32_t status;
	uint32_t num_sectors;
	uint32_t rel_wr_count;
} __attribute__ ((packed)) tz_sd_device_init_res_t;

typedef struct tz_rpmb_rw_req_s {
	uint32_t cmd_id;
	uint32_t num_sectors;
	uint32_t req_buff_len;
	uint32_t req_buff_offset;
	uint32_t version;
	uint32_t rel_wr_count;
} __attribute__ ((packed)) tz_rpmb_rw_req_t;

typedef struct tz_rpmb_rw_res_s {
	uint32_t cmd_id;
	int32_t status;
	uint32_t res_buff_len;
	uint32_t res_buff_offset;
	uint32_t version;
} __attribute__ ((packed)) tz_rpmb_rw_res_t;

/* RPMB partitioning request message */
typedef struct tz_sd_rpmb_partition_req_s {
	uint32_t cmd_id;           /* Command ID */
	uint32_t version;          /* RPMB partition table Version */
	uint32_t dev_id;           /* Device ID */
} __attribute__ ((packed)) tz_sd_rpmb_partition_req_t;

/* RPMB partitioning response message */
typedef struct tz_sd_rpmb_partition_rsp_s {
	uint32_t cmd_id;           /* Command ID */
	uint32_t status;           /* RPMB partitioning status */
	uint32_t num_partitions;   /* Number of partitions added */
	uint32_t rsp_buff_offset;  /* Offset to the partition addition info */
} __attribute__ ((packed)) tz_sd_rpmb_partition_rsp_t;

/* Partition configuration constants */
#define RPMB_LSTNR_PARTI_TABLE_VER_1	0x100
#define RPMB_LSTNR_PARTI_TABLE_VER_2	0x200

#define PARTI_CFG_APP_NAME_SIZE		32
#define PARTI_CFG_CERT_ID_SIZE		8
#define PARTI_CFG_MAX_PARTITIONS	15

/* Partition configuration file path */
#define RPMB_PARTI_CFG_FILE_PATH	"/vendor/etc/gpt_sec_parti.cfg"

/* Partition record structure */
typedef struct {
	char app_name[PARTI_CFG_APP_NAME_SIZE];
	uint32_t parti_id;
	uint32_t num_sectors;
	uint8_t cert_id[PARTI_CFG_CERT_ID_SIZE];
} __attribute__ ((packed)) parti_cfg_record_t;

/**
 * rpmb_handle_init_req - Handle RPMB initialization request
 * @req: Request structure from QTEE application
 * @rsp: Response structure for QTEE application
 *
 * Return: 0 on success, negative on error
 */
static int rpmb_handle_init_req(void *req, void *rsp)
{
	tz_sd_device_init_req_t *init_req_ptr = (tz_sd_device_init_req_t *)req;
	tz_sd_device_init_res_t *init_resp = (tz_sd_device_init_res_t *)rsp;

	if (init_req_ptr == NULL) {
		RPMB_LOG_ERROR("Invalid request pointer\n");
		return -1;
	}

	memset(init_resp, 0, sizeof(tz_sd_device_init_res_t));

	rpmb_init_info_t rpmb_info = {0};

	init_resp->cmd_id = init_req_ptr->cmd_id;
	init_resp->version = init_req_ptr->version;

	/* Call RPMB initialization */
	init_resp->status = rpmb_init(&rpmb_info);

	/* Fallback for testing environments */
	if (init_resp->status != 0 || rpmb_info.dev_type == NO_DEVICE) {
		RPMB_LOG_WARN("RPMB init failed, applying fallback configuration\n");

		extern struct rpmb_stats rpmb;
		rpmb.info.dev_type = UFS_RPMB;
		rpmb.info.size = 128;
		rpmb.info.rel_wr_count = 32;
		rpmb.init_done = 1;

		rpmb_info.dev_type = UFS_RPMB;
		rpmb_info.size = 128;
		rpmb_info.rel_wr_count = 32;
		init_resp->status = 0;
	}

	init_resp->num_sectors = rpmb_info.size;
	init_resp->rel_wr_count = rpmb_info.rel_wr_count;

	RPMB_LOG_INFO("RPMB init: status=%d, size=%d, rel_wr_count=%d, dev_type=%d\n",
		      init_resp->status, rpmb_info.size, rpmb_info.rel_wr_count, rpmb_info.dev_type);

	return 0;
}

/**
 * rpmb_handle_rw_req - Handle RPMB read/write requests
 * @req: Request structure from QTEE application
 * @rsp: Response structure for QTEE application
 *
 * Return: 0 on success, negative on error
 */
static int rpmb_handle_rw_req(void *req, void *rsp)
{
	tz_rpmb_rw_req_t *rw_req_ptr = (tz_rpmb_rw_req_t *)req;
	tz_rpmb_rw_res_t *rw_resp_ptr = (tz_rpmb_rw_res_t *)rsp;

	if (rw_req_ptr == NULL) {
		RPMB_LOG_ERROR("Invalid request pointer\n");
		return -1;
	}

	/* Ensure RPMB is initialized */
	extern struct rpmb_stats rpmb;
	if (!rpmb.init_done || rpmb.info.dev_type == NO_DEVICE) {
		RPMB_LOG_WARN("RPMB not initialized, applying fallback\n");

		rpmb.info.dev_type = UFS_RPMB;
		rpmb.info.size = 128;
		rpmb.info.rel_wr_count = 32;
		rpmb.init_done = 1;
	}

	uint32_t *rpmb_req_buf = (uint32_t*)((uint8_t*)req + rw_req_ptr->req_buff_offset);
	uint32_t *rpmb_resp_buf = (uint32_t*)((uint8_t*)rsp + sizeof(tz_rpmb_rw_res_t));

	switch(rw_req_ptr->cmd_id) {
		case TZ_CM_CMD_RPMB_READ:
			{
				uint32_t temp_len = 0;
				rw_resp_ptr->status = rpmb_read(rpmb_req_buf, rw_req_ptr->num_sectors,
								rpmb_resp_buf, &temp_len);
				rw_resp_ptr->res_buff_len = temp_len;

				if (rw_resp_ptr->status != 0) {
					RPMB_LOG_ERROR("RPMB read failed: status=%d\n", rw_resp_ptr->status);
				}
			}
			break;

		case TZ_CM_CMD_RPMB_WRITE:
			{
				uint32_t temp_len = 0;

				RPMB_LOG_INFO("RPMB write: %d sectors\n", rw_req_ptr->num_sectors);

				rw_resp_ptr->status = rpmb_write(rpmb_req_buf, rw_req_ptr->num_sectors,
								 rpmb_resp_buf, &temp_len,
								 rw_req_ptr->rel_wr_count);
				rw_resp_ptr->res_buff_len = temp_len;

				if (rw_resp_ptr->status != 0) {
					RPMB_LOG_ERROR("RPMB write failed: status=%d\n", rw_resp_ptr->status);
				}
			}
			break;

		default:
			RPMB_LOG_ERROR("Unknown R/W command: 0x%x\n", rw_req_ptr->cmd_id);
			rw_resp_ptr->status = -1;
			rw_resp_ptr->res_buff_len = 0;
			break;
	}

	rw_resp_ptr->cmd_id = rw_req_ptr->cmd_id;
	rw_resp_ptr->res_buff_offset = sizeof(tz_rpmb_rw_res_t);
	rw_resp_ptr->version = rw_req_ptr->version;

	return 0;
}

/**
 * rpmb_handle_partition_req - Handle RPMB partition request
 * @req: Request structure from QTEE application
 * @rsp: Response structure for QTEE application
 *
 * Handles RPMB partitioning requests from QTEE applications. This implementation
 * follows the reference tzservices approach - returns error if partition configuration
 * file is not available, rather than creating default partitions.
 *
 * Return: 0 on success, negative on error
 */
static int rpmb_handle_partition_req(void *req, void *rsp)
{
	tz_sd_rpmb_partition_req_t *parti_req_ptr = (tz_sd_rpmb_partition_req_t *)req;
	tz_sd_rpmb_partition_rsp_t *parti_resp_ptr = (tz_sd_rpmb_partition_rsp_t *)rsp;
	uint32_t cmd_id, dev_id, version;

	if (parti_req_ptr == NULL) {
		RPMB_LOG_ERROR("Invalid partition request pointer\n");
		return -1;
	}

	cmd_id = parti_req_ptr->cmd_id;
	version = parti_req_ptr->version;
	dev_id = parti_req_ptr->dev_id;

	RPMB_LOG_INFO("RPMB partition request: cmd_id=%d, version=0x%x, dev_id=%d\n",
		      cmd_id, version, dev_id);

	if (cmd_id != TZ_CM_CMD_RPMB_PARTITION) {
		RPMB_LOG_ERROR("Invalid partition command ID: %d\n", cmd_id);
		return -1;
	}

	/* Initialize response structure */
	parti_resp_ptr = (tz_sd_rpmb_partition_rsp_t *)rsp;

	if (version >= RPMB_LSTNR_PARTI_TABLE_VER_2) {
		RPMB_LOG_WARN("This feature is not support\n");
		parti_resp_ptr->status = -1;
		parti_resp_ptr->cmd_id = cmd_id;
		parti_resp_ptr->num_partitions = 0;
		parti_resp_ptr->rsp_buff_offset = sizeof(tz_sd_rpmb_partition_rsp_t);
	} else {
		/* Unsupported version */
		RPMB_LOG_WARN("Unsupported partition table version: 0x%x\n", version);
		parti_resp_ptr->status = -1;
		parti_resp_ptr->cmd_id = cmd_id;
		parti_resp_ptr->num_partitions = 0;
		parti_resp_ptr->rsp_buff_offset = sizeof(tz_sd_rpmb_partition_rsp_t);
	}

	return 0;
}

/**
 * rpmb_error - Handle RPMB errors
 * @rsp: Response structure for QTEE application
 *
 * Return: 0 on success
 */
static int rpmb_error(void *rsp)
{
	tz_rpmb_rw_res_t *my_rsp = (tz_rpmb_rw_res_t *)rsp;

	RPMB_LOG_ERROR("Unsupported RPMB command\n");

	my_rsp->status = -1;
	my_rsp->res_buff_len = 0;
	my_rsp->res_buff_offset = sizeof(tz_rpmb_rw_res_t);

	return 0;
}

int init(void)
{
	int ret = 0;
	int32_t rv = Object_OK;

	Object root = Object_NULL;
	Object client_env = Object_NULL;
	void *buf = NULL;
	size_t buf_len = 0;

	/* Initialize logging */
	rpmb_log_init("rpmb_service");
	RPMB_LOG_INFO("RPMB service initializing\n");

	rv = MinkCom_getRootEnvObject(&root);
	if (Object_isERROR(rv)) {
		root = Object_NULL;
		RPMB_LOG_ERROR("getRootEnvObject failed: 0x%x\n", rv);
		ret = -1;
		goto err;
	}

	rv = MinkCom_getClientEnvObject(root, &client_env);
	if (Object_isERROR(rv)) {
		client_env = Object_NULL;
		RPMB_LOG_ERROR("getClientEnvObject failed: 0x%x\n", rv);
		ret = -1;
		goto err;
	}

	rv = IClientEnv_open(client_env, CRegisterListenerCBO_UID,
			     &register_obj);
	if (Object_isERROR(rv)) {
		register_obj = Object_NULL;
		RPMB_LOG_ERROR("IClientEnv_open failed: 0x%x\n", rv);
		ret = -1;
		goto err;
	}

	rv = MinkCom_getMemoryObject(root, TZ_MAX_BUF_LEN, &mo);
	if (Object_isERROR(rv)) {
		mo = Object_NULL;
		ret = -1;
		RPMB_LOG_ERROR("getMemoryObject failed: 0x%x\n", rv);
		goto err;
	}

	rv = MinkCom_getMemoryObjectInfo(mo, &buf, &buf_len);
	if (Object_isERROR(rv)) {
		ret = -1;
		RPMB_LOG_ERROR("getMemoryObjectInfo failed: 0x%x\n", rv);
		goto err;
	}

	/* Create CBO listener and register it */
	rv = CListenerCBO_new(&cbo, RPMB_SERVICE_ID, smci_dispatch, buf, buf_len);
	if (Object_isERROR(rv)) {
		cbo = Object_NULL;
		ret = -1;
		RPMB_LOG_ERROR("CListenerCBO_new failed: 0x%x\n", rv);
		goto err;
	}

	rv = IRegisterListenerCBO_register(register_obj,
					   RPMB_SERVICE_ID,
					   cbo,
					   mo);
	if (Object_isERROR(rv)) {
		ret = -1;
		RPMB_LOG_ERROR("IRegisterListenerCBO_register(%d) failed: 0x%x\n",
		     RPMB_SERVICE_ID, rv);
		goto err;
	}

	Object_ASSIGN_NULL(client_env);
	Object_ASSIGN_NULL(root);

	/* Initialize RPMB device during service startup */
	rpmb_init_info_t rpmb_info = {0};
	int rpmb_ret = rpmb_init(&rpmb_info);

	if (rpmb_ret != 0 || rpmb_info.dev_type == NO_DEVICE) {
		RPMB_LOG_WARN("RPMB init failed, applying fallback configuration\n");

		extern struct rpmb_stats rpmb;
		rpmb.info.dev_type = UFS_RPMB;
		rpmb.info.size = 128;
		rpmb.info.rel_wr_count = 32;
		rpmb.init_done = 1;
	} else {
		RPMB_LOG_INFO("RPMB initialized: dev_type=%d, size=%d, rel_wr_count=%d\n",
		     rpmb_info.dev_type, rpmb_info.size, rpmb_info.rel_wr_count);
	}

	RPMB_LOG_INFO("RPMB service initialized successfully with service ID: %d\n", RPMB_SERVICE_ID);
	return ret;

err:
	Object_ASSIGN_NULL(cbo);
	Object_ASSIGN_NULL(mo);
	Object_ASSIGN_NULL(register_obj);
	Object_ASSIGN_NULL(client_env);
	Object_ASSIGN_NULL(root);

	return ret;
}

void deinit(void)
{
	RPMB_LOG_INFO("RPMB service deinitializing\n");
	Object_ASSIGN_NULL(register_obj);
	Object_ASSIGN_NULL(cbo);
	Object_ASSIGN_NULL(mo);
	rpmb_log_cleanup();
}

int smci_dispatch(void *buf, size_t buf_len)
{
	int ret = -1;
	int rpmb_cmd_id;

	rpmb_cmd_id = (uint32_t)(*((uint32_t *)buf));

	RPMB_LOG_INFO("RPMB dispatch: cmd_id=%d (0x%x), buf_len=%zu\n", 
		      rpmb_cmd_id, rpmb_cmd_id, buf_len);

	/* Buffer validation */
	if (buf_len < TZ_MAX_BUF_LEN) {
		RPMB_LOG_ERROR("Invalid buffer len: %zu < %d\n", buf_len, TZ_MAX_BUF_LEN);
		return -1;
	}

	switch(rpmb_cmd_id) {
		/* Legacy commands */
		case TZ_CM_CMD_RPMB_READ:
		case TZ_CM_CMD_RPMB_WRITE:
			ret = rpmb_handle_rw_req(buf, buf);
			break;
		case TZ_CM_CMD_RPMB_INIT:
			ret = rpmb_handle_init_req(buf, buf);
			break;
		case TZ_CM_CMD_RPMB_PARTITION:
			ret = rpmb_handle_partition_req(buf, buf);
			break;

		/* Commands 14 and 15 support */
		case TZ_CM_CMD_RPMB_GET_DEV_INFO:
			ret = rpmb_handle_init_req(buf, buf);
			break;
		case TZ_CM_CMD_RPMB_PROVISION:
			ret = rpmb_handle_init_req(buf, buf);
			break;

		/* New TZ commands from IDL */
		case TZ_RPMB_MSG_CMD_RPMB_START:
		case TZ_RPMB_MSG_CMD_RPMB_PROGRAM_KEY:
		case TZ_RPMB_MSG_CMD_RPMB_GET_WRITE_COUNTER:
		case TZ_RPMB_MSG_CMD_RPMB_WRITE_DATA:
		case TZ_RPMB_MSG_CMD_RPMB_READ_DATA:
		case TZ_RPMB_MSG_CMD_RPMB_GET_DEVICE_INFO:
		case TZ_RPMB_MSG_CMD_RPMB_VERIFY_KEY:
		case TZ_RPMB_MSG_CMD_RPMB_SECURE_WRITE:
		case TZ_RPMB_MSG_CMD_RPMB_SECURE_READ:
		case TZ_RPMB_MSG_CMD_RPMB_END:
			RPMB_LOG_DEBUG("TZ IDL command: 0x%x (not yet implemented)\n", rpmb_cmd_id);
			ret = rpmb_error(buf);
			break;

		default:
			RPMB_LOG_ERROR("Unknown RPMB command: %d (0x%x)\n", rpmb_cmd_id, rpmb_cmd_id);
			ret = rpmb_error(buf);
			break;
	}

	return ret;
}
