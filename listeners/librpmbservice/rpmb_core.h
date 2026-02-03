// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * RPMB Core Interface - Clean, Platform-Independent Implementation
 */

#ifndef __RPMB_CORE_H__
#define __RPMB_CORE_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* RPMB Constants */
#define RPMB_SECTOR_SIZE        256
#define RPMB_BLOCK_SIZE         512
#define RPMB_FRAME_SIZE         512
#define RPMB_MIN_BLOCK_COUNT    1

/* RPMB Device Types */
typedef enum {
	RPMB_DEVICE_NONE = 0,
	RPMB_DEVICE_EMMC,
	RPMB_DEVICE_UFS,
	RPMB_DEVICE_MAX
} rpmb_device_type_t;

/* RPMB Operation Results */
typedef enum {
	RPMB_RESULT_OK = 0,
	RPMB_RESULT_GENERAL_FAILURE,
	RPMB_RESULT_AUTH_FAILURE,
	RPMB_RESULT_COUNTER_FAILURE,
	RPMB_RESULT_ADDRESS_FAILURE,
	RPMB_RESULT_WRITE_FAILURE,
	RPMB_RESULT_READ_FAILURE,
	RPMB_RESULT_KEY_NOT_PROGRAMMED,
	RPMB_RESULT_INVALID_DEVICE = -1,
	RPMB_RESULT_NOT_INITIALIZED = -2,
	RPMB_RESULT_INVALID_PARAMETER = -3
} rpmb_result_t;

/* RPMB Device Information */
typedef struct {
	rpmb_device_type_t device_type;
	uint32_t size_sectors;          /* Size in 512-byte sectors */
	uint32_t reliable_write_count;  /* Max frames per operation */
	bool initialized;
} rpmb_device_info_t;

/* RPMB Context */
typedef struct {
	rpmb_device_info_t device_info;
	void *device_context;           /* Device-specific context */
	bool wakelock_initialized;
} rpmb_context_t;

/* RPMB Device Operations Interface */
typedef struct {
	/* Device initialization */
	rpmb_result_t (*init)(rpmb_device_info_t *info);

	/* Device cleanup */
	void (*cleanup)(void);

	/* RPMB read operation */
	rpmb_result_t (*read)(uint32_t *request_buf, uint32_t block_count,
			uint32_t *response_buf, uint32_t *response_len);

	/* RPMB write operation */
	rpmb_result_t (*write)(uint32_t *request_buf, uint32_t block_count,
			uint32_t *response_buf, uint32_t *response_len,
			uint32_t frames_per_operation);
} rpmb_device_ops_t;

/* Core RPMB API */

/**
 * Initialize RPMB subsystem
 * @param info: Device information structure to fill
 * @return: RPMB_RESULT_OK on success, error code otherwise
 */
rpmb_result_t rpmb_core_init(rpmb_device_info_t *info);

/**
 * Cleanup RPMB subsystem
 */
void rpmb_core_cleanup(void);

/**
 * Read data from RPMB device
 * @param request_buf: RPMB request frames
 * @param block_count: Number of blocks to read
 * @param response_buf: Buffer for response frames
 * @param response_len: Length of response data (output)
 * @return: RPMB_RESULT_OK on success, error code otherwise
 */
rpmb_result_t rpmb_core_read(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len);

/**
 * Write data to RPMB device
 * @param request_buf: RPMB request frames
 * @param block_count: Number of blocks to write
 * @param response_buf: Buffer for response frames
 * @param response_len: Length of response data (output)
 * @param frames_per_operation: Frames per RPMB operation
 * @return: RPMB_RESULT_OK on success, error code otherwise
 */
rpmb_result_t rpmb_core_write(uint32_t *request_buf, uint32_t block_count,
		uint32_t *response_buf, uint32_t *response_len,
		uint32_t frames_per_operation);

/**
 * Get current device information
 * @param info: Device information structure to fill
 * @return: RPMB_RESULT_OK on success, error code otherwise
 */
rpmb_result_t rpmb_core_get_device_info(rpmb_device_info_t *info);

/* Device Detection API */

/**
 * Detect available RPMB device
 * @return: Device type, RPMB_DEVICE_NONE if no device found
 */
rpmb_device_type_t rpmb_detect_device(void);

/* Utility Functions */

/**
 * Convert device type to string
 * @param device_type: Device type
 * @return: String representation
 */
const char *rpmb_device_type_to_string(rpmb_device_type_t device_type);

/**
 * Convert result code to string
 * @param result: Result code
 * @return: String representation
 */
const char *rpmb_result_to_string(rpmb_result_t result);

#endif /* __RPMB_CORE_H__ */
