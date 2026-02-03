// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef __RPMB_MSG_H__
#define __RPMB_MSG_H__

#include <stdint.h>
#include <stdio.h>

#define MSGV printf
#define MSGE printf
#define MSGD(...)

/* Fixed. Don't increase the size of TZ_CM_MAX_NAME_LEN */
#define TZ_CM_MAX_NAME_LEN		256
#define TZ_CM_MAX_DATA_LEN		20000

#define TZ_MAX_BUF_LEN			(TZ_CM_MAX_DATA_LEN + 40)
#define RPMB_DATA_SIZE			256
#define RPMB_KEY_SIZE			32
#define RPMB_MAC_SIZE			32
#define RPMB_NONCE_SIZE			16
#define RPMB_MAX_FRAME_SIZE		512

#define UNUSED(x) (void)(x)

/* RPMB Service ID - matches listener_mngr.h */
#define RPMB_SERVICE_ID		0x2000

/* RPMB Request Types */
#define RPMB_REQ_AUTH_KEY_PROGRAM	0x0001
#define RPMB_REQ_WRITE_COUNTER_READ	0x0002
#define RPMB_REQ_AUTH_DATA_WRITE	0x0003
#define RPMB_REQ_AUTH_DATA_READ		0x0004
#define RPMB_REQ_RESULT_READ		0x0005

/* RPMB Response Types */
#define RPMB_RESP_AUTH_KEY_PROGRAM	0x0100
#define RPMB_RESP_WRITE_COUNTER_READ	0x0200
#define RPMB_RESP_AUTH_DATA_WRITE	0x0300
#define RPMB_RESP_AUTH_DATA_READ	0x0400

/* RPMB Result Codes */
#define RPMB_RESULT_OK			0x0000
#define RPMB_RESULT_GENERAL_FAILURE	0x0001
#define RPMB_RESULT_AUTH_FAILURE	0x0002
#define RPMB_RESULT_COUNTER_FAILURE	0x0003
#define RPMB_RESULT_ADDRESS_FAILURE	0x0004
#define RPMB_RESULT_WRITE_FAILURE	0x0005
#define RPMB_RESULT_READ_FAILURE	0x0006
#define RPMB_RESULT_AUTH_KEY_NOT_PROG	0x0007

/* RPMB Frame structure */
typedef struct tz_rpmb_frame {
	uint8_t stuff[196];		/* Stuff bytes */
	uint8_t key_mac[RPMB_MAC_SIZE];	/* Key/MAC */
	uint8_t data[RPMB_DATA_SIZE];	/* Data */
	uint8_t nonce[RPMB_NONCE_SIZE];	/* Nonce */
	uint32_t write_counter;		/* Write counter */
	uint16_t address;		/* Address */
	uint16_t block_count;		/* Block count */
	uint16_t result;		/* Result */
	uint16_t req_resp;		/* Request/Response */
} __attribute__ ((packed)) tz_rpmb_frame_t;

/* RPMB Device Info */
typedef struct tz_rpmb_device_info {
	char device_path[TZ_CM_MAX_NAME_LEN];	/* Device path */
	uint32_t rpmb_size_mult;		/* RPMB size multiplier */
	uint32_t rel_wr_sec_c;			/* Reliable write sector count */
	uint8_t rpmb_support;			/* RPMB support flag */
	uint8_t auth_method;			/* Authentication method */
} __attribute__ ((packed)) tz_rpmb_device_info_t;

typedef enum {
	TZ_RPMB_MSG_CMD_RPMB_START		= 0x00000501,
	TZ_RPMB_MSG_CMD_RPMB_PROGRAM_KEY,
	TZ_RPMB_MSG_CMD_RPMB_GET_WRITE_COUNTER,
	TZ_RPMB_MSG_CMD_RPMB_WRITE_DATA,
	TZ_RPMB_MSG_CMD_RPMB_READ_DATA,
	TZ_RPMB_MSG_CMD_RPMB_GET_DEVICE_INFO,
	TZ_RPMB_MSG_CMD_RPMB_VERIFY_KEY,
	TZ_RPMB_MSG_CMD_RPMB_SECURE_WRITE,
	TZ_RPMB_MSG_CMD_RPMB_SECURE_READ,
	TZ_RPMB_MSG_CMD_RPMB_END,
	TZ_RPMB_MSG_CMD_UNKNOWN			= 0x7FFFFFFF
} tz_rpmb_msg_cmd_type;

/* Command structure for programming RPMB key */
typedef struct tz_rpmb_program_key_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
	uint8_t key[RPMB_KEY_SIZE];
} __attribute__ ((packed)) tz_rpmb_program_key_req_t;

typedef struct tz_rpmb_program_key_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	uint16_t result;
	int ret;
} __attribute__ ((packed)) tz_rpmb_program_key_rsp_t;

/* Command structure for getting write counter */
typedef struct tz_rpmb_get_write_counter_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
	uint8_t nonce[RPMB_NONCE_SIZE];
} __attribute__ ((packed)) tz_rpmb_get_write_counter_req_t;

typedef struct tz_rpmb_get_write_counter_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	uint32_t write_counter;
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t mac[RPMB_MAC_SIZE];
	uint16_t result;
	int ret;
} __attribute__ ((packed)) tz_rpmb_get_write_counter_rsp_t;

/* Command structure for writing RPMB data */
typedef struct tz_rpmb_write_data_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
	uint16_t address;
	uint16_t block_count;
	uint8_t data[RPMB_DATA_SIZE];
	uint8_t key[RPMB_KEY_SIZE];
} __attribute__ ((packed)) tz_rpmb_write_data_req_t;

typedef struct tz_rpmb_write_data_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	uint32_t write_counter;
	uint16_t address;
	uint8_t mac[RPMB_MAC_SIZE];
	uint16_t result;
	int ret;
} __attribute__ ((packed)) tz_rpmb_write_data_rsp_t;

/* Command structure for reading RPMB data */
typedef struct tz_rpmb_read_data_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
	uint16_t address;
	uint16_t block_count;
	uint8_t nonce[RPMB_NONCE_SIZE];
} __attribute__ ((packed)) tz_rpmb_read_data_req_t;

typedef struct tz_rpmb_read_data_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	uint8_t data[RPMB_DATA_SIZE];
	uint16_t address;
	uint16_t block_count;
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t mac[RPMB_MAC_SIZE];
	uint16_t result;
	int ret;
} __attribute__ ((packed)) tz_rpmb_read_data_rsp_t;

/* Command structure for getting device info */
typedef struct tz_rpmb_get_device_info_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
} __attribute__ ((packed)) tz_rpmb_get_device_info_req_t;

typedef struct tz_rpmb_get_device_info_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	tz_rpmb_device_info_t device_info;
	int ret;
} __attribute__ ((packed)) tz_rpmb_get_device_info_rsp_t;

/* Command structure for verifying key */
typedef struct tz_rpmb_verify_key_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
	uint8_t key[RPMB_KEY_SIZE];
	uint8_t nonce[RPMB_NONCE_SIZE];
} __attribute__ ((packed)) tz_rpmb_verify_key_req_t;

typedef struct tz_rpmb_verify_key_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t mac[RPMB_MAC_SIZE];
	uint16_t result;
	int ret;
} __attribute__ ((packed)) tz_rpmb_verify_key_rsp_t;

/* Command structure for secure write */
typedef struct tz_rpmb_secure_write_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
	uint16_t address;
	uint16_t block_count;
	uint8_t data[RPMB_DATA_SIZE];
	uint8_t key[RPMB_KEY_SIZE];
	uint8_t nonce[RPMB_NONCE_SIZE];
} __attribute__ ((packed)) tz_rpmb_secure_write_req_t;

typedef struct tz_rpmb_secure_write_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	uint32_t write_counter;
	uint16_t address;
	uint8_t mac[RPMB_MAC_SIZE];
	uint16_t result;
	int ret;
} __attribute__ ((packed)) tz_rpmb_secure_write_rsp_t;

/* Command structure for secure read */
typedef struct tz_rpmb_secure_read_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
	char device_path[TZ_CM_MAX_NAME_LEN];
	uint16_t address;
	uint16_t block_count;
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t key[RPMB_KEY_SIZE];
} __attribute__ ((packed)) tz_rpmb_secure_read_req_t;

typedef struct tz_rpmb_secure_read_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	uint8_t data[RPMB_DATA_SIZE];
	uint16_t address;
	uint16_t block_count;
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t mac[RPMB_MAC_SIZE];
	uint16_t result;
	int ret;
} __attribute__ ((packed)) tz_rpmb_secure_read_rsp_t;

/* Command structure for RPMB end */
typedef struct tz_rpmb_end_req_s {
	tz_rpmb_msg_cmd_type cmd_id;
} __attribute__ ((packed)) tz_rpmb_end_req_t;

typedef struct tz_rpmb_end_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	int ret;
} __attribute__ ((packed)) tz_rpmb_end_rsp_t;

/* Error response structure */
typedef struct tz_rpmb_err_rsp_s {
	tz_rpmb_msg_cmd_type cmd_id;
	int ret;
} __attribute__ ((packed)) tz_rpmb_err_rsp_t;

#endif /* __RPMB_MSG_H__ */
