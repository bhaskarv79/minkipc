// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef _SMCINVOKE_CLIENT_H_
#define _SMCINVOKE_CLIENT_H_

#include <object.h>
#include <stdio.h>

#define SIZE_4KB 0x00001000

enum {
	attr_uid = 1,
	attr_pkg_flags,
	attr_pkg_name,
	attr_pkg_cert,
	attr_permissions,
	attr_system_time,
};

#define CREDENTIALS_BUF_SIZE_INC 4096

/* Private handle to memory shared with QTEE */
struct smcinvoke_priv_handle {
	void *addr;
	size_t size;
};

#define CLIENT_CMD5_RUN_GPFS_TEST 5
#define CLIENT_CMD6_RUN_FS_TEST   6
#define CLIENT_CMD14_RUN_RPMB_PROV 14
#define CLIENT_CMD15_RUN_RPMB_ERASE 15
#define CLIENT_CMD17_RUN_RPMB_RW 17

#define SMCINVOKE_TEST_NOT_IMPLEMENTED 0xFFFF

struct qsc_send_cmd {
    uint32_t cmd_id;
    uint32_t data;
    uint32_t data2;
    uint32_t len;
    uint32_t start_pkt;
    uint32_t end_pkt;
    uint32_t test_buf_size;
};

struct qsc_send_cmd_64bit {
     uint32_t cmd_id;
     uint64_t data;
     uint64_t data2;
     uint32_t len;
     uint32_t start_pkt;
     uint32_t end_pkt;
     uint32_t test_buf_size;
};

struct qsc_send_cmd_rsp {
  uint32_t data;
  int32_t status;
};

enum test_types {
	INTERNAL,
	CALLBACKOBJ,
	MEMORYOBJ,
	PRINT_TZ_DIAGNOSTICS,
};

struct option testopts[] = {
	{"internal", no_argument, NULL, 'i'},
	{"callbackobj", no_argument, NULL, 'c'},
	{"memoryobj", no_argument, NULL, 'm'},
	{"diagnostics", no_argument, NULL, 'd'},
	{NULL, 0, NULL, 0},
};

#endif /* _SMCINVOKE_CLIENT_H_ */
