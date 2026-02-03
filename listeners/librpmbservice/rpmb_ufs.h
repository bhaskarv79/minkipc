// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __RPMB_UFS_H__
#define __RPMB_UFS_H__

#include <linux/bsg.h>
#include <scsi/scsi_bsg_ufs.h>
#include <endian.h>
#include <dirent.h>
#include <string.h>

/* Unified system definitions */
#define AID_SYSTEM 1000

#ifndef __u32
#define __u32 uint32_t
#endif

#define SCSI_REQ_SENSE_CDB_LEN	6
#define SCSI_REQ_SENSE_ID	0x03
#define SCSI_REQ_SENSE_BUF_LEN	18

#define SCSI_SEC_CDB_LEN	12
#define SCSI_SEC_IN_ID		0xA2
#define SCSI_SEC_OUT_ID		0xB5
#define SCSI_SEC_PROT		0xEC
#define SCSI_SEC_UFS_PROT_ID	0x0001
#define SENSE_BUF_LEN		96
#define RPMB_FRAME_SIZE		512
#define SCSI_TIMEOUT		30000

#define FNAME_SZ 64
#define DESC_DATA_SIZE 32

#define UPIU_RPMB_LUN	0xC4

#define SG_IO	0x2285

#define DWORD(b3, b2, b1, b0) htobe32((b3 << 24) | (b2 << 16) |\
					 (b1 << 8) | b0)

/* UFS BSG device nodes - unified paths */
char ufs_bsg_dev[FNAME_SZ] = "/dev/bsg/ufs-bsg0";

/* RPMB BSG device node - unified path */
char rpmb_bsg_dev[] = "/dev/bsg/0:0:0:49476";

/* UPIU Transaction Codes */
enum {
	UTP_UPIU_NOP_OUT	= 0x00,
	UTP_UPIU_COMMAND	= 0x01,
	UTP_UPIU_DATA_OUT	= 0x02,
	UTP_UPIU_TASK_REQ	= 0x04,
	UTP_UPIU_QUERY_REQ	= 0x16,
};

/* UPIU Query Function field */
enum {
	QUERY_REQ_FUNC_STD_READ		= 0x01,
	QUERY_REQ_FUNC_STD_WRITE	= 0x81,
};

enum query_req_opcode {
	QUERY_REQ_OP_READ_DESC		= 0x1,
	QUERY_REQ_OP_WRITE_DESC		= 0x2,
	QUERY_REQ_OP_READ_ATTR		= 0x3,
	QUERY_REQ_OP_WRITE_ATTR		= 0x4,
	QUERY_REQ_OP_READ_FLAG		= 0x5,
	QUERY_REQ_OP_SET_FLAG		= 0x6,
	QUERY_REQ_OP_CLEAR_FLAG		= 0x7,
	QUERY_REQ_OP_TOGGLE_FLAG	= 0x8,
};

enum query_desc_idn {
	QUERY_DESC_IDN_DEVICE	= 0x0,
	QUERY_DESC_IDN_UNIT	= 0x2,
	QUERY_DESC_IDN_GEOMETRY	= 0x7,
};

enum query_desc_size {
	QUERY_DESC_SIZE_DEVICE		= 0x40,
	QUERY_DESC_SIZE_GEOMETRY	= 0x48,
	QUERY_DESC_SIZE_UNIT		= 0x23,
};

enum bsg_ioctl_dir {
	BSG_IOCTL_DIR_TO_DEV,
	BSG_IOCTL_DIR_FROM_DEV,
};

/* Function prototypes */
int ufs_bsg_dev_open(void);
void ufs_bsg_dev_close(void);
int rpmb_bsg_dev_open(void);
void rpmb_bsg_dev_close(void);
int rpmb_ufs_send_request_sense(void);

#endif /* __RPMB_UFS_H__ */
