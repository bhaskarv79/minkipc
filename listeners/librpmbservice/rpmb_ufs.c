// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

#define LOG_TAG "rpmb_ufs"

#include "rpmb.h"
#include "rpmb_ufs.h"
#include "rpmb_core.h"
#include "rpmb_logging.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* Utility macros */
#define UNUSED(x) ((void)(x))

static int get_ufs_bsg_dev(void)
{
	DIR *dir;
	struct dirent *ent;
	int ret = -ENODEV;

	/* Try /dev/bsg first (unified approach) */
	dir = opendir("/dev/bsg");
	if (dir != NULL) {
		/* read all the files and directories within directory */
		while ((ent = readdir(dir)) != NULL) {
			if (!strcmp(ent->d_name, "ufs-bsg") ||
			    !strcmp(ent->d_name, "ufs-bsg0")) {
				strncpy(ufs_bsg_dev, "/dev/bsg/", FNAME_SZ - 1);
				strncat(ufs_bsg_dev, ent->d_name, FNAME_SZ - strlen(ufs_bsg_dev) - 1);
				ufs_bsg_dev[FNAME_SZ - 1] = '\0';
				ret = 0;
				break;
			}
		}
		closedir(dir);
	}

	/* Fallback to /dev if not found in /dev/bsg */
	if (ret != 0) {
		dir = opendir("/dev");
		if (dir != NULL) {
			while ((ent = readdir(dir)) != NULL) {
				if (!strcmp(ent->d_name, "ufs-bsg") ||
				    !strcmp(ent->d_name, "ufs-bsg0")) {
					strncpy(ufs_bsg_dev, "/dev/", FNAME_SZ - 1);
					strncat(ufs_bsg_dev, ent->d_name, FNAME_SZ - strlen(ufs_bsg_dev) - 1);
					ufs_bsg_dev[FNAME_SZ - 1] = '\0';
					ret = 0;
					break;
				}
			}
			closedir(dir);
		} else {
			RPMB_LOG_ERROR("could not open /dev or /dev/bsg (error no: %d)\n", errno);
			ret = -EINVAL;
		}
	}

	if (ret)
		RPMB_LOG_ERROR("could not find the ufs-bsg dev\n");

	return ret;
}

int ufs_bsg_dev_open(void)
{
	if (!rpmb.fd_ufs_bsg) {
		rpmb.fd_ufs_bsg = open(ufs_bsg_dev, O_RDWR);
		if (rpmb.fd_ufs_bsg < 0) {
			RPMB_LOG_ERROR("Unable to open %s (error no: %d)\n",
			     ufs_bsg_dev, errno);
			rpmb.fd_ufs_bsg = 0;
			return errno;
		}
	}

	return 0;
}

void ufs_bsg_dev_close(void)
{
	if (rpmb.fd_ufs_bsg) {
		close(rpmb.fd_ufs_bsg);
		rpmb.fd_ufs_bsg = 0;
	}
}

int rpmb_bsg_dev_open(void)
{
	if (!rpmb.fd) {
		rpmb.fd = open(rpmb_bsg_dev, O_RDWR | O_SYNC);
		if (rpmb.fd < 0) {
			RPMB_LOG_ERROR("Unable to open %s (error no: %d)\n",
			     rpmb_bsg_dev, errno);
			rpmb.fd = 0;
			return errno;
		}
	}

	return 0;
}

void rpmb_bsg_dev_close(void)
{
	if (rpmb.fd) {
		close(rpmb.fd);
		rpmb.fd = 0;
	}
}

static int ufs_bsg_ioctl(int fd, struct ufs_bsg_request *req,
			 struct ufs_bsg_reply *rsp, __u8 *buf, __u32 buf_len,
			 enum bsg_ioctl_dir dir)
{
	int ret;
	struct sg_io_v4 sg_io = {0};

	sg_io.guard = 'Q';
	sg_io.protocol = BSG_PROTOCOL_SCSI;
	sg_io.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	sg_io.request_len = sizeof(*req);
	sg_io.request = (__u64)(uintptr_t)req;
	sg_io.response = (__u64)(uintptr_t)rsp;
	sg_io.max_response_len = sizeof(*rsp);
	if (dir == BSG_IOCTL_DIR_FROM_DEV) {
		sg_io.din_xfer_len = buf_len;
		sg_io.din_xferp = (__u64)(uintptr_t)(buf);
	} else {
		sg_io.dout_xfer_len = buf_len;
		sg_io.dout_xferp = (__u64)(uintptr_t)(buf);
	}

	ret = ioctl(fd, SG_IO, &sg_io);
	if (ret)
		RPMB_LOG_ERROR("%s: Error from sg_io ioctl (return value: %d, error no: %d, reply result from LLD: %d)\n",
		     __func__, ret, errno, rsp->result);

	if (sg_io.info || rsp->result) {
		RPMB_LOG_ERROR("%s: Error from sg_io info (check sg info: device_status: 0x%x, transport_status: 0x%x, driver_status: 0x%x, reply result from LLD: %d)\n",
		     __func__, sg_io.device_status, sg_io.transport_status,
		     sg_io.driver_status, rsp->result);
		ret = -EIO;
	}

	return ret;
}

static void compose_ufs_bsg_query_req(struct ufs_bsg_request *req, __u8 func,
				    __u8 opcode, __u8 idn, __u8 index, __u8 sel,
				    __u16 length)
{
	struct utp_upiu_header *hdr = &req->upiu_req.header;
	struct utp_upiu_query *qr = &req->upiu_req.qr;

        req->msgcode = UTP_UPIU_QUERY_REQ;
        hdr->dword_0 = DWORD(UTP_UPIU_QUERY_REQ, 0, 0, 0);
        hdr->dword_1 = DWORD(0, func, 0, 0);
        hdr->dword_2 = DWORD(0, 0, length >> 8, (__u8)length);
        qr->opcode = opcode;
        qr->idn = idn;
        qr->index = index;
        qr->selector = sel;
        qr->length = htobe16(length);
}

static int ufs_query_desc(int fd, __u8 *buf,
			  __u16 buf_len, __u8 func, __u8 opcode, __u8 idn,
			  __u8 index, __u8 sel)
{
	struct ufs_bsg_request req = {0};
	struct ufs_bsg_reply rsp = {0};
	enum bsg_ioctl_dir dir = BSG_IOCTL_DIR_FROM_DEV;
	int ret = 0;

	if (opcode == QUERY_REQ_OP_WRITE_DESC)
		dir = BSG_IOCTL_DIR_TO_DEV;

	compose_ufs_bsg_query_req(&req, func, opcode, idn, index, sel, buf_len);

	ret = ufs_bsg_ioctl(fd, &req, &rsp, buf, buf_len, dir);
	if (ret)
		RPMB_LOG_ERROR("%s: Error from ufs_bsg_ioctl (return value: %d, error no: %d)\n",
		     __func__, ret, errno);

	return ret;
}

static int ufs_read_desc(int fd, __u8 *buf, __u16 buf_len,
			 __u8 idn, __u8 index)
{
	return ufs_query_desc(fd, buf, buf_len, QUERY_REQ_FUNC_STD_READ,
			      QUERY_REQ_OP_READ_DESC, idn, index, 0);
}

static int32_t get_ufs_rpmb_parameters(void)
{
	__u8 device_data[QUERY_DESC_SIZE_DEVICE] = {0};
	__u8 geo_data[QUERY_DESC_SIZE_GEOMETRY] = {0};
	__u8 unit_data[QUERY_DESC_SIZE_UNIT] = {0};
	uint16_t wspecversion = 0;
	uint32_t rpmb_num_blocks = 0;
	int32_t ret;

	ret = ufs_bsg_dev_open();
	if (ret)
		return ret;

	ret = ufs_read_desc(rpmb.fd_ufs_bsg, device_data,
			    QUERY_DESC_SIZE_DEVICE,
			    QUERY_DESC_IDN_DEVICE, 0);
	if (ret) {
		RPMB_LOG_ERROR("Error requesting ufs device info via query ioctl (return value: %d, error no: %d)\n",
				ret, errno);
		goto out;
	}

	wspecversion = (device_data[16] << 8) | device_data[17];
	RPMB_LOG_DEBUG("UFS spec version 0x%x\n", wspecversion);

	ret = ufs_read_desc(rpmb.fd_ufs_bsg, geo_data,
			    QUERY_DESC_SIZE_GEOMETRY,
			    QUERY_DESC_IDN_GEOMETRY, 0);
	if (ret) {
		RPMB_LOG_ERROR("Error requesting ufs geometry info via query ioctl (return value: %d, error no: %d)\n",
				ret, errno);
		goto out;
	}

	/*
	 * According to JEDEC UFS spec, bRPMB_ReadWriteSize in Geometry Descriptor
	 * is the number of RPMB frames allowed in a single SECURITY_PROTOCOL_IN
	 * or SECURITY_PROTOCOL_OUT i.e. in a single command UPIU
	 */
	rpmb.info.rel_wr_count = geo_data[23];
	RPMB_LOG_DEBUG("bRPMB_ReadWriteSize: %.2x\n", geo_data[23]);

	ret = ufs_read_desc(rpmb.fd_ufs_bsg, unit_data,
			    QUERY_DESC_SIZE_UNIT,
			    QUERY_DESC_IDN_UNIT, UPIU_RPMB_LUN);
	if (ret) {
		RPMB_LOG_ERROR("Error requesting ufs rpmb unit description via query ioctl (return value: %d, error no: %d)\n",
				ret, errno);
		goto out;
	}

	if (wspecversion < 0x300) {
		/*
		 * calculate the size of the rpmb parition in sectors
		 * using only lower 32 bits for now
		 */
		rpmb_num_blocks = (unit_data[15] << 24) |
				  (unit_data[16] << 16) |
				  (unit_data[17] << 8) | unit_data[18];
		RPMB_LOG_DEBUG("rpmb num blocks: %x", rpmb_num_blocks);
		/*
		 * According to JEDE UFS spec, qLogicalBlockCount in RPMB Unit
		 * Descriptor is a multiple of 256. But TZ expects the number
		 * of sectors reported with sector size in 512 bytes hence
		 * report accordingly.
		 */
		rpmb.info.size = rpmb_num_blocks / 2;
	} else {
		/*
		 * calculate the size of the rpmb parition region 0 in sectors
		 * as we are using region 0 by default
		 */
		rpmb.info.size = unit_data[19] * 256;
		RPMB_LOG_DEBUG("rpmb region 0 num blocks: %x", rpmb.info.size);
	}

out:
	ufs_bsg_dev_close();
	return ret;
}

static int scsi_bsg_ioctl(int fd, __u8 *cdb, __u8 cdb_len, void *buf,
			  __u32 buf_len, enum bsg_ioctl_dir dir)
{
	int ret;
	struct sg_io_v4 sg_io = {0};
	unsigned char sense_buf[SENSE_BUF_LEN] = {0};

	sg_io.guard = 'Q';
	sg_io.protocol = BSG_PROTOCOL_SCSI;
	sg_io.subprotocol = BSG_SUB_PROTOCOL_SCSI_CMD;
	sg_io.request_len = cdb_len;
	sg_io.request = (__u64)(uintptr_t)cdb;
	sg_io.response = (__u64)(uintptr_t)sense_buf;
	sg_io.max_response_len = SENSE_BUF_LEN;
	if (dir == BSG_IOCTL_DIR_FROM_DEV) {
		sg_io.din_xfer_len = (__u32)buf_len;
		sg_io.din_xferp = (__u64)(uintptr_t)buf;
	} else {
		sg_io.dout_xfer_len = (__u32)buf_len;
		sg_io.dout_xferp = (__u64)(uintptr_t)buf;
	}

	ret = ioctl(fd, SG_IO, &sg_io);
	if (ret)
		RPMB_LOG_ERROR("%s: Error from sg_io ioctl (return value: %d, error no: %d)\n",
		     __func__, ret, errno);

	if (sg_io.info) {
		RPMB_LOG_ERROR("SCSI error occurred!!\n");
		RPMB_LOG_ERROR("----------------------------------------------------\n");
		RPMB_LOG_ERROR("%s: Error from sg_io info (check sg info: device_status: 0x%x, transport_status: 0x%x, driver_status: 0x%x, Sense Key code: 0x%x)\n",
		     __func__, sg_io.device_status, sg_io.transport_status,
		     sg_io.driver_status, (sense_buf[2] & 0xF));
		RPMB_LOG_ERROR("----------------------------------------------------\n");
		ret = -EIO;
	}

	return ret;
}

int rpmb_ufs_send_request_sense(void)
{
	unsigned char cdb[SCSI_REQ_SENSE_CDB_LEN] = {0};
	unsigned char sense_buf[SCSI_REQ_SENSE_BUF_LEN] = {0};
	enum bsg_ioctl_dir dir = BSG_IOCTL_DIR_FROM_DEV;
	int32_t ret = 0;

	cdb[0] = SCSI_REQ_SENSE_ID;
	cdb[4] = SCSI_REQ_SENSE_BUF_LEN;

	ret = rpmb_bsg_dev_open();
	if (ret)
		return ret;

	ret = scsi_bsg_ioctl(rpmb.fd, cdb, SCSI_REQ_SENSE_CDB_LEN,
			     sense_buf, SCSI_REQ_SENSE_BUF_LEN, dir);
	if (ret)
		RPMB_LOG_ERROR("%s: Error from scsi_bsg_ioctl (return value: %d, error no: %d)\n", __func__, ret, errno);

	rpmb_bsg_dev_close();
	return ret;
}

int rpmb_ufs_init(rpmb_init_info_t *rpmb_info)
{
	int32_t ret = 0;

	ret = get_ufs_bsg_dev();
	if (ret)
		return ret;
	RPMB_LOG_DEBUG("Found the ufs bsg dev: %s\n", ufs_bsg_dev);

	ret = get_ufs_rpmb_parameters();
	if (ret < 0) {
		RPMB_LOG_ERROR("Error reading UFS descriptors (error no: %d)\n", ret);
		return ret;
	}
	RPMB_LOG_DEBUG("RPMB Mult (512-byte sector) = %d, Rel_sec_cnt = %d\n",
	     rpmb.info.size, rpmb.info.rel_wr_count);

	rpmb.info.dev_type = UFS_RPMB;
	rpmb.init_done = 1;
	rpmb_info->dev_type = rpmb.info.dev_type;
	rpmb_info->size = rpmb.info.size;
	rpmb_info->rel_wr_count = rpmb.info.rel_wr_count;

	ret = rpmb_ufs_send_request_sense();
	if (ret < 0) {
		RPMB_LOG_ERROR("Request sense command failed (error no: %d)\n", ret);
		return ret;
	}

	rpmb_init_wakelock();
	return 0;
}

int rpmb_ufs_read(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf,
		uint32_t *resp_len)
{
	uint32_t num_bytes, temp_blk_cnt = blk_cnt, blk_cnt_rem = blk_cnt;
	int32_t ret = 0, num_rpmb_trans, i;
	unsigned char scsi_sec_out_cmd_cdb[SCSI_SEC_CDB_LEN];
	unsigned char scsi_sec_in_cmd_cdb[SCSI_SEC_CDB_LEN];
	uint32_t *req_buf_cached = NULL, *req_buf_offset = NULL;

	num_rpmb_trans = blk_cnt / rpmb.info.rel_wr_count;
	if (blk_cnt % rpmb.info.rel_wr_count)
		num_rpmb_trans++;

	/*
	 * Cache the rpmb request buffer if there are multiple RPMB transfers,
	 * otherwise request buffer contents may get overwritten when we copy
	 * the response for the first RPMB transfer.
	 */
	if (num_rpmb_trans > 1) {
		req_buf_cached = malloc(num_rpmb_trans * RPMB_BLK_SIZE);
		if (!req_buf_cached)
			return -ENOMEM;

		memcpy(req_buf_cached, req_buf,
		       (num_rpmb_trans * RPMB_BLK_SIZE));
		req_buf_offset = req_buf_cached;
	} else {
		req_buf_offset = req_buf;
	}

	rpmb_wakelock();

	ret = rpmb_bsg_dev_open();
	if (ret)
		goto out_free;

	for (i = 0; i < num_rpmb_trans; i++) {
		if ((blk_cnt_rem > 0) && (blk_cnt_rem <= rpmb.info.rel_wr_count)) {
			temp_blk_cnt = blk_cnt_rem;
		} else if (blk_cnt_rem > rpmb.info.rel_wr_count) {
			temp_blk_cnt = rpmb.info.rel_wr_count;
		} else {
			/* should not end up here */
			RPMB_LOG_ERROR("Error: incorrect block count calculation in reading rpmb data from ufs\t");
			RPMB_LOG_ERROR("blk_cnt_rem = %u, temp_blk_cnt = %u, i = %d\n", blk_cnt_rem, temp_blk_cnt, i);
		}
		num_bytes = temp_blk_cnt * RPMB_FRAME_SIZE;

		/* Send a SPO cmd for a read request */
		memset(&scsi_sec_out_cmd_cdb, 0, SCSI_SEC_CDB_LEN);
		scsi_sec_out_cmd_cdb[0] = SCSI_SEC_OUT_ID;
		scsi_sec_out_cmd_cdb[1] = SCSI_SEC_PROT;

		scsi_sec_out_cmd_cdb[2] = (unsigned char)((SCSI_SEC_UFS_PROT_ID >> 8) & 0xff);
		scsi_sec_out_cmd_cdb[3] = (unsigned char)(SCSI_SEC_UFS_PROT_ID & 0xff);

		scsi_sec_out_cmd_cdb[6] = (unsigned char)((RPMB_FRAME_SIZE >> 24) & 0xff);
		scsi_sec_out_cmd_cdb[7] = (unsigned char)((RPMB_FRAME_SIZE >> 16) & 0xff);
		scsi_sec_out_cmd_cdb[8] = (unsigned char)((RPMB_FRAME_SIZE >> 8) & 0xff);
		scsi_sec_out_cmd_cdb[9] = (unsigned char)(RPMB_FRAME_SIZE & 0xff);

		ret = scsi_bsg_ioctl(rpmb.fd, scsi_sec_out_cmd_cdb, SCSI_SEC_CDB_LEN,
				     req_buf_offset, RPMB_FRAME_SIZE, BSG_IOCTL_DIR_TO_DEV);
		if (ret) {
			RPMB_LOG_ERROR("%s: Error sending SPO through scsi_bsg_ioctl (return value: %d, error no: %d, iter: %d)\n", __func__, ret, errno, i);
			goto out;
		}

		/* Send a SPI cmd to read RPMB data frames back */
		memset(&scsi_sec_in_cmd_cdb, 0, SCSI_SEC_CDB_LEN);
		scsi_sec_in_cmd_cdb[0] = SCSI_SEC_IN_ID;
		scsi_sec_in_cmd_cdb[1] = SCSI_SEC_PROT;

		scsi_sec_in_cmd_cdb[2] = (unsigned char)((SCSI_SEC_UFS_PROT_ID >> 8) & 0xff);
		scsi_sec_in_cmd_cdb[3] = (unsigned char)(SCSI_SEC_UFS_PROT_ID & 0xff);

		scsi_sec_in_cmd_cdb[6] = (unsigned char)((num_bytes >> 24) & 0xff);
		scsi_sec_in_cmd_cdb[7] = (unsigned char)((num_bytes >> 16) & 0xff);
		scsi_sec_in_cmd_cdb[8] = (unsigned char)((num_bytes >> 8) & 0xff);
		scsi_sec_in_cmd_cdb[9] = (unsigned char)(num_bytes & 0xff);

		ret = scsi_bsg_ioctl(rpmb.fd, scsi_sec_in_cmd_cdb, SCSI_SEC_CDB_LEN,
				     resp_buf, num_bytes, BSG_IOCTL_DIR_FROM_DEV);
		if (ret) {
			RPMB_LOG_ERROR("%s: Error sending SPI through scsi_bsg_ioctl (return value: %d, error no: %d, iter: %d)\n", __func__, ret, errno, i);
			goto out;
		}

		/* Select the next RPMB frame */
		req_buf_offset = (uint32_t*) ((void*)((uint8_t*)req_buf_offset + RPMB_BLK_SIZE));
		resp_buf = (uint32_t*) ((void*)((uint8_t*)resp_buf + (temp_blk_cnt * RPMB_BLK_SIZE)));
		blk_cnt_rem -= temp_blk_cnt;
	}

out:
	rpmb_bsg_dev_close();
out_free:
	if (num_rpmb_trans > 1)
		free(req_buf_cached);
	*resp_len = blk_cnt * RPMB_BLK_SIZE;
	rpmb_wakeunlock();
	return ret;
}

static int rpmb_ufs_write_with_timeout(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf,
		uint32_t *resp_len, uint32_t frames_per_rpmb_trans)
{
        int i, num_rpmb_trans = 0;
	uint32_t result_frame_bytes = RPMB_FRAME_SIZE;
	uint32_t req_frame_bytes = RPMB_FRAME_SIZE * frames_per_rpmb_trans;
	int32_t ret = 0;
	unsigned char scsi_sec_out_cmd_cdb[SCSI_SEC_CDB_LEN];
	unsigned char scsi_sec_in_cmd_cdb[SCSI_SEC_CDB_LEN];

	RPMB_LOG_DEBUG("UFS RPMB write starting: blk_cnt=%d, frames_per_trans=%d", blk_cnt, frames_per_rpmb_trans);

	rpmb_wakelock();
	ret = rpmb_bsg_dev_open();
	if (ret) {
		RPMB_LOG_ERROR("Failed to open BSG device: %d", ret);
		goto out_unlock;
	}

	/*
	 * Secure world should never send more than the reliable write count
	 * number of frames for a single operation. If in the future, the
	 * secure world sends all the rpmb requests in one shot, then it
	 * may be need to be supported in the future.
	 */
	if (frames_per_rpmb_trans > rpmb.info.rel_wr_count) {
		RPMB_LOG_ERROR("Incorrect numner of rpmb write operations requested\n");
		rpmb_bsg_dev_close();
		ret = -1;
		goto out_unlock;
	}

	num_rpmb_trans = blk_cnt / frames_per_rpmb_trans;

	for (i = num_rpmb_trans; i > 0; i--) {
		/* Send a SPO cmd to write RPMB data frames */
		memset(&scsi_sec_out_cmd_cdb, 0, SCSI_SEC_CDB_LEN);
		scsi_sec_out_cmd_cdb[0] = SCSI_SEC_OUT_ID;
		scsi_sec_out_cmd_cdb[1] = SCSI_SEC_PROT;

		scsi_sec_out_cmd_cdb[2] = (unsigned char)((SCSI_SEC_UFS_PROT_ID >> 8) & 0xff);
		scsi_sec_out_cmd_cdb[3] = (unsigned char)(SCSI_SEC_UFS_PROT_ID & 0xff);

		scsi_sec_out_cmd_cdb[6] = (unsigned char)((req_frame_bytes >> 24) & 0xff);
		scsi_sec_out_cmd_cdb[7] = (unsigned char)((req_frame_bytes >> 16) & 0xff);
		scsi_sec_out_cmd_cdb[8] = (unsigned char)((req_frame_bytes >> 8) & 0xff);
		scsi_sec_out_cmd_cdb[9] = (unsigned char)(req_frame_bytes & 0xff);

		ret = scsi_bsg_ioctl(rpmb.fd, scsi_sec_out_cmd_cdb, SCSI_SEC_CDB_LEN,
				     req_buf, req_frame_bytes, BSG_IOCTL_DIR_TO_DEV);
		if (ret) {
			RPMB_LOG_ERROR("%s: Error sending SPO through scsi_bsg_ioctl (return value: %d, error no: %d, iter: %d)\n", __func__, ret, errno, i);
			goto out;
		}

		/* Send a SPO cmd for a read request */
		memset(&scsi_sec_out_cmd_cdb, 0, SCSI_SEC_CDB_LEN);
		scsi_sec_out_cmd_cdb[0] = SCSI_SEC_OUT_ID;
		scsi_sec_out_cmd_cdb[1] = SCSI_SEC_PROT;

		scsi_sec_out_cmd_cdb[2] = (unsigned char)((SCSI_SEC_UFS_PROT_ID >> 8) & 0xff);
		scsi_sec_out_cmd_cdb[3] = (unsigned char)(SCSI_SEC_UFS_PROT_ID & 0xff);

		scsi_sec_out_cmd_cdb[6] = (unsigned char)((result_frame_bytes >> 24) & 0xff);
		scsi_sec_out_cmd_cdb[7] = (unsigned char)((result_frame_bytes >> 16) & 0xff);
		scsi_sec_out_cmd_cdb[8] = (unsigned char)((result_frame_bytes >> 8) & 0xff);
		scsi_sec_out_cmd_cdb[9] = (unsigned char)(result_frame_bytes & 0xff);

		ret = scsi_bsg_ioctl(rpmb.fd, scsi_sec_out_cmd_cdb, SCSI_SEC_CDB_LEN,
				     &read_result_reg_frame, result_frame_bytes, BSG_IOCTL_DIR_TO_DEV);
		if (ret) {
			RPMB_LOG_ERROR("%s: Error sending SPO through scsi_bsg_ioctl (return value: %d, error no: %d, iter: %d)\n", __func__, ret, errno, i);
			goto out;
		}

		/* Send a SPI cmd to read RPMB data frames back */
		memset(&scsi_sec_in_cmd_cdb, 0, SCSI_SEC_CDB_LEN);
		scsi_sec_in_cmd_cdb[0] = SCSI_SEC_IN_ID;
		scsi_sec_in_cmd_cdb[1] = SCSI_SEC_PROT;

		scsi_sec_in_cmd_cdb[2] = (unsigned char)((SCSI_SEC_UFS_PROT_ID >> 8) & 0xff);
		scsi_sec_in_cmd_cdb[3] = (unsigned char)(SCSI_SEC_UFS_PROT_ID & 0xff);

		scsi_sec_in_cmd_cdb[6] = (unsigned char)((result_frame_bytes >> 24) & 0xff);
		scsi_sec_in_cmd_cdb[7] = (unsigned char)((result_frame_bytes >> 16) & 0xff);
		scsi_sec_in_cmd_cdb[8] = (unsigned char)((result_frame_bytes >> 8) & 0xff);
		scsi_sec_in_cmd_cdb[9] = (unsigned char)(result_frame_bytes & 0xff);

		ret = scsi_bsg_ioctl(rpmb.fd, scsi_sec_in_cmd_cdb, SCSI_SEC_CDB_LEN,
				     resp_buf, result_frame_bytes, BSG_IOCTL_DIR_FROM_DEV);
		if (ret) {
			RPMB_LOG_ERROR("%s: Error sending SPO through scsi_bsg_ioctl (return value: %d, error no: %d, iter: %d)\n", __func__, ret, errno, i);
			goto out;
		}

		/* Select the next RPMB frame */
		req_buf = (uint32_t*) ((void*)((uint8_t*)req_buf + (frames_per_rpmb_trans * RPMB_BLK_SIZE)));
	}

out:
	rpmb_bsg_dev_close();
	*resp_len = RPMB_MIN_BLK_CNT * RPMB_BLK_SIZE;
out_unlock:
	rpmb_wakeunlock();
        return ret;
}

/* UFS RPMB write function - called directly by legacy rpmb.c */
int rpmb_ufs_write(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf,
		uint32_t *resp_len, uint32_t frames_per_rpmb_trans)
{
    RPMB_LOG_DEBUG("RPMB UFS write: blk_cnt=%d, frames_per_trans=%d", blk_cnt, frames_per_rpmb_trans);

    /* Call the actual write function directly */
    int result = rpmb_ufs_write_with_timeout(req_buf, blk_cnt, resp_buf, resp_len, frames_per_rpmb_trans);

    if (result == 0) {
        RPMB_LOG_DEBUG("RPMB UFS write completed successfully");
    } else {
        RPMB_LOG_ERROR("RPMB UFS write failed with error: %d", result);
    }

    return result;
}

/* UFS cleanup function for legacy system */
void rpmb_ufs_exit(void)
{
    /* UFS cleanup - close any open file descriptors */
    ufs_bsg_dev_close();
    rpmb_bsg_dev_close();
}

/* Wrapper functions for rpmb_core.c compatibility (not used by main service) */
static rpmb_result_t ufs_init_wrapper(rpmb_device_info_t *info)
{
    rpmb_init_info_t legacy_info = {0};
    int result = rpmb_ufs_init(&legacy_info);

    if (result == 0 && info) {
        info->device_type = RPMB_DEVICE_UFS;
        info->size_sectors = legacy_info.size;
        info->reliable_write_count = legacy_info.rel_wr_count;
        info->initialized = true;
    }

    return (result == 0) ? RPMB_RESULT_OK : RPMB_RESULT_GENERAL_FAILURE;
}

static void ufs_cleanup_wrapper(void)
{
    rpmb_ufs_exit();
}

static rpmb_result_t ufs_read_wrapper(uint32_t *request_buf, uint32_t block_count,
                                     uint32_t *response_buf, uint32_t *response_len)
{
    int result = rpmb_ufs_read(request_buf, block_count, response_buf, response_len);
    return (result == 0) ? RPMB_RESULT_OK : RPMB_RESULT_READ_FAILURE;
}

static rpmb_result_t ufs_write_wrapper(uint32_t *request_buf, uint32_t block_count,
                                      uint32_t *response_buf, uint32_t *response_len,
                                      uint32_t frames_per_operation)
{
    int result = rpmb_ufs_write(request_buf, block_count, response_buf,
                               response_len, frames_per_operation);
    return (result == 0) ? RPMB_RESULT_OK : RPMB_RESULT_WRITE_FAILURE;
}

/* Device operations structure for rpmb_core.c compatibility */
const rpmb_device_ops_t rpmb_ufs_ops = {
    .init = ufs_init_wrapper,
    .cleanup = ufs_cleanup_wrapper,
    .read = ufs_read_wrapper,
    .write = ufs_write_wrapper,
};
