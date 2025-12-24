/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdbool.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#include "gpt_msg.h"
#include "gpt_logging.h"

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

/* GPT constants and definitions from original service */
#define GPT_LSTNR_VERSION_1		1
#define GPT_LSTNR_VERSION_2		2
#define GPT_LSTNR_VERSION		GPT_LSTNR_VERSION_2
#define GPT_LISTENER_BUFFER_SIZE	(516*1024)
#define GPT_LSTNR_VER_NOT_SUPPORTED	-5
#define GPT_CMD_ID_NOT_SUPPORTED	-7

#define EMMC_SECTOR_SIZE	512
#define UFS_SECTOR_SIZE		4096
#define DEV_PATH "/dev/"
#define CMDLINE  "/proc/cmdline"
#define EMMC_DEV "root=/dev/mmcblk"
#define UFS_DEV  "root=/dev/sd"
#define BOOT_DEV_KEY  "bootdevice="

#define FNAME_SZ	128
#define NUM_DISKS	32
#define NUM_ENTRIES	256
#define GPT_PART_NAME_LEN	(72 / sizeof(uint16_t))

#define CTX_ID_DISK_INDEX_OFFSET	16
#define CTX_ID_INDEX_MASK	0xffff

#define INDEX_TO_CTX_ID(d, e) \
	(((d) & CTX_ID_INDEX_MASK) << CTX_ID_DISK_INDEX_OFFSET) | \
	((e) & CTX_ID_INDEX_MASK)

#define ENTRY_INDEX(c)	(c) & CTX_ID_INDEX_MASK
#define DISK_INDEX(c)	((c) >> CTX_ID_DISK_INDEX_OFFSET) & CTX_ID_INDEX_MASK

#ifndef min
#define min(a,b) (a)>(b)?(b):(a)
#endif

/* Storage Device Types */
typedef enum {
	EMMC_USER = 0,
	EMMC_BOOT1,
	EMMC_BOOT0,
	EMMC_RPMB,
	EMMC_GPP1,
	EMMC_GPP2,
	EMMC_GPP3,
	EMMC_GPP4,
	EMMC_ALL,
	UFS_RPMB,
	UFS_ALL,
	NO_DEVICE = 0x7FFFFFFF
} device_id_type;

/* GPT structures from original service */
struct gpt_entry {
	uint8_t type[16];
	uint8_t guid[16];
	uint64_t lba_start;
	uint64_t lba_end;
	uint64_t attrs;
	uint16_t name[GPT_PART_NAME_LEN];
}  __attribute__ ((packed));

#define GPT_HEADER_SIGNATURE 0x5452415020494645ULL

struct gpt_header {
	uint64_t signature;
	uint32_t revision;
	uint32_t size;
	uint32_t crc32;
	uint32_t reserved1;
	uint64_t this_lba;
	uint64_t alternative_lba;
	uint64_t first_usable_lba;
	uint64_t last_usable_lba;
	uint8_t guid[16];
	uint64_t entry_start_lba;
	uint32_t num_entries;
	uint32_t entry_size;
	uint32_t entry_array_crc32;
	uint8_t reserved2[512 - 92];
} __attribute__ ((packed));

struct disk {
	char dev_name[FNAME_SZ];
	struct gpt_header header;
	struct gpt_entry entries[NUM_ENTRIES];
};

typedef struct gpt_init_info {
	uint32_t bytes_per_sec;
	uint32_t ctx_id;
	uint32_t num_sectors;
	uint8_t guid[16];
} gpt_init_info_t;

struct gpt_stats {
	int init_done;
	device_id_type dev_type;
	uint32_t bytes_per_sec;
	uint32_t num_disks;
};

/* Global variables */
static struct disk disk_array[NUM_DISKS];
static struct gpt_stats gpt;
static uint8_t null_guid[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* Helper functions from original service */
static inline uint32_t partition_size(struct gpt_entry *e)
{
	return le64toh(e->lba_end) - le64toh(e->lba_start) + 1;
}

static inline uint64_t partition_start(struct gpt_entry *e)
{
	return le64toh(e->lba_start);
}

static inline uint64_t partition_end(struct gpt_entry *e)
{
	return le64toh(e->lba_end);
}

static inline int is_guid_valid(uint8_t *guid)
{
	return memcmp(guid, null_guid, 16);
}

static inline int is_same_guid(uint8_t *a, uint8_t *b)
{
	return !memcmp(a, b, 16);
}

static inline bool is_ctx_id_invalid(uint32_t ctx_id)
{
	return (ctx_id == (uint32_t)-1 || (DISK_INDEX(ctx_id)) >= NUM_DISKS ||
		(ENTRY_INDEX(ctx_id)) >= NUM_ENTRIES);
}

/* Device detection from original service */
static device_id_type get_boot_device_type(void)
{
	int fd;
	char *cmdline_buf = NULL;
	ssize_t ret;
	ssize_t byte_count = 0;
	char *bootdev;
	char cmdline_segment[101];
	device_id_type status_ret = NO_DEVICE;

	fd = open(CMDLINE, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		MSGE("Error unable to open the file /proc/cmdnline: (err no: %d)\n", errno);
		return NO_DEVICE;
	}

	do{
		ret = read(fd, cmdline_segment, 100);
		byte_count = ret > 0 ? (byte_count + ret) : byte_count;
	} while(ret > 0);
	if(ret < 0) {
		MSGE("Error reading the file /proc/cmdline: (err no: %d)\n", errno);
		close(fd);
		return NO_DEVICE;
	}

	do {
		if (lseek(fd, 0, SEEK_SET)) {
			MSGE("Error reading the file /proc/cmdline: (err no: %d)\n", errno);
			status_ret = NO_DEVICE;
			break;
		}
		cmdline_buf = malloc (byte_count + 1);
		if (cmdline_buf == NULL) {
			MSGE("Error gpt services run out of memory.\n");
			status_ret = NO_DEVICE;
			break;
		}
		ret = read(fd, cmdline_buf, byte_count);
		if (ret != byte_count) {
			MSGE("Error reading the file /proc/cmdline fail: size of /proc/cmdline is %d and"
				" return size is %d\n", (int)byte_count, (int)ret);
			status_ret = NO_DEVICE;
			break;
		}
		cmdline_buf[ret] = '\0';

		if(strstr(cmdline_buf, EMMC_DEV)) {
			MSGV("GPT partion exists on EMMC device\n");
			status_ret = EMMC_ALL;
			break;
		}

		if(strstr(cmdline_buf, UFS_DEV)) {
			MSGV("GPT partion exists on UFS device\n");
			status_ret = UFS_ALL;
			break;
		}

		//If dm-verity is enabled
		bootdev = strstr(cmdline_buf, BOOT_DEV_KEY);

		if(bootdev != NULL) {
			bootdev = bootdev + strlen(BOOT_DEV_KEY);
			if (*bootdev != '\0') {
				if (strstr(bootdev, "sdhci")) {
					MSGV("GPT partion exists on EMMC device");
					status_ret = EMMC_ALL;
					break;
				} else if (strstr(bootdev, "ufshc")){
					MSGV("GPT partion exists on UFS device");
					status_ret = UFS_ALL;
					break;
				}
			}
		}
		status_ret = NO_DEVICE;
		MSGE("Unknown boot device %s\n", cmdline_buf);
	} while(0);

	if (cmdline_buf)
		free(cmdline_buf);
	close(fd);
	return status_ret;
}

static int read_lba(char *dev, struct disk *disk __attribute__((unused)), void *buffer, uint64_t lba,
		    const size_t bytes)
{
	int ret, fd;
	off_t offset = lba * gpt.bytes_per_sec;

	fd = open(dev, O_RDONLY);
	if (fd < 0) {
		MSGE("failed to open dev %s (error no: %d)", dev, errno);
		return errno;
	}

	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		ret = -EINVAL;
		goto out;
	}

	ret = read(fd, buffer, bytes);
	if (ret == (int)bytes) {
		MSGD("Successfully read %d bytes from dev %s", (int)bytes, dev);
		ret = 0;
	} else {
		MSGE("error reading %s, ret = %d, bytes = %u (error no: %d)", dev, ret, (unsigned int)bytes, errno);
		ret = -EIO;
	}

out:
	close(fd);
	return ret;
}

static int write_lba(char *dev, struct disk *disk __attribute__((unused)), void *buffer, uint64_t lba,
		     const size_t bytes)
{
	int ret, fd;
	off_t offset = lba * gpt.bytes_per_sec;

	fd = open(dev, O_RDWR | O_SYNC);
	if (fd < 0) {
		MSGE("failed to open dev %s (error no: %d)", dev, errno);
		return errno;
	}

	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		ret = -EINVAL;
		goto out;
	}

	ret = write(fd, buffer, bytes);
	if (ret == (int)bytes) {
		MSGD("Successfully write %d bytes to dev %s", (int)bytes, dev);
		ret = 0;
	} else {
		MSGE("error writing %s, ret = %d, bytes = %u (error no: %d)", dev, ret, (unsigned int)bytes, errno);
		ret = -EIO;
	}

out:
	close(fd);
	return ret;
}

static bool is_emmc_dev(char *path)
{
	char type_path[280] = {0};  /* Increased buffer size */
	char type[5] = {0};
	FILE *fp = NULL;
	bool ret = false;

	snprintf(type_path, sizeof(type_path), "/sys/block/%s/device/type", path);
	fp = fopen(type_path, "r");
	if (NULL == fp) {
		MSGE("%s: open %s failed\n", __func__, type_path);
		return ret;
	}

	if (fgets(type, 5, fp)) {
		if (strncmp(type, "SD", 2))
			ret = true;
	} else
		MSGE("%s: get type of %s failed\n", __func__, path);

	fclose(fp);

	return ret;
}

/* GPT initialization from original service */
static int gpt_do_init(void)
{
	int d = -1;
	DIR *dir = opendir("/sys/block");
	struct dirent *ent;

	if (dir != NULL) {
		MSGD("start to discover disks ...\n");
		/* read all the files and directories within directory */
		while ((ent = readdir(dir)) != NULL) {
			bool disk_found = false;

			if ((gpt.dev_type == UFS_ALL &&
			     !strncmp(ent->d_name, "sd", 2)) ||
			    (gpt.dev_type == EMMC_ALL &&
			     !strncmp(ent->d_name, "mmcblk", 6) &&
			     is_emmc_dev(ent->d_name))) {
				MSGD("discovered disk %s\n", ent->d_name);
				disk_found = true;
			}

			if (disk_found) {
				struct disk *disk;

				if (d + 1 == NUM_DISKS)
					break;
				d ++;
				disk = &disk_array[d];
				/* Use safe string copy to avoid truncation warning */
				size_t name_len = strlen(ent->d_name);
				if (name_len >= FNAME_SZ) {
					name_len = FNAME_SZ - 1;
				}
				memcpy(disk->dev_name, ent->d_name, name_len);
				disk->dev_name[name_len] = '\0';
			}
		}
		gpt.num_disks = d + 1;
		MSGD("discovered %d disks\n", gpt.num_disks);
		closedir (dir);
	} else {
		/* could not open directory */
		MSGE("could not open /sys/block (error no: %d)\n", errno);
		return -EINVAL;
	}

	/* Get raw GPT header and entries */
	for (; d >= 0; d --) {
		int ret;
		uint64_t s;
		size_t l;
		struct disk *disk = &disk_array[d];
		char dev[FNAME_SZ] = {0};
		struct gpt_header *header = &disk->header;
		struct gpt_entry *entry = disk->entries;

		snprintf(dev, FNAME_SZ, "%s%s", DEV_PATH, disk->dev_name);
		MSGD("reading %s's GPT header\n", dev);
		/* Read GPT header from LBA1 */
		ret = read_lba(dev, disk, header, 1, 512);
		if (ret) {
			if (ret == EACCES || ret  == EPERM)
				continue;
			MSGE("Failed reading GPT header on disk %s (error no: %d)\n", dev, ret);
			return ret;
		}

		/* Check GPT header's Signature */
		if (le64toh(header->signature) != GPT_HEADER_SIGNATURE) {
			MSGD("Invalid GPT header found on disk %s\n", dev);
			continue;
		}

		/* Read GPT entries */
		s = le64toh(header->entry_start_lba);
		l = min(le32toh(header->num_entries), NUM_ENTRIES) *
		    sizeof(struct gpt_entry);
		ret = read_lba(dev, disk, entry, s, l);
		if (ret) {
			MSGE("Failed reading GPT entries on disk %s (error no: %d)\n", dev, errno);
			return ret;
		}
	}

	MSGD("gpt_do_init() done!!!\n");
	gpt.init_done = 1;

	return 0;
}

static int gpt_grab_info(gpt_init_info_t *gpt_info)
{
	int d, e;
	uint32_t num_entries;
	struct disk *disk;
	struct gpt_entry *entry;

	if (!gpt_info)
		return -EINVAL;

	gpt_info->bytes_per_sec = gpt.bytes_per_sec;
	gpt_info->ctx_id = -1;

	if (!is_guid_valid(gpt_info->guid)) {
		MSGE("Invalid target GUID");
		return -EINVAL;
	}

	/* Search all disks */
	for (d = gpt.num_disks - 1; d >= 0; d --) {
		disk = &disk_array[d];
		num_entries = min(le32toh(disk->header.num_entries), NUM_ENTRIES);
		MSGE("Searching on disk %d, num of entires is %d", d, num_entries);
		/* Search all GPT entries on this disk */
		for (e = 0; e < (int)num_entries; e ++) {
			entry = &disk->entries[e];
			/* Compare GPT entry type against requested GUID */
			if (is_guid_valid(entry->guid) &&
			    is_same_guid(entry->type, gpt_info->guid)) {
				gpt_info->num_sectors = partition_size(entry);
				gpt_info->ctx_id = INDEX_TO_CTX_ID(d, e);
				MSGD("nailed ctx_id = 0x%x, num_sectors = %d",
				     gpt_info->ctx_id, gpt_info->num_sectors);
				return 0;
			}
		}
	}

	return -EINVAL;
}

static int gpt_init_func(gpt_init_info_t *gpt_info)
{
	int ret = 0;
	device_id_type device;

again:
	if (gpt.init_done) {
		if (gpt_info) {
			ret = gpt_grab_info(gpt_info);
			if (ret)
				MSGE("Failed to grab gpt info, ret = %d\n", ret);
		}
		MSGD("GPT initialization done\n");
		return ret;
	}

	device = get_boot_device_type();
	gpt.dev_type = device;
	MSGD("GPT device type: %d\n", device);

	if (device == EMMC_ALL) {
		gpt.bytes_per_sec = EMMC_SECTOR_SIZE;
	} else if (device == UFS_ALL) {
		gpt.bytes_per_sec = UFS_SECTOR_SIZE;
	} else {
		gpt.init_done = 1;
		return ret;
	}

	ret = gpt_do_init();
	if (!ret)
		goto again;

	return ret;
}

static int parti_access_sanity_check(uint32_t ctx_id, uint32_t start, uint32_t count)
{
	struct disk *d = &disk_array[DISK_INDEX(ctx_id)];
	struct gpt_entry *e = &d->entries[ENTRY_INDEX(ctx_id)];

	if (start > partition_end(e) - partition_start(e) ||
	    start + count > partition_size(e))
		return -1;

	return 0;
}

static int gpt_read_func(uint32_t ctx_id, uint32_t start, uint32_t count,
	     uint32_t *resp_buf, uint32_t *resp_len)
{
	int ret = 0;
	char dev[FNAME_SZ] = {0};
	size_t size = count * gpt.bytes_per_sec;
	struct disk *d;
	struct gpt_entry *e;

	*resp_len = 0;

	if (is_ctx_id_invalid(ctx_id)) {
		MSGE("%s: Invalid context ID", __func__);
		return -EINVAL;
	}

	if (parti_access_sanity_check(ctx_id, start, count)) {
		MSGE("gpt_read() failed santiy check: start = 0x%x, count = %u, ctx_id = 0x%x",
		     start, count, ctx_id);
		return -EINVAL;
	}

	d = &disk_array[DISK_INDEX(ctx_id)];
	e = &d->entries[ENTRY_INDEX(ctx_id)];

	snprintf(dev, FNAME_SZ, "%s%s", DEV_PATH, d->dev_name);
	ret = read_lba(dev, d, resp_buf, partition_start(e) + start, size);
	if (ret)
		MSGE("error reading dev %s (error no: %d)", dev, ret);
	else
		*resp_len = size;

	return ret;
}

static int gpt_write_func(uint32_t ctx_id, uint32_t start, uint32_t count,
	      uint32_t *req_buf, uint32_t *resp_len)
{
	int ret = 0;
	char dev[FNAME_SZ] = {0};
	size_t size = count * gpt.bytes_per_sec;
	struct disk *d;
	struct gpt_entry *e;

	*resp_len = 0;

	if (is_ctx_id_invalid(ctx_id)) {
		MSGE("%s: Invalid context ID", __func__);
		return -EINVAL;
	}

	if (parti_access_sanity_check(ctx_id, start, count)) {
		MSGE("gpt_write() failed santiy check: start = 0x%x, count = %u, ctx_id = 0x%x",
		     start, count, ctx_id);
		return -EINVAL;
	}

	d = &disk_array[DISK_INDEX(ctx_id)];
	e = &d->entries[ENTRY_INDEX(ctx_id)];

	snprintf(dev, FNAME_SZ, "%s%s", DEV_PATH, d->dev_name);
	ret = write_lba(dev, d, req_buf, partition_start(e) + start, size);
	if (ret)
		MSGE("error writing dev %s (error no: %d)", dev, ret);

	return ret;
}

/**
 * smci_gpt_handle_init_req - Handle GPT initialization request
 * @req: Request buffer containing initialization parameters
 * @rsp: Response buffer for initialization results
 *
 * Process GPT initialization request by searching for the specified GUID
 * in the GPT partition table and returning partition information.
 */
static void smci_gpt_handle_init_req(void *req, void *rsp)
{
	tz_sd_gpt_init_req_t *init_req_ptr;
	tz_sd_gpt_init_res_t init_resp;
	tz_sd_gpt_init_res_v02_t init_res_v02;
	gpt_init_info_t gpt_info = {0};

	memset(&init_resp, 0, sizeof(tz_sd_gpt_init_res_t));
	memset(&init_res_v02, 0, sizeof(tz_sd_gpt_init_res_v02_t));
	init_req_ptr  = (tz_sd_gpt_init_req_t *) req;
	if(init_req_ptr == NULL) {
		MSGE("REQ pointer is NULL, quiting now!");
		return;
	}

	memcpy(gpt_info.guid, init_req_ptr->guid, 16);
	init_resp.status = gpt_init_func(&gpt_info);

	if (init_req_ptr->version == GPT_LSTNR_VERSION_1) {
		init_resp.cmd_id = init_req_ptr->cmd_id;
		init_resp.version = GPT_LSTNR_VERSION_1;
		init_resp.num_sectors = gpt_info.num_sectors;
		init_resp.size = GPT_LISTENER_BUFFER_SIZE;
		init_resp.ctx_id = gpt_info.ctx_id;

		memmove(rsp, (void*)&init_resp, sizeof(tz_sd_gpt_init_res_t));
	} else if (init_req_ptr->version >= GPT_LSTNR_VERSION_2) {
		init_res_v02.cmd_id = init_req_ptr->cmd_id;
		init_res_v02.version = GPT_LSTNR_VERSION_2;
		init_res_v02.num_sectors = gpt_info.num_sectors;
		init_res_v02.size = GPT_LISTENER_BUFFER_SIZE;
		init_res_v02.ctx_id = gpt_info.ctx_id;
		init_res_v02.bytes_per_sec = gpt_info.bytes_per_sec;
		init_res_v02.status = init_resp.status;

		memmove(rsp, (void*)&init_res_v02,
			sizeof(tz_sd_gpt_init_res_v02_t));
	} else {
		init_resp.cmd_id = init_req_ptr->cmd_id;
		init_resp.version = GPT_LSTNR_VERSION_1;
		init_resp.num_sectors = 0;
		init_resp.size = GPT_LISTENER_BUFFER_SIZE;
		init_resp.ctx_id = -1;
		init_resp.status = GPT_LSTNR_VER_NOT_SUPPORTED;

		memmove(rsp,  (void*)&init_resp,
			sizeof(tz_sd_gpt_init_res_t));
	}
}

/**
 * smci_gpt_handle_rw_req - Handle GPT read/write request
 * @req: Request buffer containing read/write parameters
 * @rsp: Response buffer for operation results
 *
 * Process GPT read or write operations on the specified partition context.
 * Performs sanity checks and delegates to appropriate read/write functions.
 */
static void smci_gpt_handle_rw_req(void *req, void *rsp)
{
	tz_gpt_rw_req_t *rw_req_ptr = (tz_gpt_rw_req_t *) req;
	tz_gpt_rw_res_t *rw_resp_ptr;
	uint32_t *gpt_req_buf = NULL;
	uint32_t *gpt_resp_buf = NULL;
	uint32_t res_buff_len = 0;  /* Local variable to avoid packed member address */

	if(rw_req_ptr == NULL) {
		MSGE("REQ pointer is NULL, quiting now!");
		return;
	}

	gpt_req_buf = (uint32_t*) ((char*)req + rw_req_ptr->req_buff_offset);
	gpt_resp_buf = (uint32_t*) ((char*)rsp + sizeof(tz_gpt_rw_res_t));
	rw_resp_ptr = (tz_gpt_rw_res_t *) rsp;

	MSGD("CMD:%d, ctx_id: 0x%x, start_lba: 0x%x, num_sectors: %d\n",
				rw_req_ptr->cmd_id,
				rw_req_ptr->ctx_id,
				rw_req_ptr->start_sector,
				rw_req_ptr->num_sectors);

	switch(rw_req_ptr->cmd_id) {
		case TZ_GPT_MSG_CMD_GPT_READ:
			rw_resp_ptr->status = gpt_read_func(rw_req_ptr->ctx_id,
						rw_req_ptr->start_sector,
						rw_req_ptr->num_sectors,
						gpt_resp_buf,
						&res_buff_len);
			rw_resp_ptr->res_buff_len = res_buff_len;
			break;
		case TZ_GPT_MSG_CMD_GPT_WRITE:
			rw_resp_ptr->status = gpt_write_func(rw_req_ptr->ctx_id,
						rw_req_ptr->start_sector,
						rw_req_ptr->num_sectors,
						gpt_req_buf,
						&res_buff_len);
			rw_resp_ptr->res_buff_len = res_buff_len;
			break;
	}

	rw_resp_ptr->res_buff_offset = sizeof(tz_gpt_rw_res_t);
	rw_resp_ptr->cmd_id = rw_req_ptr->cmd_id;
	rw_resp_ptr->ctx_id = rw_req_ptr->ctx_id;
	MSGD("CMD:%d, status:%d\n", rw_resp_ptr->cmd_id, rw_resp_ptr->status);
}

/**
 * smci_gpt_handle_init_gpt_partition - Handle GPT partition request
 * @req: Request buffer containing partition parameters
 * @rsp: Response buffer for partition results
 *
 * Handle GPT partition enumeration request. Currently not implemented
 * and returns error status.
 */
static void smci_gpt_handle_init_gpt_partition(void *req, void *rsp)
{
	tz_sd_gpt_partition_req_t *parti_req_ptr;
	tz_sd_gpt_partition_rsp_t *parti_resp_ptr;
	uint32_t cmd_id, dev_id, version;

	parti_req_ptr = (tz_sd_gpt_partition_req_t *)req;

	if (parti_req_ptr == NULL) {
		MSGE("REQ pointer is NULL, quiting now!");
		return;
	}

	cmd_id = parti_req_ptr->cmd_id;
	version = parti_req_ptr->version;
	dev_id = parti_req_ptr->dev_id;

	parti_resp_ptr = (tz_sd_gpt_partition_rsp_t *)rsp;

	MSGD("gpt_partition_req: version = 0x%x, dev_id = %d", version, dev_id);

	/* Currently, we are not handling this request */
	parti_resp_ptr->status = -1;
	parti_resp_ptr->cmd_id = cmd_id;
	parti_resp_ptr->num_partitions = 0;
	parti_resp_ptr->rsp_buff_offset = sizeof(tz_sd_gpt_partition_rsp_t);
}

/**
 * init - Initialize GPT service
 *
 * Initialize the GPT service by setting up MINK IPC communication,
 * registering the service listener, and preparing for GPT operations.
 *
 * Return: 0 on success, negative error code on failure
 */
int init(void)
{
	int ret = 0;
	int32_t rv = Object_OK;

	Object root = Object_NULL;
	Object client_env = Object_NULL;
	void *buf = NULL;
	size_t buf_len = 0;

	/* Initialize logging system */
	gpt_log_init("gpt_service");

	MSGD("GPT service initializing with service ID: 0x%x", GPT_SERVICE_ID);

	/* Get root environment object */
	rv = MinkCom_getRootEnvObject(&root);
	if (Object_isERROR(rv)) {
		root = Object_NULL;
		MSGE("getRootEnvObject failed: 0x%x\n", rv);
		ret = -1;
		goto err;
	}

	rv = MinkCom_getClientEnvObject(root, &client_env);
	if (Object_isERROR(rv)) {
		client_env = Object_NULL;
		MSGE("getClientEnvObject failed: 0x%x\n", rv);
		ret = -1;
		goto err;
	}

	rv = IClientEnv_open(client_env, CRegisterListenerCBO_UID,
			     &register_obj);
	if (Object_isERROR(rv)) {
		register_obj = Object_NULL;
		MSGE("IClientEnv_open failed: 0x%x\n", rv);
		ret = -1;
		goto err;
	}

	rv = MinkCom_getMemoryObject(root, TZ_MAX_BUF_LEN, &mo);
	if (Object_isERROR(rv)) {
		mo = Object_NULL;
		ret = -1;
		MSGE("getMemoryObject failed: 0x%x", rv);
		goto err;
	}

	rv = MinkCom_getMemoryObjectInfo(mo, &buf, &buf_len);
	if (Object_isERROR(rv)) {
		ret = -1;
		MSGE("getMemoryObjectInfo failed: 0x%x\n", rv);
		goto err;
	}

	/* Create CBO listener and register it */
	rv = CListenerCBO_new(&cbo, GPT_SERVICE_ID, smci_dispatch, buf, buf_len);
	if (Object_isERROR(rv)) {
		cbo = Object_NULL;
		ret = -1;
		MSGE("CListenerCBO_new failed: 0x%x\n", rv);
		goto err;
	}

	rv = IRegisterListenerCBO_register(register_obj,
					   GPT_SERVICE_ID,
					   cbo,
					   mo);
	if (Object_isERROR(rv)) {
		ret = -1;
		MSGE("IRegisterListenerCBO_register(%d) failed: 0x%x",
		     GPT_SERVICE_ID, rv);
		goto err;
	}

	Object_ASSIGN_NULL(client_env);
	Object_ASSIGN_NULL(root);

	MSGD("GPT service initialized successfully\n");
	return ret;

err:
	Object_ASSIGN_NULL(cbo);
	Object_ASSIGN_NULL(mo);
	Object_ASSIGN_NULL(register_obj);
	Object_ASSIGN_NULL(client_env);
	Object_ASSIGN_NULL(root);

	return ret;
}

/**
 * deinit - Deinitialize GPT service
 *
 * Clean up GPT service resources and unregister from MINK IPC framework.
 */
void deinit(void)
{
	MSGD("GPT service deinitializing\n");
	Object_ASSIGN_NULL(register_obj);
	Object_ASSIGN_NULL(cbo);
	Object_ASSIGN_NULL(mo);
}

/**
 * smci_dispatch - Main dispatch function for GPT service
 * @dmabuff: DMA buffer containing request/response data
 * @dma_buf_len: Length of the DMA buffer
 *
 * This function handles incoming GPT service requests from QTEE applications.
 * It parses the command ID and dispatches to appropriate handler functions
 * for GPT initialization, read, write, and partition operations.
 *
 * Return: 0 on success, negative error code on failure
 */
int smci_dispatch(void *dmabuff, size_t dma_buf_len)
{
	int ret = 0;
	int gpt_cmd_id;
	tz_gpt_rw_res_t *rw_resp_ptr;
	void *rsp = dmabuff;

	MSGD("GPT_SERVICE Dispatch starts! ");

	void *req = malloc(GPT_LISTENER_BUFFER_SIZE);
	if (!req) {
		MSGE("No memory.\n");
		return -1;
	}

	memmove(req, dmabuff, dma_buf_len);

	gpt_cmd_id = (uint32_t)(*((uint32_t *)req));
	MSGD("Received command id = %d", gpt_cmd_id);

	switch(gpt_cmd_id) {
		case TZ_GPT_MSG_CMD_GPT_READ:
		case TZ_GPT_MSG_CMD_GPT_WRITE:
			if (dma_buf_len >= sizeof(tz_gpt_rw_res_t)) {
				smci_gpt_handle_rw_req(req, rsp);
			} else {
				MSGE("Invalid input.");
				ret = -1;
			}
			break;
		case TZ_GPT_MSG_CMD_GPT_INIT:
			if (dma_buf_len >= sizeof(tz_sd_gpt_init_res_t)) {
				smci_gpt_handle_init_req(req, rsp);
			} else {
				MSGE("Invalid input.");
				ret = -1;
			}
			break;
		case TZ_GPT_MSG_CMD_GPT_PARTITION:
			if (dma_buf_len >= sizeof(tz_sd_gpt_partition_rsp_t)) {
				smci_gpt_handle_init_gpt_partition(req, rsp);
			} else {
				MSGE("Invalid input.");
				ret = -1;
			}
			break;
		default:
			MSGE("GPT command %d not supported, returning ERROR!",
					gpt_cmd_id);
			if (dma_buf_len >= sizeof(tz_gpt_rw_res_t)) {
				rw_resp_ptr = (tz_gpt_rw_res_t *)rsp;
				rw_resp_ptr->cmd_id = gpt_cmd_id;
				rw_resp_ptr->status = GPT_CMD_ID_NOT_SUPPORTED;
				rw_resp_ptr->res_buff_len = 0;
				rw_resp_ptr->res_buff_offset =
					sizeof(tz_gpt_rw_res_t);
			} else {
				MSGE("Invalid input.");
				ret = -1;
			}
			break;
	}

	MSGD("GPT_SERVICE Dispatch ends! ");

	free(req);

	return ret;
}
