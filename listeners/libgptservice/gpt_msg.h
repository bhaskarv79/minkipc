/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __GPT_MSG_H__
#define __GPT_MSG_H__

#include <stdint.h>
#include <stdio.h>

#include "gpt_logging.h"

/* Use GPT logging system */
#define MSGV(fmt, ...) GPT_LOG_DEBUG(fmt, ##__VA_ARGS__)
#define MSGE(fmt, ...) GPT_LOG_ERROR(fmt, ##__VA_ARGS__)
#define MSGD(fmt, ...) GPT_LOG_DEBUG(fmt, ##__VA_ARGS__)

/* Fixed. Don't increase the size of TZ_CM_MAX_NAME_LEN */
#define TZ_CM_MAX_NAME_LEN		256
#define TZ_CM_MAX_DATA_LEN		20000

#define TZ_MAX_BUF_LEN			(TZ_CM_MAX_DATA_LEN + 40)
#define GPT_MAX_PARTITIONS		128
#define GPT_PARTITION_NAME_LEN		72
#define GPT_GUID_SIZE			16

/* GPT Service ID - matches listener_mngr.h */
#define GPT_SERVICE_ID		0x2001

/* GPT Header structure */
typedef struct tz_gpt_header {
    uint64_t signature;           /* "EFI PART" */
    uint32_t revision;            /* GPT revision */
    uint32_t header_size;         /* Size of GPT header */
    uint32_t header_crc32;        /* CRC32 of header */
    uint32_t reserved;            /* Must be zero */
    uint64_t current_lba;         /* LBA of this header */
    uint64_t backup_lba;          /* LBA of backup header */
    uint64_t first_usable_lba;    /* First usable LBA */
    uint64_t last_usable_lba;     /* Last usable LBA */
    uint8_t disk_guid[GPT_GUID_SIZE]; /* Disk GUID */
    uint64_t partition_entries_lba;   /* LBA of partition entries */
    uint32_t num_partition_entries;   /* Number of partition entries */
    uint32_t partition_entry_size;    /* Size of each partition entry */
    uint32_t partition_entries_crc32; /* CRC32 of partition entries */
} __attribute__ ((packed)) tz_gpt_header_t;

/* GPT Partition Entry structure */
typedef struct tz_gpt_partition_entry {
    uint8_t partition_type_guid[GPT_GUID_SIZE]; /* Partition type GUID */
    uint8_t unique_partition_guid[GPT_GUID_SIZE]; /* Unique partition GUID */
    uint64_t starting_lba;        /* Starting LBA */
    uint64_t ending_lba;          /* Ending LBA */
    uint64_t attributes;          /* Partition attributes */
    uint16_t partition_name[GPT_PARTITION_NAME_LEN/2]; /* Partition name (UTF-16) */
} __attribute__ ((packed)) tz_gpt_partition_entry_t;

/* GPT Partition Info (simplified for userspace) */
typedef struct tz_gpt_partition_info {
    char name[GPT_PARTITION_NAME_LEN];  /* Partition name (UTF-8) */
    uint8_t type_guid[GPT_GUID_SIZE];   /* Partition type GUID */
    uint8_t unique_guid[GPT_GUID_SIZE]; /* Unique partition GUID */
    uint64_t start_lba;                 /* Starting LBA */
    uint64_t end_lba;                   /* Ending LBA */
    uint64_t size_bytes;                /* Size in bytes */
    uint64_t attributes;                /* Partition attributes */
    uint32_t index;                     /* Partition index */
} __attribute__ ((packed)) tz_gpt_partition_info_t;

typedef enum {
    TZ_GPT_MSG_CMD_GPT_INIT            = 0x401,
    TZ_GPT_MSG_CMD_GPT_READ,
    TZ_GPT_MSG_CMD_GPT_WRITE,
    TZ_GPT_MSG_CMD_GPT_PARTITION
} tz_gpt_msg_cmd_type;

/* GPT Init request - matches original tzservices */
typedef struct tz_sd_gpt_init_req_s {
    uint32_t cmd_id;
    uint32_t version;
    uint32_t parti_id;          /* Physical partition ID */
    uint8_t guid[16];          /* GUID for the partition */
} __attribute__ ((packed)) tz_sd_gpt_init_req_t;

/* GPT Init response - Version 1 */
typedef struct tz_sd_gpt_init_res_s {
    uint32_t cmd_id;
    uint32_t version;
    int32_t status;
    uint32_t num_sectors;      /* Size of GPT partition (in sectors) */
    uint32_t size;             /* Listener Buffer Size (in bytes) */
    uint32_t ctx_id;           /* Context ID/Handle for the GPT partition */
} __attribute__ ((packed)) tz_sd_gpt_init_res_t;

/* GPT Init response - Version 2 */
typedef struct tz_sd_gpt_init_res_v02_s {
    uint32_t cmd_id;           /* Command ID */
    uint32_t version;          /* Messaging version from GPT listener */
    uint32_t status;           /* GPT init status */
    uint32_t num_sectors;      /* Size of GPT partition (in sectors) */
    uint32_t size;             /* Listener Buffer Size (in bytes) */
    uint32_t ctx_id;           /* Context ID/Handle for the GPT partition */
    uint32_t bytes_per_sec;    /* Bytes per sector of the storage medium */
    uint32_t reserved1;        /* Reserved 1 */
    uint32_t reserved2;        /* Reserved 2 */
    uint32_t reserved3;        /* Reserved 3 */
    uint32_t reserved4;        /* Reserved 4 */
} __attribute__ ((packed)) tz_sd_gpt_init_res_v02_t;

/* GPT Read/Write request */
typedef struct tz_gpt_rw_req_s {
    uint32_t cmd_id;
    uint32_t ctx_id;           /* Context ID/Handle for the GPT partition */
    uint32_t start_sector;
    uint32_t num_sectors;
    uint32_t req_buff_len;
    uint32_t req_buff_offset;
} __attribute__ ((packed)) tz_gpt_rw_req_t;

/* GPT Read/Write response */
typedef struct tz_gpt_rw_res_s {
    uint32_t cmd_id;
    uint32_t ctx_id;           /* Context ID/Handle for the GPT partition */
    int32_t status;
    uint32_t res_buff_len;
    uint32_t res_buff_offset;
} __attribute__ ((packed)) tz_gpt_rw_res_t;

/* GPT partitioning request */
typedef struct tz_sd_gpt_partition_req_s {
    uint32_t cmd_id;           /* Command ID */
    uint32_t version;          /* GPT partition table Version */
    uint32_t dev_id;           /* Device ID for the GPT partition */
    uint8_t guid[16];          /* GUID for the partition */
} __attribute__ ((packed)) tz_sd_gpt_partition_req_t;

/* GPT partitioning response */
typedef struct tz_sd_gpt_partition_rsp_s {
    uint32_t cmd_id;           /* Command ID */
    uint32_t status;           /* GPT partitioning status */
    uint32_t num_partitions;   /* Number of partitions added */
    uint32_t rsp_buff_offset;  /* Offset to the partition addition info */
} __attribute__ ((packed)) tz_sd_gpt_partition_rsp_t;

/* Command structure for creating partition */
typedef struct tz_gpt_create_partition_req_s {
    tz_gpt_msg_cmd_type cmd_id;
    char device_path[TZ_CM_MAX_NAME_LEN];
    char partition_name[GPT_PARTITION_NAME_LEN];
    uint8_t type_guid[GPT_GUID_SIZE];
    uint64_t start_lba;
    uint64_t size_lba;
    uint64_t attributes;
} __attribute__ ((packed)) tz_gpt_create_partition_req_t;

typedef struct tz_gpt_create_partition_rsp_s {
    tz_gpt_msg_cmd_type cmd_id;
    uint32_t partition_index;
    uint8_t unique_guid[GPT_GUID_SIZE];
    int ret;
} __attribute__ ((packed)) tz_gpt_create_partition_rsp_t;

/* Command structure for deleting partition */
typedef struct tz_gpt_delete_partition_req_s {
    tz_gpt_msg_cmd_type cmd_id;
    char device_path[TZ_CM_MAX_NAME_LEN];
    char partition_name[GPT_PARTITION_NAME_LEN];
    uint32_t partition_index;  /* Use index if name is empty */
} __attribute__ ((packed)) tz_gpt_delete_partition_req_t;

typedef struct tz_gpt_delete_partition_rsp_s {
    tz_gpt_msg_cmd_type cmd_id;
    int ret;
} __attribute__ ((packed)) tz_gpt_delete_partition_rsp_t;

/* Command structure for verifying GPT integrity */
typedef struct tz_gpt_verify_integrity_req_s {
    tz_gpt_msg_cmd_type cmd_id;
    char device_path[TZ_CM_MAX_NAME_LEN];
} __attribute__ ((packed)) tz_gpt_verify_integrity_req_t;

typedef struct tz_gpt_verify_integrity_rsp_s {
    tz_gpt_msg_cmd_type cmd_id;
    uint32_t header_valid;
    uint32_t backup_header_valid;
    uint32_t partition_table_valid;
    uint32_t backup_partition_table_valid;
    int ret;
} __attribute__ ((packed)) tz_gpt_verify_integrity_rsp_t;

/* Command structure for getting disk info */
typedef struct tz_gpt_get_disk_info_req_s {
    tz_gpt_msg_cmd_type cmd_id;
    char device_path[TZ_CM_MAX_NAME_LEN];
} __attribute__ ((packed)) tz_gpt_get_disk_info_req_t;

typedef struct tz_gpt_get_disk_info_rsp_s {
    tz_gpt_msg_cmd_type cmd_id;
    uint64_t total_sectors;
    uint32_t sector_size;
    uint64_t total_size_bytes;
    uint32_t num_partitions;
    uint8_t disk_guid[GPT_GUID_SIZE];
    int ret;
} __attribute__ ((packed)) tz_gpt_get_disk_info_rsp_t;

/* Command structure for GPT end */
typedef struct tz_gpt_end_req_s {
    tz_gpt_msg_cmd_type cmd_id;
} __attribute__ ((packed)) tz_gpt_end_req_t;

typedef struct tz_gpt_end_rsp_s {
    tz_gpt_msg_cmd_type cmd_id;
    int ret;
} __attribute__ ((packed)) tz_gpt_end_rsp_t;

/* Error response structure */
typedef struct tz_gpt_err_rsp_s {
    tz_gpt_msg_cmd_type cmd_id;
    int ret;
} __attribute__ ((packed)) tz_gpt_err_rsp_t;

#endif /* __GPT_MSG_H__ */
