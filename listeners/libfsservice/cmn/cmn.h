// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef __FS_CMN_H_
#define __FS_CMN_H_

#include <stdio.h>

#define MSGV(...)
#define MSGD(...)
#define MSGE printf

#define UNUSED(x) (void)(x)

/* Request/Response buffer size */
#define TZ_CM_MAX_NAME_LEN      256   /**< Fixed. Don't increase the size. */
#define TZ_CM_MAX_DATA_LEN      20000
#define TZ_MAX_BUF_LEN          (TZ_CM_MAX_DATA_LEN + 40)
#define TZ_GP_MAX_BUF_LEN       (504 * 1024)

#define TZ_FILE_DIR_LEN         256
#define TZ_FILE_NAME_LEN        128

/* Error Codes */
#define FS_ERROR_NO_CMD         -1
#define GPFS_ERROR_NO_CMD       -1

/* GP Defines */
#define BAK                     ".bak"
#define MAX_READ_SIZE           (64 * 1024)
#define DATA_VENDOR_PATH        "/data/vendor"
#define LEGACY_DATA_PATH        "/data/misc/qsee/"
#define LEGACY_PERSIST_PATH     "/persist/data/"
#define DATA_PATH               "/var/tmp/qtee_supplicant/vendor/tzstorage/"
#define PERSIST_PATH            "/var/lib/tee/qtee_supplicant/"
#define PERSIST_MOUNT_PATH      "/var/lib/tee"

/* Secure File System - version 2 */
#define GP_FS_VERSION           2

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
#endif

static inline int memsmove(void *dest, size_t dest_len, const void *src,
			   size_t src_len)
{
	if (src_len <= dest_len) {
		memmove(dest, src, src_len);
		return 0;
	} else {
		return -1;
	}
}

static inline int memscpy(void *dest, size_t dest_len, const void *src,
			  size_t src_len)
{
	if (src_len <= dest_len) {
		memcpy(dest, src, src_len);
		return 0;
	} else {
		return -1;
	}
}

#endif // __FS_CMN_H_
