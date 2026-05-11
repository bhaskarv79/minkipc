// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <mntent.h>
#include <dirent.h>
#include <libgen.h>
#include <time.h>

#include "cmn.h"
#include "helper.h"

#ifdef USE_GLIB
#include <glib.h>
#define strlcat g_strlcat
#define strlcpy g_strlcpy
#endif

#define WHITE_LIST_SIZE 4
static char *gp_whitelist_paths[] = {
	"/data/system/users/",
	"/data/misc/qsee/",
	"/vendor/data/",
	"/data/qwes/licenses/"
};

static bool should_log(void) {
    static int tokens = 1; // Max burst
    static long last_time = 0;
    const int RATE_LIMIT_MS = 5000; // 5 second interval
    const int MAX_BURST = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long now = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    // Replenish tokens based on time passed
    if (now - last_time > RATE_LIMIT_MS) {
        tokens = MAX_BURST;
        last_time = now;
    }

    if (tokens > 0) {
        tokens--;
        return true;
    }
    return false; // Rate limited
}

static void rate_limited_log(const char *msg) {
    if (should_log()) {
        MSGE("%s", msg);
    }
}

bool is_persist_partition_mounted(void)
{
	FILE *f;
	struct mntent *entry;

	if (NULL == (f = fopen("/proc/mounts", "rb"))) {
		MSGE("Error: open /proc/mounts failed!\n");
		goto exit;
	}

	while ((entry = getmntent(f))) {
		if (strcmp(entry->mnt_dir, PERSIST_MOUNT_PATH) == 0)
			goto exit;
	}
	rate_limited_log("WARN: Persist partition not mounted!\n"
			 "WARN: Writing to root filesystem path /var/lib/tee..\n"
			 "WARN: Secure files could be lost if root filesystem "
			 "is corrupted or wiped out by administrator!\n");

exit:
	if (f)
		endmntent(f);
	return true;
}

int check_dir_path(const char *path)
{
	int ret = -1;
	char *dirc = NULL;
	char *dname = NULL;
	DIR *dfd = NULL;

	if (path == NULL)
		return -1;

	dirc = strndup(path, strlen(path));
	dname = dirname(dirc);
	if (dname == NULL)
		goto path_fail;

	dfd = opendir(dname);
	if (dfd != NULL) {
		ret = 0;
		closedir(dfd);
	}

path_fail:
	free(dirc);
	return ret;
}

bool is_persist_path_need_append(const char *path)
{
	int compare = 0;

	if (!path)
		return false;

	compare = strncmp(LEGACY_PERSIST_PATH, path, strlen(LEGACY_PERSIST_PATH));
	if (compare == 0) {
		MSGD("%s is a legacy persist path\n", path);
		return true;
	}

	MSGD("%s is not a legacy persist path\n", path);
	return false;
}

bool is_whitelist_path(const char *path)
{
	size_t i = 0;
	if (!path)
		return false;

	for (i = 0; i < WHITE_LIST_SIZE; i++) {
		if (strncmp(gp_whitelist_paths[i], path,
			    strlen(gp_whitelist_paths[i])) == 0) {
			return true;
		}
	}

	MSGD("%s is not part of whitelist paths\n", path);
	return false;
}

/**
 * @brief Checks if the path length is valid for appending a prefix.
 *
 * @param old_len Length of the original path.
 * @param prefix_len Length of the prefix to be added.
 * @param new_len Length of the new path buffer.
 * @return true if valid, false otherwise.
 */
static bool is_valid_path_length(size_t old_len, size_t prefix_len,
				 size_t new_len)
{
	return (old_len + prefix_len < TZ_FILE_DIR_LEN &&
		old_len <= SIZE_MAX - prefix_len &&
		new_len == TZ_FILE_DIR_LEN);
}

/**
 * @brief Prepends a prefix to the old path and stores it in new_path.
 *
 * @param prefix The prefix to prepend (e.g., DATA_PATH or PERSIST_PATH).
 * @param old_path The original path.
 * @param new_path The buffer to store the new path.
 */
static void prepend_path(const char *prefix, const char *old_path,
			 char *new_path)
{
	memset(new_path, 0, TZ_FILE_DIR_LEN);
	strlcpy(new_path, prefix, TZ_FILE_DIR_LEN);
	if (old_path[0] == '/')
		strlcat(new_path, old_path + 1, TZ_FILE_DIR_LEN);
	else
		strlcat(new_path, old_path, TZ_FILE_DIR_LEN);
}

/**
 * @brief Check if the persist path needs to be modified.

 * Some Trusted Applications pass legacy mount point paths for persist partition
 * such as /var/persist. This function checks if the mount point path needs
 * to be updated to re-direct to a new path, such as /var/lib/tee.
 *
 * @param path The path possibly prefixed with legacy mount point.
 */
static bool is_persist_path_need_modify(const char *path)
{
	int compare = 0;

	if (!path)
		return false;

	compare = strncmp(OLD_PERSIST_MOUNT_PATH, path, strlen(OLD_PERSIST_MOUNT_PATH));
	if (compare == 0) {
		MSGD("%s is an old persist mount path\n", path);
		return true;
	}

	MSGD("%s is not an old persist mount path\n", path);
	return false;
}

/**
 * @brief Modify the persist path to re-direct to a new mount point.

 * Some Trusted Applications pass legacy mount point paths for persist partition
 * such as /var/persist. This function modifies the mount point path to
 * re-direct to a new path, such as /var/lib/tee.
 *
 * @param prefix The new mount point path (e.g., /var/lib/tee).
 * @param old_path The original path with the legacy mount point.
 * @param new_path The buffer to store the new path.
 */
static void modify_path(const char *prefix, const char *old_path,
                        char *new_path)
{
	memset(new_path, 0, TZ_FILE_DIR_LEN);
	strlcpy(new_path, prefix, TZ_FILE_DIR_LEN);
	strlcat(new_path, old_path + strlen(OLD_PERSIST_MOUNT_PATH), TZ_FILE_DIR_LEN);
}

char *get_resolved_path(char *old_path, size_t old_len, char *new_path,
			size_t new_len)
{
	if (check_dir_path(old_path) == 0) {
		MSGD("Directory exists and permissions already present, "
		     "no need to append\n");
		return old_path;
	}

	if (is_whitelist_path(old_path)) {
		if (!is_valid_path_length(old_len, strlen(DATA_PATH),
					  new_len)) {
			MSGE("get_resolved_path() failed to prepend DATA_PATH "
			     "for %s (old_len=%zu, new_len=%zu)\n",
			     old_path, old_len, new_len);
			return old_path;
		}

		prepend_path(DATA_PATH, old_path, new_path);
		MSGD("get_resolved_path : old_path(%s) to new_vendor_path(%s)\n",
		     old_path, new_path);
		MSGD("get_resolved_path : old_pathlen =%zu, new_vendor_path_len=%zu\n",
		     strlen(old_path), strlen(new_path));
		return new_path;
	}

	if (is_persist_path_need_modify(old_path)) {
		modify_path(PERSIST_MOUNT_PATH, old_path, new_path);
		return new_path;
	}

	if (is_persist_path_need_append(old_path)) {
		if (!is_valid_path_length(old_len, strlen(PERSIST_PATH),
					  new_len)) {
			MSGE("get_resolved_path() failed to prepend PERSIST_PATH "
			     "for %s (old_len=%zu, new_len=%zu)\n",
			     old_path, old_len, new_len);
			return old_path;
		}

		prepend_path(PERSIST_PATH, old_path, new_path);
		MSGD("get_resolved_path : old_path(%s) to new_vendor_path(%s)\n",
		     old_path, new_path);
		MSGD("get_resolved_path : old_pathlen =%zu, new_vendor_path_len=%zu\n",
		     strlen(old_path), strlen(new_path));
		return new_path;
	}

	MSGD("Path %s is not in whitelist paths, not prepending\n", old_path);
	return old_path;
}
