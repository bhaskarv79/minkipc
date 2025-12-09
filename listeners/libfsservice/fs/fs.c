// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include <errno.h>

#include "fs_msg.h"
#include "cmn.h"
#include "fs.h"
#include "helper.h"

#ifdef USE_GLIB
#include <glib.h>
#define strlcat g_strlcat
#define strlcpy g_strlcpy
#endif

static int error_number;

static int rmdir_h(char *);
static int mkdir_h(const char *);
static int dir_exists(char *);

static int file_preopen(const char *path_name)
{
	int path_len = 0;
	char path[TZ_FILE_DIR_LEN + 1] = { 0 };

	MSGD("calling file_preopen %s\n", path_name);

	path_len = strlen(path_name);
	if (path_len >= TZ_FILE_DIR_LEN || path_len < 0) {
		error_number = EINVAL;
		return -1;
	}

	if (memscpy((void *)path, ARRAY_SIZE(path),
		    (void *)path_name, path_len)) {
		error_number = EFAULT;
		MSGE("Invalid buffer len in memscpy %s, %d\n",
		     __func__, __LINE__);
		return -EINVAL;
	}

	while (path_len > 0) {
		if (path[path_len - 1] == '/') {
			path[path_len] = '\0';
			break;
		}
		path_len--;
	}

	/* This condition implies that the pathname from QTEE did not
	 * have a trailing forward-slash /
	 */
	if (path_len == 0) {
		error_number = EINVAL;
		return -1;
	}

	MSGD("file_preopen : path_len = %d\n", path_len);
	return mkdir_h(path);
}

int file_open(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_open_req_t *my_req = (tz_file_open_req_t *)req;
	tz_file_open_rsp_t *my_rsp = (tz_file_open_rsp_t *)rsp;
	char *path_name = my_req->pathname;
	int flags = my_req->flags;
	int ret_val = -1;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };

	MSGD("calling file_open %s, flag = %d\n", path_name, flags);

	path_name = get_resolved_path(my_req->pathname,
				    strlen(my_req->pathname),
				    new_vendor_path,
				    TZ_FILE_DIR_LEN);

	if (req_len < sizeof(tz_file_open_req_t) ||
	    rsp_len < sizeof(tz_file_open_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	if (flags & O_CREAT) {
		ret_val = file_preopen(path_name);
		if (ret_val != 0) {
			my_rsp->ret = -1;
			/* file_preopen() sets error_number internally */
			my_rsp->cmd_id = TZ_FS_MSG_CMD_FILE_OPEN;
			MSGE("Error: file_open failed!\n");
			return 0;
		}
	}

	my_rsp->ret = open(path_name, flags, S_IRUSR | S_IWUSR);
	if (my_rsp->ret < 0)
		error_number = errno;

	my_rsp->cmd_id = TZ_FS_MSG_CMD_FILE_OPEN;

	MSGD("file_open %s is done and returns %d\n",
	     path_name, my_rsp->ret);

	return 0;
}

int file_openat(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_openat_req_t *my_req = (tz_file_openat_req_t *)req;
	tz_file_openat_rsp_t *my_rsp = (tz_file_openat_rsp_t *)rsp;
	int dir_fd = my_req->dirfd;
	char *path_name = my_req->pathname;
	int flags = my_req->flags;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };

	MSGD("calling file_openat!\n");

	if (req_len < sizeof(tz_file_openat_req_t) ||
	    rsp_len < sizeof(tz_file_openat_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	path_name = get_resolved_path(my_req->pathname,
				    strlen(my_req->pathname),
				    new_vendor_path,
				    TZ_FILE_DIR_LEN);

	my_rsp->ret = openat(dir_fd, path_name, flags,
			     S_IRUSR | S_IWUSR);
	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_openat failed %d\n", errno);
	}

	MSGD("file_openat is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_unlinkat(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_unlinkat_req_t *my_req = (tz_file_unlinkat_req_t *)req;
	tz_file_unlinkat_rsp_t *my_rsp = (tz_file_unlinkat_rsp_t *)rsp;
	int dir_fd = my_req->dirfd;
	const char *path_name = my_req->pathname;
	int flags = my_req->flags;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };

	MSGD("calling file_unlinkat!\n");

	if (req_len < sizeof(tz_file_unlinkat_req_t) ||
	    rsp_len < sizeof(tz_file_unlinkat_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	path_name = get_resolved_path(my_req->pathname,
				    strlen(my_req->pathname),
				    new_vendor_path,
				    TZ_FILE_DIR_LEN);

	my_rsp->ret = unlinkat(dir_fd, path_name, flags);
	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_unlinkat failed %d\n", errno);
	}

	MSGD("file_unlinkat is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_creat(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_creat_req_t *my_req = (tz_file_creat_req_t *)req;
	tz_file_creat_rsp_t *my_rsp = (tz_file_creat_rsp_t *)rsp;
	char *path_name = my_req->pathname;
	mode_t mode = (mode_t)my_req->mode;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };

	MSGD("calling file_creat!\n");

	if (req_len < sizeof(tz_file_creat_req_t) ||
	    rsp_len < sizeof(tz_file_creat_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	path_name = get_resolved_path(my_req->pathname,
				    strlen(my_req->pathname),
				    new_vendor_path,
				    TZ_FILE_DIR_LEN);

	my_rsp->ret = creat(path_name, mode);
	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_creat failed %d\n", errno);
	}

	MSGD("file_creat is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_read(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_read_req_t *my_req = (tz_file_read_req_t *)req;
	tz_file_read_rsp_t *my_rsp = (tz_file_read_rsp_t *)rsp;
	int fd = my_req->fd;
	uint8_t *buf = my_rsp->buf;
	size_t count = (size_t)my_req->count;

	MSGD("calling file_read!\n");

	if (req_len < sizeof(tz_file_read_req_t) ||
	    rsp_len < sizeof(tz_file_read_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	MSGD("file_read: the size to read is %zu\n", count);

	if (count <= TZ_CM_MAX_DATA_LEN)
		my_rsp->ret = read(fd, buf, count);
	else
		my_rsp->ret = read(fd, buf, TZ_CM_MAX_DATA_LEN);

	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_read failed %d\n", errno);
	}

	MSGD("file_read is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_write(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_write_req_t *my_req = (tz_file_write_req_t *)req;
	tz_file_write_rsp_t *my_rsp = (tz_file_write_rsp_t *)rsp;
	int fd = my_req->fd;
	const void *buf = my_req->buf;
	size_t count = (size_t)my_req->count;

	MSGD("calling file_write!\n");

	if (req_len < sizeof(tz_file_write_req_t) ||
	    rsp_len < sizeof(tz_file_write_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	MSGD("file_write: the size to write is %zu\n", count);

	if (count <= TZ_CM_MAX_DATA_LEN) {
		my_rsp->ret = write(fd, buf, count);
	} else {
		my_rsp->ret = write(fd, buf, TZ_CM_MAX_DATA_LEN);
	}

	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_write failed %d\n", errno);
	}

	MSGD("file_write is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_fstat(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_fstat_req_t *my_req = (tz_file_fstat_req_t *)req;
	tz_file_fstat_rsp_t *my_rsp = (tz_file_fstat_rsp_t *)rsp;
	int file_des = my_req->filedes;
	struct stat buf;

	MSGD("calling file_fstat!\n");

	if (req_len < sizeof(tz_file_fstat_req_t) ||
	    rsp_len < sizeof(tz_file_fstat_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	if (fstat(file_des, &buf) == -1) {
		my_rsp->ret = -1;
	} else {
		my_rsp->buf.st_dev = (uint64_t)buf.st_dev;
		my_rsp->buf.st_mode = (unsigned int)buf.st_mode;
		my_rsp->buf.st_nlink = (unsigned int)buf.st_nlink;
		my_rsp->buf.st_uid = (uint32_t)buf.st_uid;
		my_rsp->buf.st_gid = (uint32_t)buf.st_gid;
		my_rsp->buf.st_rdev = (uint64_t)buf.st_rdev;
		my_rsp->buf.st_size = (int64_t)buf.st_size;
		my_rsp->buf.st_blksize = (uint32_t)buf.st_blksize;
		my_rsp->buf.st_blocks = (uint64_t)buf.st_blocks;
		my_rsp->buf.st_atim = (uint32_t)((struct timespec)buf.st_atim).tv_sec;
		my_rsp->buf.st_atim_nsec = (uint32_t)((struct timespec)buf.st_atim).tv_nsec;
		my_rsp->buf.st_mtim = (uint32_t)((struct timespec)buf.st_mtim).tv_sec;
		my_rsp->buf.st_mtim_nsec = (uint32_t)((struct timespec)buf.st_mtim).tv_nsec;
		my_rsp->buf.st_ctim = (uint32_t)((struct timespec)buf.st_ctim).tv_sec;
		my_rsp->buf.st_ctim_nsec = (uint32_t)((struct timespec)buf.st_ctim).tv_nsec;
		my_rsp->buf.st_ino = (uint64_t)buf.st_ino;
#if !defined(__aarch64__)
		memset(my_rsp->buf.__pad0, 0, sizeof(my_rsp->buf.__pad0));
		my_rsp->buf.__st_ino = 0;
		memset(my_rsp->buf.__pad3, 0, sizeof(my_rsp->buf.__pad3));
#endif
		my_rsp->ret = 0;
	}

	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_fstat failed %d\n", errno);
	}

	MSGD("file_fstat: st_size = %ld\n", my_rsp->buf.st_size);
	return 0;
}

int file_lstat(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_lstat_req_t *my_req = (tz_file_lstat_req_t *)req;
	tz_file_lstat_rsp_t *my_rsp = (tz_file_lstat_rsp_t *)rsp;
	const char *path = my_req->path;
	struct stat buf;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };

	MSGD("calling file_lstat!\n");
	MSGD("path = %s\n", path);

	if (req_len < sizeof(tz_file_lstat_req_t) ||
	    rsp_len < sizeof(tz_file_lstat_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	path = get_resolved_path(my_req->path, strlen(my_req->path),
			       new_vendor_path, TZ_FILE_DIR_LEN);

	if (lstat(path, &buf) == -1) {
		my_rsp->ret = -1;
	} else {
		my_rsp->buf.st_dev = (uint64_t)buf.st_dev;
		my_rsp->buf.st_mode = (unsigned int)buf.st_mode;
		my_rsp->buf.st_nlink = (unsigned int)buf.st_nlink;
		my_rsp->buf.st_uid = (uint32_t)buf.st_uid;
		my_rsp->buf.st_gid = (uint32_t)buf.st_gid;
		my_rsp->buf.st_rdev = (uint64_t)buf.st_rdev;
		my_rsp->buf.st_size = (int64_t)buf.st_size;
		my_rsp->buf.st_blksize = (uint32_t)buf.st_blksize;
		my_rsp->buf.st_blocks = (uint64_t)buf.st_blocks;
		my_rsp->buf.st_atim = (uint32_t)((struct timespec)buf.st_atim).tv_sec;
		my_rsp->buf.st_atim_nsec = (uint32_t)((struct timespec)buf.st_atim).tv_nsec;
		my_rsp->buf.st_mtim = (uint32_t)((struct timespec)buf.st_mtim).tv_sec;
		my_rsp->buf.st_mtim_nsec = (uint32_t)((struct timespec)buf.st_mtim).tv_nsec;
		my_rsp->buf.st_ctim = (uint32_t)((struct timespec)buf.st_ctim).tv_sec;
		my_rsp->buf.st_ctim_nsec = (uint32_t)((struct timespec)buf.st_ctim).tv_nsec;
		my_rsp->buf.st_ino = (uint64_t)buf.st_ino;
#if !defined(__aarch64__)
		memset(my_rsp->buf.__pad0, 0, sizeof(my_rsp->buf.__pad0));
		my_rsp->buf.__st_ino = 0;
		memset(my_rsp->buf.__pad3, 0, sizeof(my_rsp->buf.__pad3));
#endif
		my_rsp->ret = 0;
	}

	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_lstat failed %d\n", errno);
	}

	MSGD("in file_lstat st_size = %ld\n", my_rsp->buf.st_size);
	return 0;
}

int file_link(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_link_req_t *my_req = (tz_file_link_req_t *)req;
	tz_file_link_rsp_t *my_rsp = (tz_file_link_rsp_t *)rsp;
	char *old_path = NULL;
	char old_vendor_path[TZ_FILE_DIR_LEN] = { 0 };
	char *new_path = NULL;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };

	MSGD("calling file_link!\n");

	if (req_len < sizeof(tz_file_link_req_t) ||
	    rsp_len < sizeof(tz_file_link_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	old_path = get_resolved_path(my_req->oldpath,
				   strlen(my_req->oldpath),
				   old_vendor_path,
				   TZ_FILE_DIR_LEN);

	new_path = get_resolved_path(my_req->newpath,
				   strlen(my_req->newpath),
				   new_vendor_path,
				   TZ_FILE_DIR_LEN);

	my_rsp->ret = link(old_path, new_path);
	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_link failed %d\n", errno);
	}

	MSGD("file_link is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_unlink(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_unlink_req_t *my_req = (tz_file_unlink_req_t *)req;
	tz_file_unlink_rsp_t *my_rsp = (tz_file_unlink_rsp_t *)rsp;
	char *path = my_req->pathname;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };

	MSGD("calling file_unlink!\n");

	if (req_len < sizeof(tz_file_unlink_req_t) ||
	    rsp_len < sizeof(tz_file_unlink_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	path = get_resolved_path(my_req->pathname,
			       strlen(my_req->pathname),
			       new_vendor_path,
			       TZ_FILE_DIR_LEN);

	my_rsp->ret = unlink(path);
	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_unlink failed %d\n", errno);
	}

	MSGD("file_unlink is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_close(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_close_req_t *my_req = (tz_file_close_req_t *)req;
	tz_file_close_rsp_t *my_rsp = (tz_file_close_rsp_t *)rsp;
	int fd = my_req->fd;

	MSGD("calling file_close!\n");

	if (req_len < sizeof(tz_file_close_req_t) ||
	    rsp_len < sizeof(tz_file_close_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	my_rsp->ret = close(fd);
	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_close failed %d\n", errno);
	}

	MSGD("file_close is done and returns = %d\n", my_rsp->ret);
	return 0;
}

/**
 * @brief Helper function to allocate and copy the pathname into a new null
 *	terminated buffer.
 *
 * @param path_name Path name of the file or directory to remove.
 * @return On failure, returns NULL and sets error_number.
 */
static char *prepare_path_copy(const char *path_name)
{
	int len = strlen(path_name);
	if (len == 0 || len >= TZ_FILE_DIR_LEN) {
		error_number = EINVAL;
		return NULL;
	}

	char *copy = malloc(len + 1);
	if (!copy) {
		error_number = ENOMEM;
		return NULL;
	}

	if (memscpy(copy, len + 1, path_name, len + 1)) {
		error_number = EFAULT;
		free(copy);
		return NULL;
	}

	copy[len] = '\0';
	return copy;
}

/**
 * @brief Helper function to removes a file or directory based on the path type.
 *
 * @param path_name Path name of the file or directory to remove.
 * @param path_copy Null-terminated version of path_name.
 * @return On failure, returns -1 and sets error_number.
 */
static int remove_file_or_dir(const char *path_name, char *path_copy)
{
	char ptr[500] = { 0 };
	int ret_val;

	if (dir_exists(path_copy) == -1) {
		return unlink(path_name);
	}

	ret_val = snprintf(ptr, sizeof(ptr), "%s", path_name);
	if (ret_val < 0 || (unsigned int)ret_val >= sizeof(ptr)) {
		error_number = -EFAULT;
		return -1;
	}

	/* rmdir_h() sets error_number internally on failure */
	return rmdir_h(ptr);
}

int file_remove(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_remove_req_t *my_req = (tz_file_remove_req_t *)req;
	tz_file_remove_rsp_t *my_rsp = (tz_file_remove_rsp_t *)rsp;
	char *path_name = my_req->pathname;
	char new_vendor_path[TZ_FILE_DIR_LEN] = { 0 };
	char *path_copy = NULL;

	MSGD("calling file_remove!\n");

	if (req_len < sizeof(tz_file_remove_req_t) ||
	    rsp_len < sizeof(tz_file_remove_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	if (path_name == NULL) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		return 0;
	}

	path_name = get_resolved_path(path_name, strlen(path_name),
				    new_vendor_path, TZ_FILE_DIR_LEN);

	if (strlen(path_name) == 0 ||
	    strlen(path_name) >= TZ_FILE_DIR_LEN) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		return 0;
	}

	/* path_copy is a NULL terminated version of path_name to be passed to
	 * dir_exists() later */
	path_copy = prepare_path_copy(path_name);
	if (!path_copy) {
		my_rsp->ret = -1;
		/* error_number set by function on failure */
		MSGE("prepare_path_copy failed %d\n", error_number);
		return 0;
	}

	MSGD("pathname = %s\n", path_name);

	my_rsp->ret = remove_file_or_dir(path_name, path_copy);
	if (my_rsp->ret < 0) {
		/* error_number set by function on failure */
		MSGE("remove_file_or_directory failed %d\n", error_number);
	}

	free(path_copy);
	MSGD("file_remove is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_rename(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_rename_req_t *my_req = (tz_file_rename_req_t *)req;
	tz_file_rename_rsp_t *my_rsp = (tz_file_rename_rsp_t *)rsp;
	char old_vendor_path[TZ_FILE_DIR_LEN] = {0};
	char new_vendor_path[TZ_FILE_DIR_LEN] = {0};
	char *old_name = NULL;
	char *new_name = NULL;

	if (req_len < sizeof(tz_file_rename_req_t) ||
	    rsp_len < sizeof(tz_file_rename_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	MSGD("rename old %s, new %s!\n", my_req->oldfilename, my_req->newfilename);

	if (strlen(my_req->oldfilename) >= TZ_CM_MAX_NAME_LEN ||
	    strlen(my_req->newfilename) >= TZ_CM_MAX_NAME_LEN) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("file_rename: file name is too long\n");
		return 0;
	}

	old_name = get_resolved_path(my_req->oldfilename,
				   strlen(my_req->oldfilename),
				   old_vendor_path,
				   TZ_FILE_DIR_LEN);

	new_name = get_resolved_path(my_req->newfilename,
				   strlen(my_req->newfilename),
				   new_vendor_path,
				   TZ_FILE_DIR_LEN);

	my_rsp->cmd_id = TZ_FS_MSG_CMD_FILE_RENAME;
	MSGD("calling rename old %s, new %s!\n", old_name, new_name);
	my_rsp->ret = rename(old_name, new_name);

	if (my_rsp->ret < 0)
		error_number = errno;

	MSGD("file_rename is done, and returns %d\n", my_rsp->ret);

	return 0;
}

int file_error(void *rsp, size_t rsp_len)
{
	tz_file_err_rsp_t *my_rsp = (tz_file_err_rsp_t *)rsp;
	MSGD("calling %s!\n", __func__);

	if (rsp_len < sizeof(tz_file_err_rsp_t)) {
		MSGE("%s Invalid buffer length.\n", __func__);
		return -1;
	}

	my_rsp->ret = FS_ERROR_NO_CMD;

	MSGD("%s is done and returns = %d\n", __func__, my_rsp->ret);
	return 0;
}

size_t file_partition_error(uint32_t id, void *rsp)
{
	MSGD("calling %s!\n", __func__);

	size_t size = 0;

	switch (id) {
	case TZ_FS_MSG_CMD_FILE_READ:
		((tz_file_read_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_file_read_rsp_t);
		break;
	case TZ_FS_MSG_CMD_FILE_FSTAT:
		((tz_file_fstat_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_file_fstat_rsp_t);
		break;
	case TZ_FS_MSG_CMD_FILE_LSTAT:
		((tz_file_lstat_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_file_lstat_rsp_t);
		break;
	case TZ_FS_MSG_CMD_FILE_PAR_FR_SIZE:
		((tz_file_par_free_size_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_file_par_free_size_rsp_t);
		break;
	case TZ_FS_MSG_CMD_DIR_OPEN:
		((tz_dir_open_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_dir_open_rsp_t);
		break;
	case TZ_FS_MSG_CMD_DIR_READ:
		((tz_dir_read_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_dir_read_rsp_t);
		break;
	case TZ_FS_MSG_CMD_DIR_CLOSE:
		((tz_dir_close_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_dir_close_rsp_t);
		break;
	default:
		((tz_file_err_rsp_t *)rsp)->ret = -1;
		size = sizeof(tz_file_err_rsp_t);
		break;
	}

	error_number = EAGAIN;

	MSGD("%s is done and returns EAGAIN\n", __func__);

	return size;
}

/**
 * @brief Recursively removes a directory and its contents.
 * @param dir_input Path to the directory to remove.
 * @return 0 on success, -1 on failure.
 */
static int rmdir_h(char *dir_input)
{
	DIR *pdir = NULL;
	struct dirent *pent = NULL;
	struct stat estat;
	char path[512] = {0};
	char x[512] = {0};
	int ret = 0;
	int pret_val = -1;

	if (strlen(dir_input) + 1 >= sizeof(path)) {
		MSGD("path too long: %s\n", dir_input);
		error_number = EINVAL;
		return -1;
	}

	if (memscpy(path, sizeof(path), dir_input,
		    strlen(dir_input) + 1)) {
		MSGE("memscpy failed %s, %d\n", __func__, __LINE__);
		error_number = EFAULT;
		return -1;
	}

	// Adding null termination to string.
	path[strlen(dir_input) + 1] = '\0';

	MSGD("rmdir_h: path = %s\n", path);

	pdir = opendir(path);

	// Directory does not exist
	if (pdir == NULL) {
		MSGD("Directory does not exist\n");
		error_number = errno;
		return -1;
	}

	// Consider each dir/file in a directory
	while ((pent = readdir(pdir)) != NULL) {
		// Skip . or ..
		// Note: not necessary because given absolute path?
		if ((strcmp(pent->d_name, ".") == 0) ||
		    (strcmp(pent->d_name, "..") == 0)) {
			MSGD("Skipping: %s\n", pent->d_name);
			continue;
		}

		// Entering first non . or .. file
		MSGD("Processing: %s\n", pent->d_name);

		ret = snprintf(x, sizeof(x), "%s", path);
		if (ret < 0 || (unsigned int) ret >= sizeof(x)) {
			MSGE("snprintf failed\n");
			break;
		}

		// Update path to the first entry in the directory
		if (strcmp(&path[strlen(path) - 1], "/") != 0) {
			if (strlcat(path, "/", sizeof(path)) >= sizeof(path)) {
				MSGE("strlcat failed\n");
				break;
			}
		}

		if (strlcat(path, pent->d_name, sizeof(path)) >= sizeof(path)) {
			MSGE("strlcat failed\n");
			break;
		}

		if (stat(path, &estat)) {
			MSGE("stat failed: %s\n", strerror(errno));
			pret_val = 0;
			continue;
		}

		// If entry is a directory, make recursive call
		if (S_ISDIR(estat.st_mode)) {
			MSGD("Recursing into: %s\n", path);
			rmdir_h(path);

			// Restore previous path
			ret = snprintf(path, sizeof(path), "%s", x);
			if (ret < 0 || (unsigned int) ret >= sizeof(path)) {
				MSGE("snprintf failed\n");
				break;
			}

			pret_val = 0;
			continue;
		}

		// If entry is a file, unlink the file
		unlink(path);
		MSGD("Unlinked: %s\n", path);

		// Restore previous path
		ret = snprintf(path, sizeof(path), "%s", x);
		if (ret < 0 || (unsigned int)ret >= sizeof(path)) {
			MSGE("snprintf failed\n");
			break;
		}

		MSGD("Restored path: %s\n", path);
		pret_val = 0;
	}

	if (pdir != NULL)
		closedir(pdir);

	/* All string op failures in rmdir_h will result in failure here.
	 * hence we can just log the final error_number here.
	 */
	if (rmdir(path)) {
		pret_val = -1;
		error_number = errno;
	} else {
		pret_val = 0;
	}

	return pret_val;
}


/**
 * @brief Checks if a directory exists.
 * @param dirname Path to the directory.
 * @return 0 if the directory exists, -1 otherwise.
 */
static int dir_exists(char *dirname)
{
	int ret_val = 0;
	char *temp_dir = NULL;
	unsigned int len = 0;
	DIR *dfd = NULL;

	if (strcmp(dirname, DATA_VENDOR_PATH) == 0 ||
	    strcmp(dirname, DATA_PATH) == 0) {
		MSGD("ignore checking path: %s\n", dirname);
		return ret_val;
	}

	len = strlen(dirname);
	temp_dir = malloc(len + 1);
	if (temp_dir == NULL) {
		ret_val = -1;
		error_number = ENOMEM;
		MSGE("Error: malloc failed!\n");
		goto exit;
	}

	if (memscpy(temp_dir, len + 1, dirname, len)) {
		free(temp_dir);
		error_number = EFAULT;
		MSGE("Invalid buffer len in memscpy %s, %d\n", __func__,
		     __LINE__);
		return -1;
	}

	temp_dir[len] = '\0';
	dfd = opendir((const char *)temp_dir);

	MSGD("calling dir_exists!\n");
	MSGD("opening dir %s\n", temp_dir);

	if (dfd != NULL) {
		ret_val = 0;
		closedir(dfd);
	} else {
		ret_val = -1;
		error_number = errno;
		MSGD("dir %s does not exist!\n", temp_dir);
		goto exit;
	}

	MSGD("dir %s exists, return 0\n", temp_dir);

exit:
	if (temp_dir != NULL)
		free(temp_dir);

	return ret_val;
}

/**
 * @brief Recursively creates a directory and its parent directories.
 * @param p_dir Path to the directory to create.
 * @return 0 on success, -1 or -EINVAL on failure.
 */
static int mkdir_h(const char *p_dir)
{
	uint32_t len_folder = 0;
	uint32_t len_travel = 0;
	char *directory = NULL;
	char *cur_pos = NULL;
	uint32_t len_dir = 0;
	int ret_val = -1;

	// Verify path validity
	if ((p_dir == NULL) || (p_dir[0] == '\0')) {
		error_number = EINVAL;
		MSGE("input dir in mkdir_h is null, return -1\n");
		return ret_val;
	}

	MSGD("calling mkdir_h, path = %s\n", p_dir);

	len_dir = strlen(p_dir);

	if (len_dir >= TZ_FILE_DIR_LEN) {
		error_number = EINVAL;
		MSGE("input dir length is too big. return -1\n");
		return ret_val;
	}

	if (dir_exists((char *)p_dir) == 0) {
		MSGD("input dir %s already exists\n", p_dir);
		return 0;
	}

	// Copy the name of the path
	ret_val = 0;
	directory = (char *)malloc(len_dir + 1);

	if (directory == NULL) {
		error_number = ENOMEM;
		MSGE("malloc in mkdir_h failed! return -1\n");
		return -1;
	}

	if (memscpy(directory, len_dir, p_dir, len_dir)) {
		error_number = EFAULT;
		free(directory);
		MSGE("Invalid buffer len in memscpy %s, %d\n",
		     __func__, __LINE__);
		return -EINVAL;
	}

	directory[len_dir] = '\0';
	cur_pos = directory;

	// Skip the root '/'
	if (*cur_pos == '/') {
		cur_pos++;
		len_travel++;
	}

	while (len_travel < len_dir) {
		len_folder = 0;

		while (*cur_pos != '/' && *cur_pos != '\0') {
			cur_pos++;
			len_folder++;
			len_travel++;
		}

		if (len_folder == 0)
			break;

		// Found a parent directory
		if (*cur_pos == '/') {
			*cur_pos = '\0';

			// The parent directory exists
			if (dir_exists(directory) == 0) {
				*cur_pos = '/';
				cur_pos++;
				len_travel++;
				continue;
			}
		}

		// mkdir() fails
		ret_val = mkdir(directory, 0774);
		if (ret_val != 0 && errno != EEXIST) {
			error_number = errno;
			MSGE("mkdir(%s) failed: %d errno %d\n",
			     directory, ret_val, errno);
			break;
		}

		*cur_pos = '/';
		cur_pos++;
		len_travel++;
	}

	if (directory != NULL)
		free(directory);

	MSGD("mkdir_h returns %d\n", ret_val);
	return ret_val;
}

int file_fcntl(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_fcntl_req_t *my_req = (tz_file_fcntl_req_t *)req;
	tz_file_fcntl_rsp_t *my_rsp = (tz_file_fcntl_rsp_t *)rsp;
	int fd = my_req->fd;
	int cmd = my_req->cmd;

	MSGD("calling file_fcntl!\n");

	if (req_len < sizeof(tz_file_fcntl_req_t) ||
	    rsp_len < sizeof(tz_file_fcntl_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	my_rsp->ret = fcntl(fd, cmd);

	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_fcntl failed %d\n", errno);
	}

	MSGD("file_fcntl is done and returns = %d\n", my_rsp->ret);

	return 0;
}

int file_lseek(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_lseek_req_t *my_req = (tz_file_lseek_req_t *)req;
	tz_file_lseek_rsp_t *my_rsp = (tz_file_lseek_rsp_t *)rsp;
	int fildes = my_req->fildes;
	off_t offset = (off_t)my_req->offset;
	int whence = my_req->whence;

	MSGD("calling file_lseek!\n");

	if (req_len < sizeof(tz_file_lseek_req_t) ||
	    rsp_len < sizeof(tz_file_lseek_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	my_rsp->ret = lseek(fildes, offset, whence);

	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_lseek failed %d\n", errno);
	}

	MSGD("file_lseek is done and returns = %d\n", my_rsp->ret);

	return 0;
}

int file_rmdir(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_rmdir_req_t *my_req = (tz_file_rmdir_req_t *)req;
	tz_file_rmdir_rsp_t *my_rsp = (tz_file_rmdir_rsp_t *)rsp;
	const char *path = my_req->path;
	char ptr[500] = {0};
	char new_vendor_path[TZ_FILE_DIR_LEN] = {0};

	MSGD("calling file_rmdir!\n");

	if (req_len < sizeof(tz_file_rmdir_req_t) ||
	    rsp_len < sizeof(tz_file_rmdir_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	if (path == NULL) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		return 0;
	}

	MSGD("dir len = %ld\n", strlen(path));
	MSGD("dir path = %s\n", path);

	path = get_resolved_path(my_req->path, strlen(my_req->path),
			       new_vendor_path, TZ_FILE_DIR_LEN);

	if (strlen(path) >= 499) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: the length of path is too long!\n");
		return 0;
	}

	if (memscpy(ptr, ARRAY_SIZE(ptr), path, strlen(path) + 1)) {
		my_rsp->ret = -1;
		error_number = EFAULT;
		MSGE("Invalid buffer len in memscpy %s, %d\n",
		     __func__, __LINE__);
		return 0;
	}

	/* Add terminating NULL character */
	ptr[strlen(path) + 1] = '\0';
	my_rsp->ret = rmdir_h(ptr);

	if (my_rsp->ret < 0) {
		/* rmdir_h() automatically updates error_number */
		MSGE("file_rmdir failed %d\n", error_number);
	}

	MSGD("file_rmdir is done and returns = %d\n", my_rsp->ret);

	return 0;
}

int file_mkdir(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_mkdir_req_t *my_req = (tz_file_mkdir_req_t *)req;
	tz_file_mkdir_rsp_t *my_rsp = (tz_file_mkdir_rsp_t *)rsp;
	const char *path = my_req->pathname;
	char new_vendor_path[TZ_FILE_DIR_LEN] = {0};

	MSGD("calling file_mkdir!\n");

	if (req_len < sizeof(tz_file_mkdir_req_t) ||
	    rsp_len < sizeof(tz_file_mkdir_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	if (path == NULL) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		return 0;
	}

	MSGD("pathname = %s\n", path);
	MSGD("path length = %ld\n", strlen(path));

	path = get_resolved_path(my_req->pathname, strlen(my_req->pathname),
			       new_vendor_path, TZ_FILE_DIR_LEN);

	my_rsp->ret = mkdir_h(path);
	my_rsp->cmd_id = TZ_FS_MSG_CMD_FILE_MKDIR;

	if (my_rsp->ret < 0) {
		/* mkdir_h() automatically updates error_number */
		MSGE("file_mkdir failed %d\n", errno);
	}

	MSGD("file_mkdir returns %d\n", my_rsp->ret);

	return 0;
}

int file_testdir(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_testdir_req_t *my_req = (tz_file_testdir_req_t *)req;
	tz_file_testdir_rsp_t *my_rsp = (tz_file_testdir_rsp_t *)rsp;
	const char *pathname = my_req->pathname;
	char new_vendor_path[TZ_FILE_DIR_LEN] = {0};
	char *path_copy = NULL;
	int fsname_len = 0;

	MSGD("calling file_testdir!\n");

	if (pathname == NULL) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: file_testdir failed, pathname is NULL!\n");
		return 0;
	}

	pathname = get_resolved_path(my_req->pathname,
				   strlen(my_req->pathname),
				   new_vendor_path,
				   TZ_FILE_DIR_LEN);

	if (req_len < sizeof(tz_file_testdir_req_t) ||
	    rsp_len < sizeof(tz_file_testdir_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	fsname_len = strlen(pathname);
	if (fsname_len == 0) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: file_testdir failed, pathname is empty!\n");
		return 0;
	}

	if (fsname_len >= TZ_FILE_NAME_LEN) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: file_testdir failed, pathname is too long!\n");
		return 0;
	}

	path_copy = malloc(fsname_len + 1);
	if (path_copy == NULL) {
		my_rsp->ret = -1;
		error_number = ENOMEM;
		MSGE("Error: malloc in file_testdir failed!\n");
		return 0;
	}

	memset(path_copy, 0, fsname_len);
	if (memscpy(path_copy, fsname_len, pathname, fsname_len)) {
		free(path_copy);
		my_rsp->ret = -1;
		error_number = EFAULT;
		MSGE("Invalid buffer len in memscpy %s, %d\n",
		     __func__, __LINE__);
		return 0;
	}

	path_copy[fsname_len] = '\0';

	my_rsp->ret = dir_exists(path_copy);
	if (my_rsp->ret < 0) {
		/* dir_exists() sets error_number internally */
		MSGE("file_testdir failed %d\n", errno);
	}

	my_rsp->cmd_id = TZ_FS_MSG_CMD_FILE_TESTDIR;

	if (path_copy != NULL)
		free(path_copy);

	MSGD("file_testdir returns = %d\n", my_rsp->ret);
	return 0;
}

int file_telldir(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	UNUSED(req);
	UNUSED(req_len);
	tz_file_telldir_rsp_t *my_rsp = (tz_file_telldir_rsp_t *)rsp;

	MSGE("file_telldir is not supported!\n");

	if (rsp_len < sizeof(tz_file_telldir_rsp_t)) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("%s Invalid buffer length\n", __func__);
		goto exit;
	}

	my_rsp->ret = -1;

exit:
	MSGD("file_telldir is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_end(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	UNUSED(req);
	UNUSED(req_len);
	tz_file_end_rsp_t *my_rsp = (tz_file_end_rsp_t *)rsp;

	MSGD("fs: calling file_end!\n");

	if (rsp_len < sizeof(tz_file_end_rsp_t)) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("%s Invalid buffer length\n", __func__);
		goto exit;
	}

	my_rsp->ret = 0;

exit:
	MSGD("file_end is done and returns = %d\n", my_rsp->ret);
	return 0;
}

int file_get_partition_free_size(void *req, size_t req_len,
				 void *rsp, size_t rsp_len)
{
	tz_file_par_free_size_req_t *my_req = (tz_file_par_free_size_req_t *)req;
	tz_file_par_free_size_rsp_t *my_rsp = (tz_file_par_free_size_rsp_t *)rsp;
	char *partition_name = NULL;
	int i = 0;
	struct statfs disk_info;

	if (req_len < sizeof(tz_file_par_free_size_req_t) ||
	    rsp_len < sizeof(tz_file_par_free_size_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	// 'partition' is a stack-allocated array, never NULL
	partition_name = (char *)my_req->partition;

	i = strlen(partition_name);
	if (i >= TZ_CM_MAX_NAME_LEN - 2) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("fs: partition name is too long!\n");
		goto exit;
	}

	for (; i > 0; --i)
		partition_name[i] = partition_name[i - 1];

	partition_name[0] = '/';

	my_rsp->ret = statfs(partition_name, &disk_info);
	if (my_rsp->ret < 0) {
		my_rsp->ret = -1;
		error_number = errno;
		MSGE("Error: file_get_partition_free_size: "
		     "Partition %s, statfs failed and returned %d\n",
		     partition_name, my_rsp->ret);
		goto exit;
	}

	my_rsp->ret = 0;
	my_rsp->size = disk_info.f_bavail * disk_info.f_bsize;

exit:
	return 0;
}

int file_dir_chown_chmod(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_chown_chmod_req_t *my_req = (tz_file_chown_chmod_req_t *)req;
	tz_file_chown_chmod_rsp_t *my_rsp = (tz_file_chown_chmod_rsp_t *)rsp;

	char *path = my_req->path;
	uint32_t path_len = my_req->path_len;
	char *word = my_req->word;
	uint32_t word_len = my_req->word_len;
	char *owner = my_req->owner;
	uint32_t owner_len = my_req->owner_len;
	char *mod = my_req->mod;
	uint32_t mod_len = my_req->mod_len;
	uint32_t level = my_req->level;

	int ret = 0;
	char *word_start = NULL;
	uint32_t pass_len = 0;
	char *chown_path = NULL;
	char *chmod_path = NULL;
	char *temp_path = NULL;
	char *find_word_path = NULL;
	char star_str[TZ_CM_MAX_NAME_LEN];
	uint32_t pass_level = 0;

	if (req_len < sizeof(tz_file_chown_chmod_req_t) ||
	    rsp_len < sizeof(tz_file_chown_chmod_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	if (!path || !word || !owner || !mod ||
	    path_len == 0 || word_len == 0 ||
	    owner_len == 0 || mod_len == 0) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: file_dir_chown_mod: invalid input\n");
		return 0;
	}

	if (path_len > TZ_CM_MAX_NAME_LEN ||
	    word_len > TZ_CM_MAX_NAME_LEN ||
	    owner_len > TZ_CM_MAX_NAME_LEN ||
	    mod_len > TZ_CM_MAX_NAME_LEN ||
	    level > TZ_CM_MAX_NAME_LEN / 4) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: file_dir_chown_mod: input too large\n");
		return 0;
	}

	temp_path = (char *)malloc(path_len + 1);
	if (!temp_path) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: malloc failed\n");
		return 0;
	}

	if (memscpy(temp_path, path_len, (const char *)path, path_len)) {
		free(temp_path);
		my_rsp->ret = -1;
		error_number = EFAULT;
		MSGE("Invalid buffer len in memscpy %s, %d\n", __func__, __LINE__);
		return 0;
	}

	temp_path[path_len] = '\0';
	word_start = temp_path;
	pass_len = path_len;

	while (*word_start != '\0') {
		if (pass_len < word_len) {
			my_rsp->ret = -1;
			error_number = EINVAL;
			MSGE("Error: word not in path\n");
			free(temp_path);
			return 0;
		}

		if (strncmp(word_start, word, word_len) == 0)
			break;

		word_start++;
		pass_len--;
	}

	/* Found key word */
	find_word_path = (char *)malloc(path_len + 1);
	if (!find_word_path) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: malloc failed\n");
		goto exit;
	}

	memset(find_word_path, 0, path_len + 1);
	if (memscpy(find_word_path, path_len + 1, path,
		    path_len - pass_len + word_len)) {
		my_rsp->ret = -1;
		error_number = EFAULT;
		MSGE("Invalid buffer len in memscpy %s, %d\n", __func__, __LINE__);
		goto exit;
	}

	chown_path = (char *)malloc(TZ_CM_MAX_NAME_LEN);
	if (!chown_path) {
		my_rsp->ret = -1;
		error_number = ENOMEM;
		MSGE("Error: malloc for chown_path failed\n");
		goto exit;
	}

	chmod_path = (char *)malloc(TZ_CM_MAX_NAME_LEN);
	if (!chmod_path) {
		my_rsp->ret = -1;
		error_number = ENOMEM;
		MSGE("Error: malloc for chmod_path failed\n");
		goto exit;
	}

	temp_path[path_len - pass_len + word_len] = '\0';

	/* change root folder owner */
	memset(chown_path, 0, TZ_CM_MAX_NAME_LEN);
	ret = snprintf(chown_path, TZ_CM_MAX_NAME_LEN, "chown %s %s", owner,
		       temp_path);
	if (ret < 0 || ret >= TZ_CM_MAX_NAME_LEN) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: snprintf failed\n");
		goto exit;
	}

	ret = system(chown_path);
	MSGD("%s is done\n", chown_path);
	if (ret != 0) {
		my_rsp->ret = -1;
		error_number = (ret == -1) ? errno : EINVAL;
		MSGE("Error: system() failed: %d\n", error_number);
		goto exit;
	}

	/* change root folder mod */
	memset(chmod_path, 0, TZ_CM_MAX_NAME_LEN);
	ret = snprintf(chmod_path, TZ_CM_MAX_NAME_LEN, "chmod %s %s", mod,
		       temp_path);
	if (ret < 0 || ret >= TZ_CM_MAX_NAME_LEN) {
		my_rsp->ret = -1;
		error_number = EINVAL;
		MSGE("Error: snprintf failed\n");
		goto exit;
	}

	ret = system(chmod_path);
	MSGD("%s is done\n", chmod_path);
	if (ret != 0) {
		my_rsp->ret = -1;
		error_number = (ret == -1) ? errno : EINVAL;
		MSGE("Error: system() failed: %d\n", error_number);
		goto exit;
	}

	if (memscpy(temp_path, path_len, (const char *)path, path_len)) {
		my_rsp->ret = -1;
		error_number = EFAULT;
		MSGE("Invalid buffer len in memscpy %s, %d\n", __func__, __LINE__);
		goto exit;
	}

	/* if the last char = '/' remove it */
	temp_path[path_len] = '\0';
	if (temp_path[path_len - 1] == '/')
		temp_path[path_len - 1] = '\0';

	/* change subfolder owner and mod */
	word_start += word_len;
	memset(star_str, 0, sizeof(star_str));

	while (level != pass_level) {
		if (memscpy(star_str + pass_level * 2, sizeof(star_str),
			    "/*", 2)) {
			my_rsp->ret = -1;
			error_number = EFAULT;
			MSGE("Invalid buffer len in memscpy %s, %d\n", __func__, __LINE__);
			goto exit;
		}

		/* reset chown_path */
		memset(chown_path, 0, TZ_CM_MAX_NAME_LEN);
		ret = snprintf(chown_path, TZ_CM_MAX_NAME_LEN, "chown %s %s%s",
			       owner, find_word_path, star_str);
		if (ret < 0 || ret >= TZ_CM_MAX_NAME_LEN) {
			my_rsp->ret = -1;
			error_number = EINVAL;
			MSGE("Error: snprintf failed\n");
			goto exit;
		}

		ret = system(chown_path);
		MSGD("%s is done\n", chown_path);
		if (ret != 0) {
			my_rsp->ret = -1;
			error_number = (ret == -1) ? errno : EINVAL;
			MSGE("Error: system() failed: %d\n", error_number);
			goto exit;
		}

		memset(chmod_path, 0, TZ_CM_MAX_NAME_LEN);
		ret = snprintf(chmod_path, TZ_CM_MAX_NAME_LEN, "chmod %s %s%s",
			       mod, find_word_path, star_str);
		if (ret < 0 || ret >= TZ_CM_MAX_NAME_LEN) {
			my_rsp->ret = -1;
			error_number = EINVAL;
			MSGE("Error: snprintf failed\n");
			goto exit;
		}

		ret = system(chmod_path);
		MSGD("%s is done", chmod_path);
		if (ret != 0) {
			my_rsp->ret = -1;
			error_number = (ret == -1) ? errno : EINVAL;
			MSGE("Error: system() failed: %d\n", error_number);
			goto exit;
		}

		pass_level++;
	}

exit:
	if (temp_path)
		free(temp_path);
	if (find_word_path)
		free(find_word_path);
	if (chown_path)
		free(chown_path);
	if (chmod_path)
		free(chmod_path);

	MSGD("file_dir_chown_chmod is done and returns %d\n", my_rsp->ret);
	return 0;
}

int file_sync(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_file_sync_req_t *my_req = (tz_file_sync_req_t *)req;
	tz_file_sync_rsp_t *my_rsp = (tz_file_sync_rsp_t *)rsp;
	int fd = my_req->fd;

	MSGD("calling file_sync!\n");

	if (req_len < sizeof(tz_file_sync_req_t) ||
	    rsp_len < sizeof(tz_file_sync_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	my_rsp->ret = fsync(fd);

	if (my_rsp->ret < 0) {
		error_number = errno;
		MSGE("file_sync failed %d\n", errno);
	}

	MSGD("file_sync is done, and returns %d\n", my_rsp->ret);
	return 0;
}

int dir_open(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_dir_open_req_t *my_req = (tz_dir_open_req_t *)req;
	tz_dir_open_rsp_t *my_rsp = (tz_dir_open_rsp_t *)rsp;
	const char *pathname = my_req->pathname;
	char new_vendor_path[TZ_FILE_DIR_LEN] = {0};
	DIR *pdir = NULL;

	if (pathname == NULL) {
		my_rsp->ret = E_FS_INVALID_ARG;
		error_number = EINVAL;
		return 0;
	}

	MSGD("calling dir_open %s\n", pathname);

	if (req_len < sizeof(tz_dir_open_req_t) ||
	    rsp_len < sizeof(tz_dir_open_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	my_rsp->cmd_id = (tz_fs_msg_cmd_type)TZ_FS_MSG_CMD_DIR_OPEN;

	pathname = get_resolved_path(my_req->pathname,
				   strlen(my_req->pathname),
				   new_vendor_path,
				   TZ_FILE_DIR_LEN);

	if (strlen(pathname) >= TZ_CM_MAX_NAME_LEN) {
		my_rsp->ret = E_FS_PATH_TOO_LONG;
		error_number = EINVAL;
		MSGE("Error: dir_open: path is too long\n");
		goto exit;
	}

	pdir = opendir(pathname);
	if (pdir == NULL) {
		my_rsp->ret = E_FS_DIR_NOT_EXIST;
		error_number = errno;
		MSGE("Error: dir_open: directory does not exist: %s\n", pathname);
		goto exit;
	}

	my_rsp->ret = E_FS_SUCCESS;

exit:
	if (pdir)
		my_rsp->pdir = (uint64_t)((uintptr_t)pdir);

	MSGD("dir_open done, and returns %d\n", my_rsp->ret);

	return 0;
}


int dir_read(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_dir_read_req_t *my_req = (tz_dir_read_req_t *)req;
	tz_dir_read_rsp_t *my_rsp = (tz_dir_read_rsp_t *)rsp;
	DIR *pdir = NULL;
	struct dirent *pdirent = NULL;

       MSGD("calling dir_read\n");

	if (req_len < sizeof(tz_dir_read_req_t) ||
	    rsp_len < sizeof(tz_dir_read_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	my_rsp->cmd_id = (tz_fs_msg_cmd_type)TZ_FS_MSG_CMD_DIR_READ;

	if (my_req->pdir == 0) {
		my_rsp->ret = E_FS_INVALID_ARG;
		error_number = EINVAL;
		MSGE("Error: dir_read: directory pointer is null\n");
		return 0;
	}

	pdir = (DIR *)((uintptr_t)my_req->pdir);
	if (pdir == NULL) {
		MSGE("Error: dir_read: pdir is null\n");
		my_rsp->ret = E_FS_INVALID_ARG;
		return 0;
	}

	pdirent = readdir(pdir);
	my_rsp->ret = E_FS_SUCCESS;

	/* NULL from readdir() may indicate end of stream, not error */
	if (pdirent != NULL) {
		my_rsp->pdirent.d_ino = (uint64_t)pdirent->d_ino;
		my_rsp->pdirent.d_off = (int64_t)pdirent->d_off;
		my_rsp->pdirent.d_reclen = (unsigned short)pdirent->d_reclen;
		my_rsp->pdirent.d_type = (unsigned char)pdirent->d_type;

		if (memscpy(my_rsp->pdirent.d_name, TZ_CM_MAX_NAME_LEN,
			    pdirent->d_name, TZ_CM_MAX_NAME_LEN)) {

			my_rsp->ret = -1;
			error_number = EFAULT;
			MSGE("Invalid buffer len in memscpy %s, %d\n",
				__func__, __LINE__);
			return 0;
		}
	} else {
		/* End of stream: set inode to 0 */
		my_rsp->pdirent.d_ino = 0;
	}

	MSGD("dir_read done, and returns %d\n", my_rsp->ret);

	return 0;
}

int dir_close(void *req, size_t req_len, void *rsp, size_t rsp_len)
{
	tz_dir_close_req_t *my_req = (tz_dir_close_req_t *)req;
	tz_dir_close_rsp_t *my_rsp = (tz_dir_close_rsp_t *)rsp;
	DIR *pdir = NULL;

	MSGD("calling dir_close\n");

	if (req_len < sizeof(tz_dir_close_req_t) ||
	    rsp_len < sizeof(tz_dir_close_rsp_t)) {
		MSGE("%s Invalid buffer length\n", __func__);
		return -1;
	}

	my_rsp->cmd_id = (tz_fs_msg_cmd_type)TZ_FS_MSG_CMD_DIR_CLOSE;

	if (my_req->pdir == 0) {
		my_rsp->ret = E_FS_INVALID_ARG;
		error_number = EINVAL;
		MSGE("Error: dir_close: directory pointer is null\n");
		return 0;
	}

	pdir = (DIR *)((uintptr_t)my_req->pdir);
	if (pdir == NULL) {
		MSGE("Error: dir_read: pdir is null\n");
		my_rsp->ret = E_FS_INVALID_ARG;
		error_number = EINVAL;
		return 0;
	}

	my_rsp->ret = closedir(pdir);
	if (my_rsp->ret < 0)
		error_number = errno;

	MSGD("dir_close done, and returns %d\n", my_rsp->ret);

	return 0;
}

int file_get_errno(void *rsp, size_t rsp_len)
{
	tz_file_get_errno_rsp_t *my_rsp = (tz_file_get_errno_rsp_t *)rsp;

	if (rsp_len < sizeof(tz_file_get_errno_rsp_t)) {
		MSGE("%s Invalid buffer length.\n", __func__);
		return -1;
	}

	my_rsp->ret = error_number;
	my_rsp->cmd_id = TZ_FS_MSG_CMD_FILE_GET_ERRNO;

	return 0;
}
