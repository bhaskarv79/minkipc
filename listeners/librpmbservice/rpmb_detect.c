// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * RPMB Device Detection - Clean, Platform-Independent
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rpmb_core.h"
#include "rpmb_logging.h"

/* Device detection paths */
#define PROC_CMDLINE_PATH       "/proc/cmdline"
#define DEV_BSG_PATH           "/dev/bsg"
#define DEV_BLOCK_PATH         "/dev/block"

/* Detection patterns */
#define UFS_PATTERN            "ufs"
#define EMMC_PATTERN           "mmc"
#define SDHCI_PATTERN          "sdhci"
#define UFSHC_PATTERN          "ufshc"

/**
 * Check if UFS device exists
 */
static bool check_ufs_device(void)
{
	DIR *dir;
	struct dirent *entry;
	bool found = false;

	RPMB_LOG_DEBUG("Checking for UFS devices in %s", DEV_BSG_PATH);

	dir = opendir(DEV_BSG_PATH);
	if (!dir) {
		RPMB_LOG_DEBUG("Cannot open %s", DEV_BSG_PATH);
		return false;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strstr(entry->d_name, "ufs") != NULL) {
			RPMB_LOG_DEBUG("Found UFS device: %s", entry->d_name);
			found = true;
			break;
		}
	}

	closedir(dir);
	return found;
}

/**
 * Check if eMMC RPMB device exists
 */
static bool check_emmc_rpmb_device(void)
{
	struct stat st;
	const char *emmc_paths[] = {
		"/dev/mmcblk0rpmb",
		"/dev/block/mmcblk0rpmb",
		NULL
	};

	for (int i = 0; emmc_paths[i] != NULL; i++) {
		if (stat(emmc_paths[i], &st) == 0) {
			RPMB_LOG_DEBUG("Found eMMC RPMB device: %s", emmc_paths[i]);
			return true;
		}
	}

	RPMB_LOG_DEBUG("No eMMC RPMB device found");
	return false;
}

/**
 * Parse kernel command line for boot device information
 */
static rpmb_device_type_t detect_from_cmdline(void)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	rpmb_device_type_t device_type = RPMB_DEVICE_NONE;

	RPMB_LOG_DEBUG("Checking kernel command line for boot device info");

	fp = fopen(PROC_CMDLINE_PATH, "r");
	if (!fp) {
		RPMB_LOG_DEBUG("Cannot open %s", PROC_CMDLINE_PATH);
		return RPMB_DEVICE_NONE;
	}

	if (getline(&line, &len, fp) > 0) {
		RPMB_LOG_DEBUG("Kernel cmdline: %.100s%s", line, strlen(line) > 100 ? "..." : "");

		/* Check for UFS indicators */
		if (strstr(line, UFSHC_PATTERN) != NULL ||
				strstr(line, "root=/dev/sd") != NULL) {
			RPMB_LOG_DEBUG("UFS device detected from cmdline");
			device_type = RPMB_DEVICE_UFS;
		}
		/* Check for eMMC indicators */
		else if (strstr(line, SDHCI_PATTERN) != NULL ||
				strstr(line, "root=/dev/mmcblk") != NULL) {
			RPMB_LOG_DEBUG("eMMC device detected from cmdline");
			device_type = RPMB_DEVICE_EMMC;
		}
	}

	free(line);
	fclose(fp);
	return device_type;
}

/**
 * Detect RPMB device based on available hardware
 */
rpmb_device_type_t rpmb_detect_device(void)
{
	rpmb_device_type_t device_type = RPMB_DEVICE_NONE;

	RPMB_LOG_INFO("Starting RPMB device detection");

	/* First, check for actual device nodes */
	if (check_ufs_device()) {
		RPMB_LOG_INFO("UFS device detected");
		device_type = RPMB_DEVICE_UFS;
	} else if (check_emmc_rpmb_device()) {
		RPMB_LOG_INFO("eMMC RPMB device detected");
		device_type = RPMB_DEVICE_EMMC;
	} else {
		/* Fallback to kernel command line detection */
		RPMB_LOG_DEBUG("No direct device nodes found, checking cmdline");
		device_type = detect_from_cmdline();
	}

	/* Final fallback for development/testing */
	if (device_type == RPMB_DEVICE_NONE) {
		RPMB_LOG_WARN("No RPMB device detected, defaulting to UFS for testing");
		device_type = RPMB_DEVICE_UFS;
	}

	RPMB_LOG_INFO("RPMB device detection result: %s",
			rpmb_device_type_to_string(device_type));

	return device_type;
}
