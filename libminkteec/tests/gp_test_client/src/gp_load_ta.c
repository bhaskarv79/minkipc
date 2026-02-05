// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "MinkCom.h"

#include "CAppLoader.h"
#include "IAppController.h"
#include "IAppLoader.h"
#include "IClientEnv.h"

#include "gp_load_ta.h"

#define GP_TA_COUNT 5
const char *ta_list[] = { GP_TEST2_APP_NAME, GP_TEST_APP_NAME,
			  GP_SAMPLE_APP_NAME, EXAMPLE_GP_APP_NAME,
			  GP_SAMPLE2_APP_NAME };

static Object appController[GP_TA_COUNT] = { Object_NULL };

static size_t test_get_file_size(FILE *file)
{
	ssize_t size;

	if (fseek(file, 0, SEEK_END)) {
		printf("%s\n", strerror(errno));
		return 0;
	}

	size = ftell(file);
	if (size < 0) {
		printf("%s\n", strerror(errno));
		return 0;
	}

	if (fseek(file, 0, SEEK_SET)) {
		printf("%s\n", strerror(errno));
		return 0;
	}

	return size;
}

static int test_read_file(const char *filename, char **buffer, size_t *size)
{
	int ret = -1;
	FILE *file;
	char *file_buf;
	size_t file_size;

	file = fopen(filename, "r");
	if (!file) {
		printf("%s\n", strerror(errno));
		return -1;
	}

	file_size = test_get_file_size(file);
	if (!file_size)
		goto out;

	file_buf = malloc(file_size);
	if (!file_buf) {
		printf("malloc,\n");
		goto out;
	}

	printf("File %s, size: %zu Bytes.\n", filename, file_size);

	if (fread(file_buf, 1, file_size, file) != file_size) {
		printf("fread.\n");
		free(file_buf);
		goto out;
	}

	*buffer = file_buf;
	*size = file_size;

	ret = 0;
out:
	fclose(file);

	return ret;
}

static int load_ta(const char *filename, size_t i)
{
	int ret = 0;
	Object rootEnv = Object_NULL;
	Object clientEnv = Object_NULL;
	Object appLoader = Object_NULL;
	char *buffer;
	size_t size;

	MinkCom_getRootEnvObject(&rootEnv);
	MinkCom_getClientEnvObject(rootEnv, &clientEnv);
	IClientEnv_open(clientEnv, CAppLoader_UID, &appLoader);

	/* Read the TA file. */
	ret = test_read_file(filename, &buffer, &size);
	if (ret)
		goto exit;

	ret = IAppLoader_loadFromBuffer(appLoader, (uint8_t *)buffer, size,
					&appController[i]);
	if (ret)
		printf("Loading app failed, ret: 0x%x\n", ret);

	free(buffer);
exit:
	Object_ASSIGN_NULL(appLoader);
	Object_ASSIGN_NULL(rootEnv);
	Object_ASSIGN_NULL(clientEnv);

	return ret;
}

void unload_gp_tas(void)
{
	size_t i = 0;

	for (; i < GP_TA_COUNT; i++) {
		if (!Object_isNull(appController[i])) {
			/* Unload the GP TA */
			IAppController_unload(appController[i]);
			Object_release(appController[i]);
		}
	}
}

int preload_gp_tas(const char *pathname)
{
	int ret = 0;
	size_t i = 0;
	char filename[1024] = { 0 };

	for (; i < GP_TA_COUNT; i++) {
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename), "%s/%s", pathname,
			 ta_list[i]);

		ret = load_ta(filename, i);
		if (ret) {
			printf("Failed to load %s: ret = 0x%x\n", ta_list[i],
			       ret);
			break;
		}
	}

	if (ret)
		unload_gp_tas();

	return ret;
}
