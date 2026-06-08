// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * rpmb_client — RPMB key provisioning and erase utility
 *
 * MinkIPC port of rpmbClient.c.  Supports the same two operations as
 * the original:
 *
 *   -p / --ProvisionKey   Provision the RPMB authentication key
 *   -e / --EraseKey       Erase the entire RPMB partition
 *
 * Usage:
 *   rpmb_client -p
 *   rpmb_client -e
 *   rpmb_client -h
 */

#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "CRPMBService.h"
#include "IClientEnv.h"
#include "IRPMBService.h"
#include "MinkCom.h"
#include "object.h"

#define LOG_ERR(fmt, ...)                                                      \
	fprintf(stderr, "RPMB_CLIENT ERROR [%s:%d]: " fmt, __func__, __LINE__, \
		##__VA_ARGS__)

static struct option test_command_options[] = {
	{ "ProvisionKey", no_argument, NULL, 'p' },
	{ "EraseKey",     no_argument, NULL, 'e' },
	{ "Help",         no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 },
};

/*
 * rpmb_get_service_obj - obtain an RPMB service object from QTEE
 * @rpmb_obj: output — caller-owned RPMB service object
 *
 * Opens a MinkIPC connection to QTEE and returns the RPMB service
 * object.  The caller must release it with Object_ASSIGN_NULL() when
 * done.
 *
 * Returns Object_OK on success, an Object_ERROR_* code on failure.
 */
static int32_t rpmb_get_service_obj(Object *rpmb_obj)
{
	int32_t rv;
	Object root = Object_NULL;
	Object client_env = Object_NULL;

	rv = MinkCom_getRootEnvObject(&root);
	if (Object_isERROR(rv)) {
		root = Object_NULL;
		LOG_ERR("MinkCom_getRootEnvObject failed: %d\n", rv);
		goto cleanup;
	}

	rv = MinkCom_getClientEnvObject(root, &client_env);
	if (Object_isERROR(rv)) {
		client_env = Object_NULL;
		LOG_ERR("MinkCom_getClientEnvObject failed: %d\n", rv);
		goto cleanup;
	}

	rv = IClientEnv_open(client_env, CRPMBService_UID, rpmb_obj);
	if (Object_isERROR(rv)) {
		*rpmb_obj = Object_NULL;
		LOG_ERR("IClientEnv_open(CRPMBService_UID) failed: %d\n", rv);
		goto cleanup;
	}

cleanup:
	Object_ASSIGN_NULL(client_env);
	Object_ASSIGN_NULL(root);
	return rv;
}

/*
 * qsc_rpmb_check - query RPMB key provisioning status
 *
 * Invokes IRPMBService_rpmbCheckProv() and prints the result.
 * Called as option 2 from the provision-key menu.
 */
static int32_t qsc_rpmb_check(void)
{
	int32_t rv;
	int32_t status;
	Object rpmb_obj = Object_NULL;

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv))
		goto cleanup;

	status = IRPMBService_rpmbCheckProv(rpmb_obj);

	switch (status) {
	case Object_OK:
		printf("RPMB Key status: RPMB_KEY_PROVISIONED_AND_OK\n");
		break;
	case IRPMBService_ERROR_RPMB_NOT_PROVISIONED:
		printf("RPMB Key status: RPMB_KEY_NOT_PROVISIONED (0x%x)\n",
		       status);
		break;
	case IRPMBService_ERROR_RPMB_MAC:
		printf("RPMB Key status:"
		       " RPMB_KEY_PROVISIONED_BUT_MAC_MISMATCH (0x%x)\n",
		       status);
		break;
	default:
		printf("RPMB Key status: Others (0x%x)\n", status);
		break;
	}

	rv = Object_OK;

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return rv;
}

/*
 * qsc_rpmb_provision_key - provision the RPMB authentication key
 *
 * Prompts the user to select production key (0), test key (1), or
 * check current status (2), then invokes the appropriate MinkIPC call.
 *
 * Returns Object_OK on success, an Object_ERROR_* code on failure.
 */
static int32_t qsc_rpmb_provision_key(void)
{
	int32_t rv = Object_OK;
	Object rpmb_obj = Object_NULL;
	int32_t key_type;

	printf("\t-------------------------------------------------------\n");
	printf("\t WARNING!!! You are about to provision the RPMB key.\n");
	printf("\t This is a ONE time operation and CANNOT be reversed.\n");
	printf("\t-------------------------------------------------------\n");
	printf("\t 0 -> Provision Production key\n");
	printf("\t 1 -> Provision Test key\n");
	printf("\t 2 -> Check RPMB key provision status\n");
	printf("\t-------------------------------------------------------\n");
	printf("\t Select an option to proceed: ");
	fflush(stdout);

	key_type = (int32_t)(getchar() - '0');

	switch (key_type) {
	case 0:
	case 1:
		rv = rpmb_get_service_obj(&rpmb_obj);
		if (Object_isERROR(rv))
			goto cleanup;

		rv = IRPMBService_rpmbProvisionKey(rpmb_obj, key_type);
		if (!Object_isERROR(rv))
			printf("RPMB key provisioning completed\n");
		else
			LOG_ERR("RPMB key provisioning failed: 0x%x\n", rv);
		break;

	case 2:
		rv = qsc_rpmb_check();
		break;

	default:
		printf("Invalid RPMB provision key type (%d)\n", key_type);
		rv = Object_ERROR;
		break;
	}

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return rv;
}

/*
 * qsc_rpmb_erase - erase the entire RPMB partition
 *
 * Prompts the user for confirmation, then invokes
 * IRPMBService_rpmbErase() via MinkIPC.
 *
 * Returns Object_OK on success, an Object_ERROR_* code on failure.
 */
static int32_t qsc_rpmb_erase(void)
{
	int32_t rv = Object_OK;
	Object rpmb_obj = Object_NULL;
	char input;

	printf("\t-------------------------------------------------------\n");
	printf("\t WARNING!!! You are about to erase the entire RPMB"
	       " partition.\n");
	printf("\t-------------------------------------------------------\n");
	printf("\t Do you want to proceed (y/n)? ");
	fflush(stdout);

	input = getchar();
	if (input != 'y')
		return Object_OK;

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv))
		goto cleanup;

	rv = IRPMBService_rpmbErase(rpmb_obj);
	if (!Object_isERROR(rv))
		printf("RPMB erase completed\n");
	else
		LOG_ERR("RPMB erase failed: 0x%x\n", rv);

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return rv;
}

static void qsc_usage(void)
{
	printf("*************************************************************\n");
	printf("*************       RPMB CLIENT (MinkIPC)       *************\n");
	printf("*************************************************************\n");
	printf("\n"
	       "Usage:\n"
	       "  rpmb_client -p   Provision RPMB key\n"
	       "  rpmb_client -e   Erase RPMB partition\n"
	       "  rpmb_client -h                Print this help message\n"
	       "\n"
	       "Options:\n"
	       "  -p, --ProvisionKey   Provision the RPMB authentication key\n"
	       "  -e, --EraseKey       Erase the entire RPMB partition\n"
	       "  -h, --Help           Show this help text\n"
	       "\n"
	       "Examples:\n"
	       "  rpmb_client -p   (provision RPMB key)\n"
	       "  rpmb_client -e   (erase RPMB partition)\n"
	       "---------------------------------------------------------\n\n");
}

/*
 * run_test_command - parse options and dispatch the selected command
 *
 * Reads the option flag (-p / -e / -h) and dispatches the selected
 * command once.
 *
 * Returns 0 on success, -1 on failure.
 */
static int run_test_command(int argc, char *argv[])
{
	int command;
	int32_t rv = Object_OK;

	command = getopt_long(argc, argv, "peh", test_command_options, NULL);

	if (command == -1 || command == '?') {
		qsc_usage();
		return -1;
	}

	if (command == 'h') {
		qsc_usage();
		return 0;
	}

	switch (command) {
	case 'p':
		rv = qsc_rpmb_provision_key();
		break;
	case 'e':
		rv = qsc_rpmb_erase();
		break;
	default:
		qsc_usage();
		return 0;
	}

	if (Object_isERROR(rv))
		LOG_ERR("Command failed: error %d\n", rv);

	return Object_isERROR(rv) ? -1 : 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		qsc_usage();
		return -1;
	}

	return run_test_command(argc, argv);
}
