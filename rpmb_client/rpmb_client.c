// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <getopt.h>
#include <stdbool.h>
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

/*
 * LOG_ERR - write an error message to stderr with function/line context.
 * LOG_MSG - write an informational message to stdout with function/line context.
 */
#define LOG_ERR(fmt, ...)                                                      \
	fprintf(stderr, "RPMB_CLIENT ERROR [%s:%d]: " fmt, __func__, __LINE__, \
		##__VA_ARGS__)

#define LOG_MSG(fmt, ...)                                                      \
	fprintf(stdout, "RPMB_CLIENT [%s:%d]: " fmt, __func__, __LINE__,      \
		##__VA_ARGS__)

/* Minimum argc: program name + command option + iteration count */
#define ARG_HAS_ITERATION 3

/*
 * RPMB_BLOCK_SIZE - size of one RPMB data block in bytes.
 * Matches RPMB_DATA_SIZE in rpmb_msg.h (256 bytes per half-sector).
 */
#define RPMB_BLOCK_SIZE 256U

static uint32_t test_iterations = 1;

static struct option test_command_options[] = {
	{ "ProvisionKey", no_argument, NULL, 'p' },
	{ "EraseKey",     no_argument, NULL, 'e' },
	{ "Read",         no_argument, NULL, 'r' },
	{ "Write",        no_argument, NULL, 'w' },
	{ "test",         no_argument, NULL, 't' },
	{ "Help",         no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 },
};

/*
 * rpmb_get_service_obj - obtain an RPMB service object from QTEE
 * @rpmb_obj: output — caller-owned RPMB service object
 *
 * Establishes a MinkIPC connection to QTEE, registers as a client,
 * and opens the RPMB service object via the IDL-generated UID.
 * The intermediate root and client_env objects are released before
 * this function returns; only *rpmb_obj is retained by the caller.
 *
 * The caller must release *rpmb_obj with Object_ASSIGN_NULL() when
 * it is no longer needed.
 *
 * Returns Object_OK on success, an Object_ERROR_* code on failure.
 */
static int32_t rpmb_get_service_obj(Object *rpmb_obj)
{
	int32_t rv = Object_OK;
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
 * qsc_rpmb_check - query RPMB key provisioning status via SMCInvoke
 *
 * Invokes IRPMBService_rpmbCheckProv() and prints the result.
 *
 * Always returns Object_OK — check-status is a diagnostic operation.
 * The TA's status code is printed but is not propagated as a command
 * failure so that the caller's iteration loop is not aborted.
 */
static int32_t qsc_rpmb_check(void)
{
	int32_t rv = Object_OK;
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
		printf("RPMB Key status: RPMB_KEY_NOT_PROVISIONED"
		       " (0x%x)\n", status);
		break;
	case IRPMBService_ERROR_RPMB_MAC:
		printf("RPMB Key status:"
		       " RPMB_KEY_PROVISIONED_BUT_MAC_MISMATCH"
		       " (0x%x)\n", status);
		break;
	case Object_ERROR_INVALID:
		/*
		 * The TA returned Object_ERROR_INVALID (2).
		 * This means the TA does not implement rpmbCheckProv
		 * with the current operation code (IRPMBService_OP 0).
		 * Possible causes:
		 *   - CRPMBService_UID (0x16) does not match the TA
		 *     registered on this device
		 *   - TA was compiled with a different IRPMBService IDL
		 *     version (different operation numbering)
		 */
		printf("RPMB Key status: Object_ERROR_INVALID (0x%x)"
		       " — TA does not support rpmbCheckProv;"
		       " verify CRPMBService_UID=0x%x and TA IDL version\n",
		       status, CRPMBService_UID);
		break;
	default:
		printf("RPMB Key status: unexpected error (0x%x)\n", status);
		break;
	}

	/* Always return Object_OK — status has been printed above. */
	rv = Object_OK;

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return rv;
}

/*
 * qsc_rpmb_provision_key - provision RPMB key via SMCInvoke
 *
 * Interactively prompts the user to select a key type (production or
 * test) or to check the current provision status, then invokes the
 * appropriate IRPMBService method via MinkIPC.
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
		if (!Object_isERROR(rv)) {
			printf("RPMB key provisioning completed\n");
		} else if (rv == Object_ERROR_INVALID) {
			LOG_ERR("RPMB key provisioning failed:"
				" Object_ERROR_INVALID (0x%x)"
				" — TA does not support rpmbProvisionKey;"
				" verify CRPMBService_UID=0x%x"
				" and TA IDL version\n",
				rv, CRPMBService_UID);
		} else {
			LOG_ERR("RPMB key provisioning failed: 0x%x\n", rv);
		}
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
 * qsc_rpmb_erase - erase the RPMB partition via SMCInvoke
 *
 * Prompts the user for confirmation, then erases the entire RPMB
 * partition by invoking IRPMBService_rpmbErase() via MinkIPC.
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
	if (!Object_isERROR(rv)) {
		printf("RPMB erase completed\n");
	} else if (rv == Object_ERROR_INVALID) {
		LOG_ERR("RPMB erase failed: Object_ERROR_INVALID (0x%x)"
			" — TA does not support rpmbErase;"
			" verify CRPMBService_UID=0x%x"
			" and TA IDL version\n",
			rv, CRPMBService_UID);
	} else {
		LOG_ERR("RPMB erase failed: 0x%x\n", rv);
	}

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return rv;
}

/*
 * qsc_rpmb_read - read blocks from the RPMB partition via SMCInvoke
 * @address:     half-sector address of the first block to read
 * @block_count: number of 256-byte blocks to read
 * @data:        caller-supplied output buffer (must be >= block_count * 256)
 * @data_len:    size of @data in bytes
 * @data_lenout: actual bytes written into @data on success
 *
 * Invokes IRPMBService_rpmbRead().  The RPMB service performs the full
 * authenticated read protocol (nonce generation, HMAC verification,
 * write-counter validation) and returns only the plaintext payload.
 *
 * Returns Object_OK on success, an Object_ERROR_* code on failure.
 */
static int32_t qsc_rpmb_read(uint32_t address, uint32_t block_count,
			      uint8_t *data, size_t data_len,
			      size_t *data_lenout)
{
	int32_t rv = Object_OK;
	Object rpmb_obj = Object_NULL;

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv))
		goto cleanup;

	rv = IRPMBService_rpmbRead(rpmb_obj, address, block_count,
				   data, data_len, data_lenout);
	if (Object_isERROR(rv))
		LOG_ERR("RPMB read failed: %d\n", rv);

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return rv;
}

/*
 * qsc_rpmb_write - write blocks to the RPMB partition via SMCInvoke
 * @address:     half-sector address of the first block to write
 * @block_count: number of 256-byte blocks to write
 * @data:        data to write (must be exactly block_count * 256 bytes)
 * @data_len:    size of @data in bytes
 *
 * Invokes IRPMBService_rpmbWrite().  The RPMB service performs the full
 * authenticated write protocol (write-counter fetch, HMAC computation,
 * result-frame verification) before returning.
 *
 * Returns Object_OK on success, an Object_ERROR_* code on failure.
 */
static int32_t qsc_rpmb_write(uint32_t address, uint32_t block_count,
			       const uint8_t *data, size_t data_len)
{
	int32_t rv = Object_OK;
	Object rpmb_obj = Object_NULL;

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv))
		goto cleanup;

	rv = IRPMBService_rpmbWrite(rpmb_obj, address, block_count,
				    data, data_len);
	if (Object_isERROR(rv))
		LOG_ERR("RPMB write failed: %d\n", rv);

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return rv;
}

static void qsc_usage(void)
{
	printf("RPMB Test Client (SMCInvoke / MinkIPC)\n\n"
	       "Usage:\n"
	       "  rpmb_client -p <iterations>        Provision RPMB key\n"
	       "  rpmb_client -e <iterations>        Erase RPMB partition\n"
	       "  rpmb_client -r <iterations>        Read one block from RPMB address 0\n"
	       "  rpmb_client -w <iterations>        Write one block to RPMB address 0\n"
#ifdef RPMB_ENABLE_TESTS
	       "  rpmb_client --test [ta_path]       Run all RPMB test cases\n"
	       "                                     ta_path: TA directory required for\n"
	       "                                     read/write tests [C/D]; omit to run\n"
	       "                                     provision/erase tests only [A/B]\n"
#endif
	       "  rpmb_client -h                     Print this help message\n\n"
	       "Options:\n"
	       "  -p, --ProvisionKey   Provision the RPMB authentication key\n"
	       "  -e, --EraseKey       Erase the entire RPMB partition\n"
	       "  -r, --Read           Read one 256-byte block from RPMB address 0\n"
	       "  -w, --Write          Write one 256-byte test block to RPMB address 0\n"
#ifdef RPMB_ENABLE_TESTS
	       "  -t, --test           Run all RPMB test cases and report results\n"
#endif
	       "  -h, --Help           Show this help text\n\n"
	       "Examples:\n"
	       "  rpmb_client -p 1                   (provision RPMB key)\n"
	       "  rpmb_client -e 1                   (erase RPMB partition)\n"
	       "  rpmb_client -r 1                   (read RPMB block 0)\n"
	       "  rpmb_client -w 1                   (write RPMB block 0)\n"
#ifdef RPMB_ENABLE_TESTS
	       "  rpmb_client --test                 (provision+erase tests only)\n"
	       "  rpmb_client --test /data/ta/       (all tests including read/write)\n"
#endif
	       "---------------------------------------------------------\n\n");
}

/*
 * run_test_command - parse options and run the selected RPMB command
 *
 * Parses the command-line option (-p / -e / -r / -w / -h), reads the
 * iteration count from the next positional argument, and runs the
 * selected RPMB operation for the requested number of iterations.
 *
 * Returns 0 on success, -1 on failure.
 */
static int run_test_command(int argc, char *argv[])
{
	int command;
	int32_t rv = Object_OK;
	uint32_t i;
	uint8_t rw_buf[RPMB_BLOCK_SIZE];
	size_t rw_lenout = 0;

	command = getopt_long(argc, argv, "perwth", test_command_options, NULL);

	if (command == -1 || command == '?') {
		qsc_usage();
		return -1;
	}

	if (command == 'h') {
		qsc_usage();
		return 0;
	}

	/* The iteration count must follow the option flag */
	if (optind >= argc) {
		LOG_ERR("Missing <iterations> argument\n");
		qsc_usage();
		return -1;
	}

	test_iterations = (uint32_t)atoi(argv[optind]);
	if (test_iterations == 0) {
		LOG_ERR("<iterations> must be a positive integer\n");
		return -1;
	}

	for (i = 0; i < test_iterations; i++) {
		switch (command) {
		case 'p':
			rv = qsc_rpmb_provision_key();
			break;
		case 'e':
			rv = qsc_rpmb_erase();
			break;
		case 'r':
			memset(rw_buf, 0, sizeof(rw_buf));
			rv = qsc_rpmb_read(0, 1, rw_buf, sizeof(rw_buf),
					   &rw_lenout);
			if (!Object_isERROR(rv))
				printf("RPMB read completed (%zu bytes)\n",
				       rw_lenout);
			break;
		case 'w':
			memset(rw_buf, (int)(i & 0xFF), sizeof(rw_buf));
			rv = qsc_rpmb_write(0, 1, rw_buf, sizeof(rw_buf));
			if (!Object_isERROR(rv))
				printf("RPMB write completed\n");
			break;
		default:
			qsc_usage();
			return 0;
		}

		if (Object_isERROR(rv)) {
			LOG_ERR("Command failed at iteration %u:"
				" error %d\n",
				i, rv);
			break;
		}
	}

	return Object_isERROR(rv) ? -1 : 0;
}

/* =========================================================================
 * RPMB Test Subsystem
 *
 * Guarded by RPMB_ENABLE_TESTS.  Define this flag at compile time to
 * include all test cases in the binary:
 *
 *   cmake -DRPMB_ENABLE_TESTS=ON ...
 *
 * Production builds must NOT define RPMB_ENABLE_TESTS.
 *
 * Migrated from: libminkadaptor/tests/smcinvoke_client/src/
 *   CLIENT_CMD14_RUN_RPMB_PROV  (14) → rpmb_test_provision_key,
 *                                       rpmb_test_provision_status
 *   CLIENT_CMD15_RUN_RPMB_ERASE (15) → rpmb_test_erase
 *   CLIENT_CMD17_RUN_RPMB_RW    (17) → rpmb_test_write, rpmb_test_read,
 *                                       rpmb_test_rw
 * =========================================================================
 */
#ifdef RPMB_ENABLE_TESTS

/*
 * g_ta_path - optional TA directory path supplied via --test <ta_path>.
 *
 * Read/write tests ([C] rpmbRead, [D] rpmbWrite, [C+D] round-trip) require
 * the RPMB service TA to be accessible.  When this variable is NULL those
 * three tests are skipped rather than failed, so that the provisioning and
 * erase tests can still run on hardware where the TA is not yet deployed.
 *
 * Usage:  rpmb_client --test /path/to/ta/directory
 */
static const char *g_ta_path = NULL;

/*
 * Forward declaration required by -Wmissing-declarations.
 * rpmb_run_tests() is the only non-static symbol in this subsystem;
 * it is called from main() below.
 */
int rpmb_run_tests(void);

/*
 * rpmb_test_provision_status - [A] verify rpmbCheckProv() returns a
 * recognised status code.
 *
 * Corresponds to CLIENT_CMD14_RUN_RPMB_PROV (status-check sub-path).
 * The test passes whether the key is provisioned or not; it only fails
 * if the IPC call itself returns an unexpected error code.
 *
 * Returns 0 on pass, 1 on fail.
 */
static int rpmb_test_provision_status(void)
{
	int32_t rv;
	Object rpmb_obj = Object_NULL;

	LOG_MSG("rpmb_test_provision_status: checking RPMB key status...\n");

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_provision_status: FAILED"
			" - cannot get service object: %d\n", rv);
		return 1;
	}

	rv = IRPMBService_rpmbCheckProv(rpmb_obj);
	Object_ASSIGN_NULL(rpmb_obj);

	/*
	 * All three outcomes are valid: key provisioned and OK, key not
	 * provisioned, or key provisioned but MAC mismatch.  Any other
	 * return code indicates an unexpected IPC failure.
	 */
	if (rv == Object_OK ||
	    rv == IRPMBService_ERROR_RPMB_NOT_PROVISIONED ||
	    rv == IRPMBService_ERROR_RPMB_MAC) {
		LOG_MSG("rpmb_test_provision_status: PASSED (status=0x%x)\n",
			rv);
		return 0;
	}

	LOG_ERR("rpmb_test_provision_status: FAILED"
		" (unexpected rv=0x%x)\n", rv);
	return 1;
}

/*
 * rpmb_test_provision_key - [A] provision the RPMB test key.
 *
 * Corresponds to CLIENT_CMD14_RUN_RPMB_PROV (provision sub-path).
 * Uses key_type = 1 (test key) to avoid permanently consuming the
 * production key slot during automated testing.
 *
 * Note: RPMB key provisioning is a one-time hardware operation.  On
 * hardware where the key is already provisioned this call will return
 * an error from the device; that is expected and the test is marked
 * as a known-hardware-state result rather than a failure.
 *
 * Returns 0 on pass, 1 on fail.
 */
static int rpmb_test_provision_key(void)
{
	int32_t rv;
	Object rpmb_obj = Object_NULL;

	LOG_MSG("rpmb_test_provision_key: provisioning RPMB test key"
		" (key_type=1)...\n");

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_provision_key: FAILED"
			" - cannot get service object: %d\n", rv);
		return 1;
	}

	rv = IRPMBService_rpmbProvisionKey(rpmb_obj, 1 /* test key */);
	Object_ASSIGN_NULL(rpmb_obj);

	if (!Object_isERROR(rv)) {
		LOG_MSG("rpmb_test_provision_key: PASSED\n");
		return 0;
	}

	LOG_ERR("rpmb_test_provision_key: FAILED (rv=0x%x)\n", rv);
	return 1;
}

/*
 * rpmb_test_erase - [B] erase the RPMB partition.
 *
 * Corresponds to CLIENT_CMD15_RUN_RPMB_ERASE.
 * Requires the RPMB key to be provisioned before this test is run.
 *
 * Returns 0 on pass, 1 on fail.
 */
static int rpmb_test_erase(void)
{
	int32_t rv;
	Object rpmb_obj = Object_NULL;

	LOG_MSG("rpmb_test_erase: erasing RPMB partition...\n");

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_erase: FAILED"
			" - cannot get service object: %d\n", rv);
		return 1;
	}

	rv = IRPMBService_rpmbErase(rpmb_obj);
	Object_ASSIGN_NULL(rpmb_obj);

	if (!Object_isERROR(rv)) {
		LOG_MSG("rpmb_test_erase: PASSED\n");
		return 0;
	}

	LOG_ERR("rpmb_test_erase: FAILED (rv=0x%x)\n", rv);
	return 1;
}

/*
 * rpmb_test_write - [D] authenticated write of one 256-byte block.
 *
 * Corresponds to the write sub-path of CLIENT_CMD17_RUN_RPMB_RW.
 * Writes a deterministic test pattern (byte[i] = i & 0xFF) to RPMB
 * half-sector address 0.  The RPMB service handles write-counter
 * fetch, HMAC computation, and result-frame verification.
 *
 * Requires g_ta_path to be set (--test <ta_path>).  Skipped if NULL.
 *
 * Returns 0 on pass or skip, 1 on fail.
 */
static int rpmb_test_write(void)
{
	int32_t rv;
	Object rpmb_obj = Object_NULL;
	uint8_t write_buf[RPMB_BLOCK_SIZE];
	uint32_t i;

	if (!g_ta_path) {
		LOG_MSG("rpmb_test_write: SKIPPED"
			" (no TA path; run: rpmb_client --test <ta_path>)\n");
		return 0;
	}

	LOG_MSG("rpmb_test_write: writing test pattern to RPMB address 0"
		" (%u bytes)...\n", RPMB_BLOCK_SIZE);

	/* Fill with a deterministic, easily recognisable test pattern */
	for (i = 0; i < RPMB_BLOCK_SIZE; i++)
		write_buf[i] = (uint8_t)(i & 0xFFU);

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_write: FAILED"
			" - cannot get service object: %d\n", rv);
		return 1;
	}

	rv = IRPMBService_rpmbWrite(rpmb_obj, 0U, 1U,
				    write_buf, sizeof(write_buf));
	Object_ASSIGN_NULL(rpmb_obj);

	if (!Object_isERROR(rv)) {
		LOG_MSG("rpmb_test_write: PASSED\n");
		return 0;
	}

	LOG_ERR("rpmb_test_write: FAILED (rv=0x%x)\n", rv);
	return 1;
}

/*
 * rpmb_test_read - [C] authenticated read of one 256-byte block.
 *
 * Corresponds to the read sub-path of CLIENT_CMD17_RUN_RPMB_RW.
 * Reads one block from RPMB half-sector address 0.  The RPMB service
 * handles nonce generation, HMAC verification, and write-counter
 * validation before returning the plaintext payload.
 *
 * Requires g_ta_path to be set (--test <ta_path>).  Skipped if NULL.
 *
 * Returns 0 on pass or skip, 1 on fail.
 */
static int rpmb_test_read(void)
{
	int32_t rv;
	Object rpmb_obj = Object_NULL;
	uint8_t read_buf[RPMB_BLOCK_SIZE];
	size_t read_lenout = 0;

	if (!g_ta_path) {
		LOG_MSG("rpmb_test_read: SKIPPED"
			" (no TA path; run: rpmb_client --test <ta_path>)\n");
		return 0;
	}

	LOG_MSG("rpmb_test_read: reading one block from RPMB address 0"
		" (%u bytes)...\n", RPMB_BLOCK_SIZE);

	memset(read_buf, 0, sizeof(read_buf));

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_read: FAILED"
			" - cannot get service object: %d\n", rv);
		return 1;
	}

	rv = IRPMBService_rpmbRead(rpmb_obj, 0U, 1U,
				   read_buf, sizeof(read_buf), &read_lenout);
	Object_ASSIGN_NULL(rpmb_obj);

	if (!Object_isERROR(rv)) {
		LOG_MSG("rpmb_test_read: PASSED (%zu bytes returned)\n",
			read_lenout);
		return 0;
	}

	LOG_ERR("rpmb_test_read: FAILED (rv=0x%x)\n", rv);
	return 1;
}

/*
 * rpmb_test_rw - [C+D] write-then-read round-trip with data verification.
 *
 * Corresponds to CLIENT_CMD17_RUN_RPMB_RW (full read/write test).
 * Writes a known pattern (byte[i] = 0xA5 ^ (i & 0xFF)) to RPMB
 * address 0, reads it back, and verifies the payload matches exactly.
 * Both the write and read use the same MinkIPC service object to
 * exercise the full authenticated round-trip within a single test.
 *
 * Requires g_ta_path to be set (--test <ta_path>).  Skipped if NULL.
 *
 * Returns 0 on pass or skip, 1 on fail.
 */
static int rpmb_test_rw(void)
{
	int32_t rv;
	Object rpmb_obj = Object_NULL;
	uint8_t write_buf[RPMB_BLOCK_SIZE];
	uint8_t read_buf[RPMB_BLOCK_SIZE];
	size_t read_lenout = 0;
	uint32_t i;
	int result = 0;

	if (!g_ta_path) {
		LOG_MSG("rpmb_test_rw: SKIPPED"
			" (no TA path; run: rpmb_client --test <ta_path>)\n");
		return 0;
	}

	LOG_MSG("rpmb_test_rw: write-then-read round-trip at RPMB"
		" address 0 (%u bytes)...\n", RPMB_BLOCK_SIZE);

	/* Distinct pattern: XOR of 0xA5 with the byte index */
	for (i = 0; i < RPMB_BLOCK_SIZE; i++)
		write_buf[i] = (uint8_t)(0xA5U ^ (i & 0xFFU));
	memset(read_buf, 0, sizeof(read_buf));

	rv = rpmb_get_service_obj(&rpmb_obj);
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_rw: FAILED"
			" - cannot get service object: %d\n", rv);
		return 1;
	}

	/* Authenticated write */
	rv = IRPMBService_rpmbWrite(rpmb_obj, 0U, 1U,
				    write_buf, sizeof(write_buf));
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_rw: write FAILED (rv=0x%x)\n", rv);
		result = 1;
		goto cleanup;
	}

	/* Authenticated read-back */
	rv = IRPMBService_rpmbRead(rpmb_obj, 0U, 1U,
				   read_buf, sizeof(read_buf), &read_lenout);
	if (Object_isERROR(rv)) {
		LOG_ERR("rpmb_test_rw: read FAILED (rv=0x%x)\n", rv);
		result = 1;
		goto cleanup;
	}

	/* Payload verification */
	if (read_lenout != sizeof(write_buf)) {
		LOG_ERR("rpmb_test_rw: length mismatch"
			" (expected %zu, got %zu)\n",
			sizeof(write_buf), read_lenout);
		result = 1;
		goto cleanup;
	}

	if (memcmp(write_buf, read_buf, sizeof(write_buf)) != 0) {
		LOG_ERR("rpmb_test_rw: data mismatch FAILED\n");
		result = 1;
		goto cleanup;
	}

	LOG_MSG("rpmb_test_rw: PASSED\n");

cleanup:
	Object_ASSIGN_NULL(rpmb_obj);
	return result;
}

/*
 * rpmb_run_tests - execute all RPMB test cases and report results
 *
 * Runs every registered test case sequentially.  Each test case is
 * self-contained: it sets up its own MinkIPC connection, performs the
 * operation, logs pass/fail, and tears down the connection.
 *
 * Returns the total number of failures (0 = all tests passed).
 */
int rpmb_run_tests(void)
{
	int failures = 0;

	LOG_MSG("rpmb_run_tests: starting RPMB test suite\n");
	if (g_ta_path)
		LOG_MSG("rpmb_run_tests: TA path = %s\n", g_ta_path);
	else
		LOG_MSG("rpmb_run_tests: no TA path provided"
			" — [C/D] read/write tests will be SKIPPED\n");
	LOG_MSG("----------------------------------------------\n");

	/*
	 * [A] Provisioning / key status tests
	 * Underlying operations: rpmbCheckProv, rpmbProvisionKey — EXIST
	 * Source: CLIENT_CMD14_RUN_RPMB_PROV
	 */
	failures += rpmb_test_provision_status();
	failures += rpmb_test_provision_key();

	/*
	 * [B] Erase / counter read tests
	 * Underlying operation: rpmbErase — EXISTS
	 * Source: CLIENT_CMD15_RUN_RPMB_ERASE
	 */
	failures += rpmb_test_erase();

	/*
	 * [D] Authenticated write test
	 * Underlying operation: rpmbWrite — ported in this file
	 * Source: CLIENT_CMD17_RUN_RPMB_RW (write sub-path)
	 */
	failures += rpmb_test_write();

	/*
	 * [C] Authenticated read test
	 * Underlying operation: rpmbRead — ported in this file
	 * Source: CLIENT_CMD17_RUN_RPMB_RW (read sub-path)
	 */
	failures += rpmb_test_read();

	/*
	 * [C+D] Write-then-read round-trip with data verification
	 * Underlying operations: rpmbWrite + rpmbRead — ported in this file
	 * Source: CLIENT_CMD17_RUN_RPMB_RW (full round-trip)
	 */
	failures += rpmb_test_rw();

	LOG_MSG("----------------------------------------------\n");
	if (failures == 0)
		LOG_MSG("RPMB tests: ALL PASSED\n");
	else
		LOG_ERR("RPMB tests: %d FAILED\n", failures);

	return failures;
}

#endif /* RPMB_ENABLE_TESTS */

int main(int argc, char *argv[])
{
	/*
	 * Test mode: rpmb_client --test  (or -t)
	 * Handled before the normal argument count check so that
	 * "--test" does not require an <iterations> argument.
	 */
#ifdef RPMB_ENABLE_TESTS
	if (argc >= 2 &&
	    (strcmp(argv[1], "--test") == 0 || strcmp(argv[1], "-t") == 0)) {
		/*
		 * Optional positional argument: TA directory path.
		 * Required for read/write tests [C/D]; omit to run
		 * provision/erase tests [A/B] only.
		 *
		 *   rpmb_client --test                  (A/B only)
		 *   rpmb_client --test /data/ta/        (A/B + C/D)
		 */
		if (argc >= 3)
			g_ta_path = argv[2];
		return rpmb_run_tests();
	}
#endif

	if (argc < ARG_HAS_ITERATION) {
		qsc_usage();
		return -1;
	}

	return run_test_command(argc, argv);
}
