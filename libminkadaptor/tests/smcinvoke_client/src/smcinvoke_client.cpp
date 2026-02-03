// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include <cstring>
#include <string>

#include "smcinvoke_client.h"

#include "CAppLoader.h"
#include "CDiagnostics.h"
#include "CIO.h"
#include "CTestCallable_open.h"
#include "CTestCallable_priv.h"
#include "IAppController.h"
#include "IAppLegacyTest.h"
#include "IAppLoader.h"
#include "IClientEnv.h"
#include "IDiagnostics.h"
#include "IOpener.h"
#include "ITestCBack.h"
#include "ITestMemManager.h"
#include "MinkCom.h"
#include "tzecotestapp_uids.h"
#include "tzt.h"
#include <qcbor/qcbor.h>

int32_t create_and_assign_mem_obj(Object, Object *);

static void usage(void)
{
	printf("\n\n---------------------------------------------------------\n"
	       "Usage: smcinvoke_client -[OPTION] [ARGU_1] ...... [ARGU_n]\n\n"
	       "Runs the user space tests specified by option and arguments \n"
	       "parameter(s).\n"
	       "\n\n"
	       "OPTION can be:\n"
	       "  -i, Run internal test cases related to listeners etc.\n"
	       "      e.g. smcinvoke_client -i /data/smplap64.mbn <cmd> <no_of_iterations>\n"
	       "  -c, Run tests for checking callback object support via MinkIPC\n"
	       "      e.g. smcinvoke_client -c /data <no_of_iterations>\n"
	       "  -d  Run the TZ diagnostics test that prints basic info on TZ heaps\n"
	       "      e.g. smcinvoke_client -d <no_of_iterations>\n"
	       "  -m  Run tests for checking memory object support via MinkIPC\n"
	       "      e.g. smcinvoke_client -m /data <no_of_iterations>\n"
	       "  -h, Print this help message and exit\n\n\n");
}

static int64_t get_time_in_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (int64_t)(tv.tv_sec * 1000) + (int64_t)(tv.tv_usec / 1000);
}

static int realloc_useful_buf(UsefulBuf *buf)
{
	void *ptr;

	ptr = realloc(buf->ptr, buf->len + CREDENTIALS_BUF_SIZE_INC);
	if (!ptr)
		return -1;

	buf->ptr = ptr;
	buf->len += CREDENTIALS_BUF_SIZE_INC;
	memset(buf->ptr, 0, buf->len);

	return 0;
}

/* Get credentials. */
static void* get_self_creds(size_t *buf_len)
{
	QCBOREncodeContext e_ctx;
	void *credential_buf = nullptr;
	UsefulBufC enc;
	UsefulBuf creds_useful_buf = { NULL, 0 };

	do {
		if (realloc_useful_buf(&creds_useful_buf)) {
			free(creds_useful_buf.ptr);
			return nullptr;
		}

		/* Use UID and system time to create a CBOR buffer. */
		QCBOREncode_Init(&e_ctx, creds_useful_buf);
		QCBOREncode_OpenMap(&e_ctx);
		QCBOREncode_AddInt64ToMapN(&e_ctx, attr_uid, getuid());
		QCBOREncode_AddInt64ToMapN(&e_ctx, attr_system_time,
					   get_time_in_ms());
		QCBOREncode_CloseMap(&e_ctx);
	} while (QCBOREncode_Finish(&e_ctx, &enc) ==
		 QCBOR_ERR_BUFFER_TOO_SMALL);

	credential_buf = (void *)enc.ptr;
	*buf_len = enc.len;

	return credential_buf;
}

int32_t create_and_assign_mem_obj(Object root, Object *argptr)
{
	int32_t result = Object_OK;
	void* alignedPtr = NULL;
	Object mo = Object_NULL;
	struct smcinvoke_priv_handle handle = { NULL, 0 };

	// Create a memory object of 32 KB
	result = MinkCom_getMemoryObject(root, 8*SIZE_4KB, &mo);
	if (result) {
		LOGE_PRINT("MinkCom_getMemoryObject failed: 0x%x\n", result);
		return result;
	}

	result = MinkCom_getMemoryObjectInfo(mo, &handle.addr, &handle.size);
	if (result) {
		LOGE_PRINT("MinkCom_getMemoryObjectInfo failed: 0x%x\n", result);
		goto err;
	}

	// Write into it
	alignedPtr = handle.addr;
	*(uint64_t*)alignedPtr = ITestMemManager_TEST_PATTERN1;

	Object_INIT(*argptr, mo);
err:
	Object_ASSIGN_NULL(mo);
	return result;
}

static void test_smcinvoke_memobj_basic(Object rootEnv, Object appObj)
{
	Object mmTestObj = Object_NULL;
	void* alignedPtr = NULL;
	void* alignedPtr1 = NULL;
	Object memObj = Object_NULL;
	Object memObj1 = Object_NULL;
	struct smcinvoke_priv_handle handle = { NULL, 0 };
	struct smcinvoke_priv_handle handle1 = { NULL, 0 };

	// Get the memmgr test object
	SILENT_OK(IOpener_open(appObj, CTzEcoTestApp_TestMemManager_UID, &mmTestObj));

	// Get a memory object
	SILENT_OK(MinkCom_getMemoryObject(rootEnv, SIZE_4KB, &memObj));
	TEST_FALSE(Object_isNull(memObj));

	// Get address and size of backing memory in handle
	SILENT_OK(MinkCom_getMemoryObjectInfo(memObj, &handle.addr, &handle.size));
	LOGD_PRINT("addr = %p, size = 0x%lx\n", handle.addr, handle.size);

	// Write to the memory
	alignedPtr = handle.addr;
	*(uint64_t*)alignedPtr = ITestMemManager_TEST_PATTERN1;

	LOGD_PRINT("send buf %lx\n", *(uint64_t*)alignedPtr);

	// Send memory object to TA
	SILENT_OK(ITestMemManager_access(mmTestObj, memObj));

	// Did the TA modify it?
	LOGD_PRINT("return buf %lx\n", *(uint64_t*)alignedPtr);

	SILENT_TRUE(*(uint64_t*)alignedPtr == ITestMemManager_TEST_PATTERN2);

	// Send the same memory object again (mapping information is not sent again)
	*(uint64_t*)alignedPtr = ITestMemManager_TEST_PATTERN1;
	LOGD_PRINT("Mem obj sent 2nd time: send buf %lx\n", *(uint64_t*)alignedPtr);

	SILENT_OK(ITestMemManager_access(mmTestObj, memObj));
	LOGD_PRINT("Mem obj sent 2nd time: return buf %lx\n",
		   *(uint64_t*)alignedPtr);
	SILENT_TRUE(*(uint64_t*)alignedPtr == ITestMemManager_TEST_PATTERN2);

	MSGV("PASSED - Single Memory Object access Test.\n");

	// Get another memory object
	SILENT_OK(MinkCom_getMemoryObject(rootEnv, SIZE_4KB, &memObj1));
	TEST_FALSE(Object_isNull(memObj1));

	SILENT_OK(MinkCom_getMemoryObjectInfo(memObj1, &handle1.addr, &handle1.size));
	LOGD_PRINT("addr = %p, size = 0x%lx\n", handle1.addr, handle1.size);

	// Send two memory objects and test TA access to both
	*(uint64_t*)alignedPtr = ITestMemManager_TEST_PATTERN1;
	LOGD_PRINT("1st mem obj: send buf %lx\n", *(uint64_t*)alignedPtr);

	alignedPtr1 = handle1.addr;
	*(uint64_t*)alignedPtr1 = ITestMemManager_TEST_PATTERN1;
	LOGD_PRINT("2nd mem obj: send buf %lx\n", *(uint64_t*)alignedPtr1);

	SILENT_OK(ITestMemManager_accessTwoMemObjects(mmTestObj, memObj, memObj1));

	LOGD_PRINT("1st mem obj: return buf %lx\n", *(uint64_t*)alignedPtr);
	LOGD_PRINT("2nd mem obj: return buf %lx\n", *(uint64_t*)alignedPtr1);
	SILENT_TRUE(*(uint64_t*)alignedPtr == ITestMemManager_TEST_PATTERN2);
	SILENT_TRUE(*(uint64_t*)alignedPtr1 == ITestMemManager_TEST_PATTERN2);

	Object_ASSIGN_NULL(memObj1);
	Object_ASSIGN_NULL(memObj);

	MSGV("PASSED - Two Memory Object access Test.\n");

	// Send a memory object and release it immediately (without mapping)
	SILENT_OK(MinkCom_getMemoryObject(rootEnv, SIZE_4KB, &memObj));
	TEST_FALSE(Object_isNull(memObj));

	SILENT_OK(ITestMemManager_releaseImmediately(mmTestObj, memObj));

	// Free the objects
	Object_ASSIGN_NULL(memObj);
	Object_ASSIGN_NULL(mmTestObj);
}

static void test_smcinvoke_cback_basic(Object appObj, Object root, Object clientEnv)
{
	Object oTCB = Object_NULL;
	Object oCB = Object_NULL;
	Object oCB1 = Object_NULL;
	Object mem_oCB = Object_NULL;
	TestCallable *cb = NULL;
	uint8_t bi[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	int ret = Object_OK;

	// Get the remote test object from the TA
	SILENT_OK(IOpener_open(appObj, CTzEcoTestApp_TestCBack_UID, &oTCB));

	// Get a local callable object
	SILENT_OK(CTestCallable_open(clientEnv, root, &oCB));
	cb = (TestCallable *)oCB.context;

	// Set the expected return and check preconditions
	SILENT_TRUE(cb->op == -1);
	SILENT_TRUE(cb->counter == 0);
	SILENT_TRUE(cb->refs == 1);
	cb->retValue = Object_OK;

	ret = ITestCBack_call(oTCB, oCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	// Check it happened as expected
	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_call);

	// Repeat with BI
	cb->counter = 0;
	// Some unique error code which doesn't overlap with Mink error codes
	cb->retValueError = 0x0AFAFAFA;
	cb->bArg_ptr = bi;
	cb->bArg_len = sizeof(bi);

	ret = ITestCBack_callWithBuffer(oTCB, bi, sizeof(bi), oCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callWithBuffer);

	// And with a buffer that doesn't match
	cb->counter = 0;

	ret = ITestCBack_callWithBuffer(oTCB, bi, sizeof(bi) - 1, oCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	SILENT_TRUE(ret == cb->retValueError);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callWithBuffer);

	MSGV("PASSED - Callback tests with Buffer inputs.\n");

	// With another callable object as argument
	SILENT_OK(CTestCallable_open(clientEnv, root, &oCB1));
	cb->counter = 0;
	Object_ASSIGN(cb->oArg, oCB1);
	ret = ITestCBack_callWithObject(oTCB, oCB1, oCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callWithObject);

	// Now with a remote object as argument
	cb->counter = 0;
	cb->op = -1;
	ret = ITestCBack_callWithObject(oTCB, oTCB, oCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	SILENT_TRUE(ret = ITestCallable_ERROR_OBJECT_REMOTE);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callWithObject);

	Object_RELEASE_IF(oCB1);

	// Now test the callback object is retained by TA
	cb->counter = 0;
	cb->op = -1;
	ret = ITestCBack_set(oTCB, oCB);
	SILENT_OK(ret);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	SILENT_TRUE(cb->counter == 0);
	SILENT_TRUE(cb->op == -1);

	// Now call it
	ret = ITestCBack_callSet(oTCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	// Check it happened as expected
	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_call);

	// Release it
	cb->counter = 0;
	cb->op = -1;
	ret = ITestCBack_set(oTCB, Object_NULL);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	SILENT_OK(ret);
	SILENT_TRUE(cb->counter == 0);
	SILENT_TRUE(cb->op == -1);

	// Release callback object after set
	ret = ITestCBack_set(oTCB, oCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	// Release it
	Object_ASSIGN_NULL(oCB);
	ret = ITestCBack_callSet(oTCB);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	ret = ITestCBack_set(oTCB, Object_NULL);
	LOGD_PRINT("%s:%d: ret=0x%x counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);

	MSGV("PASSED - Callback tests with Remote and Callback object inputs.\n");

	/* Test use case that returns memory object in callback response and
	 * also checks for any memory leak caused by this mem object.
	 */
	SILENT_OK(CTestCallable_open(clientEnv, root, &mem_oCB));
	cb = (TestCallable*)mem_oCB.context;
	SILENT_TRUE(cb->op == -1);
	SILENT_TRUE(cb->counter == 0);
	SILENT_TRUE(cb->refs == 1);
	cb->retValue = Object_OK;
	// Some unique error code which doesn't overlap with Mink error codes
	cb->retValueError = 0xFAFAFAFA;

	ret = ITestCBack_callGetMemObject(oTCB, mem_oCB);
	LOGD_PRINT("%s:%d: ret=%d counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);
	SILENT_OK(ret);
	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callGetMemObject);

	/* After returning from QTEE, the memory object should be released */

	/* Test use case for returning memory objects in a callback response
	 * with different paramters
	 */
	cb->op = -1;
	cb->counter = 0;
	cb->bArg_ptr = bi;
	cb->bArg_len = sizeof(bi);

	ret = ITestCBack_callGetMemObjectWithBufferIn(oTCB, bi, sizeof(bi), mem_oCB);
	LOGD_PRINT("%s:%d: ret=%d counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);
	SILENT_OK(ret);
	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callGetMemObjectWithBufferIn);

	/* BO */
	cb->op = -1;
	cb->counter = 0;
	cb->bArg_ptr = NULL;
	cb->bArg_len = 0;

	ret = ITestCBack_callGetMemObjectWithBufferOut(oTCB, mem_oCB);
	LOGD_PRINT("%s:%d: ret=%d counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);
	SILENT_OK(ret);
	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callGetMemObjectWithBufferOut);

	/* BI and BO */
	cb->op = -1;
	cb->counter = 0;
	cb->bArg_ptr = bi;
	cb->bArg_len = sizeof(bi);

	ret = ITestCBack_callGetMemObjectWithBufferInAndOut(oTCB, bi, sizeof(bi), mem_oCB);

	LOGD_PRINT("%s:%d: ret=%d counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);
	SILENT_OK(ret);
	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callGetMemObjectWithBufferInAndOut);

	/* Test two memory objects returned in a callback resopnse */
	cb->op = -1;
	cb->counter = 0;
	cb->bArg_ptr = NULL;
	cb->bArg_len = 0;

	ret = ITestCBack_callGetTwoMemObjects(oTCB, mem_oCB);

	LOGD_PRINT("%s:%d: ret=%d counter=%zu op=%d refs=%d\n", __FUNCTION__,
		   __LINE__, ret, cb->counter, cb->op, cb->refs);
	SILENT_OK(ret);
	SILENT_TRUE(ret == cb->retValue);
	SILENT_TRUE(cb->counter == 1);
	SILENT_TRUE(cb->op == ITestCallable_OP_callGetTwoMemObjects);

	MSGV("PASSED - Callback tests with Memory Object inputs.\n");

	// We are done!
	Object_ASSIGN_NULL(mem_oCB);
	Object_ASSIGN_NULL(oTCB);
}

static int __readFile(std::string const &filename, size_t &size,
		      uint8_t *buffer)
{
	FILE *file = NULL;
	size_t readBytes = 0;
	int ret = 0;

	do {
		file = fopen(filename.c_str(), "r");
		if (file == NULL) {
			LOGE_PRINT("Failed to open file %s: %s (%d)\n",
				   filename.c_str(), strerror(errno), errno);
			ret = -1;
			break;
		}

		readBytes = fread(buffer, 1, size, file);
		if (readBytes != size) {
			LOGE_PRINT(
				"Error reading the file %s: %zu vs %zu bytes: %s (%d)\n",
				filename.c_str(), readBytes, size,
				strerror(errno), errno);
			ret = -1;
			break;
		}

		ret = size;
	} while (0);

	if (file) {
		fclose(file);
	}

	return ret;
}

static int __getFileSize(std::string const &filename)
{
	FILE *file = NULL;
	int size = 0;
	int ret = 0;

	do {
		file = fopen(filename.c_str(), "r");
		if (file == NULL) {
			LOGE_PRINT("Failed to open file %s: %s (%d)\n",
				   filename.c_str(), strerror(errno), errno);
			size = -1;
			break;
		}

		ret = fseek(file, 0L, SEEK_END);
		if (ret) {
			LOGE_PRINT("Error seeking in file %s: %s (%d)\n",
				   filename.c_str(), strerror(errno), errno);
			size = -1;
			break;
		}

		size = ftell(file);
		if (size == -1) {
			LOGE_PRINT("Error telling size of file %s: %s (%d)\n",
				   filename.c_str(), strerror(errno), errno);
			size = -1;
			break;
		}
	} while (0);

	if (file) {
		fclose(file);
	}

	return size;
}

static int loadApp(Object appLoader, std::string const &path,
		   Object *appController, Object *appLegacy)
{
	size_t size = 0;
	uint8_t *buffer = NULL;
	int ret = 0;

	do {
		ret = __getFileSize(path);
		if (ret <= 0) {
			ret = -1;
			break;
		}

		size = (size_t)ret;
		buffer = new uint8_t[size];
		if (buffer == NULL) {
			LOGE_PRINT("Buffer allocation failed.\n");
			ret = -1;
			break;
		}

		ret = __readFile(path, size, buffer);
		if (ret < 0)
			break;
		MSGE("Load %s, size %zu, buf %p.\n", path.c_str(), size,
		     buffer);

		ret = IAppLoader_loadFromBuffer(appLoader, buffer, size,
						appController);
		if (ret) {
			LOGE_PRINT("Loading %s app failed, ret: %d\n",
				   path.c_str(), ret);
			break;
		}

		SILENT_OK(IAppController_getAppObject(*appController, appLegacy));

	} while (0);

	if (buffer)
		delete[] buffer;

	return ret;
}

static int sendCommand(uint32_t cmdId, Object appLegacy, bool b32)
{
	int ret	= Object_OK;
	struct qsc_send_cmd smplap32_req;
	struct qsc_send_cmd_64bit smplap64_req;
	struct qsc_send_cmd_rsp smplap_rsp;
	size_t rspSizeOut = sizeof(smplap_rsp);
	void * req = NULL;
	size_t reqLen = 0;

	if (b32) {
		req = &smplap32_req;
		reqLen = sizeof(smplap32_req);
	} else {
		req = &smplap64_req;
		reqLen = sizeof(smplap64_req);
	}

	smplap32_req.cmd_id = cmdId;
	smplap64_req.cmd_id = cmdId;
	smplap_rsp.status = -1;

	LOGD_PRINT("CMD: %u (%s)", cmdId, (b32) ? "32" : "64");

	switch (cmdId) {
	case CLIENT_CMD5_RUN_GPFS_TEST:
	case CLIENT_CMD6_RUN_FS_TEST:
	case CLIENT_CMD14_RUN_RPMB_PROV:
	case CLIENT_CMD15_RUN_RPMB_ERASE:
	case CLIENT_CMD17_RUN_RPMB_RW:
		ret = IAppLegacyTest_handleRequest(appLegacy, req, reqLen, &smplap_rsp, sizeof(smplap_rsp), &rspSizeOut);
		if (ret) break;
		SILENT_TRUE(rspSizeOut == sizeof(smplap_rsp));
		ret = smplap_rsp.status;
		break;
	default:
		LOGD_PRINT("Command %d is currently unsupported\n", cmdId);
		smplap_rsp.status = SMCINVOKE_TEST_NOT_IMPLEMENTED;
		break;
	}

	if (smplap_rsp.status == SMCINVOKE_TEST_NOT_IMPLEMENTED) {
		LOGD_PRINT("Command is not supported, resp status: %d\n", smplap_rsp.status);
	} else if (Object_isOK(ret) && (smplap_rsp.status == 0)) {
		LOGD_PRINT("sendCommand succeeded\n");
	} else {
		LOGE_PRINT("sendCommand failed: %d %d (%x)\n", ret, smplap_rsp.status, smplap_rsp.status);
	}

	if (ret == 0 && (smplap_rsp.status != SMCINVOKE_TEST_NOT_IMPLEMENTED)) {
		ret = smplap_rsp.status;
	}

	return ret;
}

static int run_internal_app(int argc, char *argv[])
{
	int ret = Object_OK;
	size_t i = 0;
	Object rootEnv = Object_NULL;
	Object clientEnv = Object_NULL;
	Object appLoader = Object_NULL;
	Object appLegacy = Object_NULL;
	Object appController = Object_NULL;
	int32_t type = 0;
	bool b32 = false;

	if (argc < 5) {
		usage();
		return -1;
	}

	std::string appName   = argv[2];
	uint32_t cmdId        = atoi(argv[3]);
	size_t testIterations = atoi(argv[4]);

	if (argc == 6) {
		type = atoi(argv[5]);
		b32 = (type & 1) ? true: false;
	}

	LOGD_PRINT("Executing command %u on %s (%s) load from buffer for %zu"
		   "times\n", cmdId, appName.c_str(), (b32) ? "32bit" : "64bit",
		   testIterations);

	SILENT_OK(MinkCom_getRootEnvObject(&rootEnv));
	SILENT_OK(MinkCom_getClientEnvObject(rootEnv, &clientEnv));
	SILENT_OK(IClientEnv_open(clientEnv, CAppLoader_UID, &appLoader));

	//load TA
	SILENT_OK(loadApp(appLoader, appName, &appController, &appLegacy));

	// run the test
	for (i = 0; i < testIterations; i++) {
		ret = sendCommand(cmdId, appLegacy, b32);
		if (ret) break;
	}

	if (ret) {
		LOGE_PRINT("TEST FAILED after %zu iterations\n", i);
	} else {
		LOGV_PRINT("TEST SUCCEEDED for %zu iterations\n", i);
	}

	// tear down the environment
	ret = IAppController_unload(appController);
	if (ret == 0)
		LOGD_PRINT("Unload Successful\n");

	Object_ASSIGN_NULL(appLegacy);
	Object_ASSIGN_NULL(appController);

	Object_ASSIGN_NULL(appLoader);
	Object_ASSIGN_NULL(clientEnv);
	Object_ASSIGN_NULL(rootEnv);

	return ret;
}

static int run_tzecotestapp_test(int argc, char *argv[], int flag)
{
	int32_t result = Object_OK;
	Object rootEnv = Object_NULL;
	Object clientEnv = Object_NULL;
	Object appLoader = Object_NULL;
	Object appController = Object_NULL;
	Object appObj = Object_NULL;

	if (argc < 3) {
		usage();
		return -1;
	}

	std::string appFullPath = argv[2];
	size_t iterations = atoi(argv[3]);

	SILENT_OK(MinkCom_getRootEnvObject(&rootEnv));
	SILENT_OK(MinkCom_getClientEnvObject(rootEnv, &clientEnv));
	SILENT_OK(IClientEnv_open(clientEnv, CAppLoader_UID, &appLoader));

	appFullPath.append("/").append("tzecotestapp.mbn");
	SILENT_OK(loadApp(appLoader, appFullPath, &appController, &appObj));

	for (size_t i = 0; i < iterations; i++) {
		switch (flag) {
		case CALLBACKOBJ:
			// Callback obj test
			test_smcinvoke_cback_basic(appObj, rootEnv, clientEnv);
			LOGD_PRINT(
				" test_smcinvoke_cback_basic iteration %zu finished\n",
				i);
			break;
		case MEMORYOBJ:
			/* memory obj test*/
			test_smcinvoke_memobj_basic(rootEnv, appObj);
			LOGD_PRINT(
				" test_smcinvoke_memobj_basic iteration %zu finished\n",
				i);
		default:
			break;
		}
	}

	result = IAppController_unload(appController);
	if (result == 0)
		LOGD_PRINT("Unload Successful\n");

	// Release the controller, thus also unloading the TA
	Object_release(appObj);
	Object_release(appController);

	Object_RELEASE_IF(appLoader);
	Object_RELEASE_IF(clientEnv);
	Object_RELEASE_IF(rootEnv);

	MSGV("TEST PASSED!\n");

	return 0;
}

static int run_tz_diagnostics_test(int argc, char *argv[])
{
	Object rootEnv = Object_NULL;
	Object credentials = Object_NULL;
	Object clientEnv = Object_NULL;
	Object appObject = Object_NULL;
	IDiagnostics_HeapInfo heapInfo;

	size_t len = 0;
	void* creds = NULL;

	if (argc < 2) {
		usage();
		return -1;
	}

	creds = get_self_creds(&len);
	if (!creds) {
		return -1;
	}

	CIO_open(creds, len, &credentials);

	int iterations = atoi(argv[2]);
	memset((void *)&heapInfo, 0, sizeof(IDiagnostics_HeapInfo));

	SILENT_OK(MinkCom_getRootEnvObject(&rootEnv));
	SILENT_OK(MinkCom_getClientEnvObjectWithCreds(rootEnv, credentials, &clientEnv));
	SILENT_OK(IClientEnv_open(clientEnv, CDiagnostics_UID, &appObject));

	for (int i = 0; i < iterations; i++) {
		MSGV("Retrieve TZ heap info Iteration %d\n", i);
		SILENT_OK(IDiagnostics_queryHeapInfo(appObject, &heapInfo));

		MSGV("%d = Total bytes as heap\n", heapInfo.totalSize);
		MSGV("%d = Total bytes allocated from heap\n",
			   heapInfo.usedSize);
		MSGV("%d = Total bytes free on heap\n",
			   heapInfo.freeSize);
		MSGV("%d = Total bytes overhead\n",
			   heapInfo.overheadSize);
		MSGV("%d = Total bytes wasted\n", heapInfo.wastedSize);
		MSGV("%d = Largest free block size\n\n",
			   heapInfo.largestFreeBlockSize);

		MSGV("TEST PASSED!\n\n");
	}

	Object_ASSIGN_NULL(appObject);
	Object_ASSIGN_NULL(clientEnv);
	Object_ASSIGN_NULL(credentials);
	Object_ASSIGN_NULL(rootEnv);
	return 0;
}

static int run_smcinvoke_test_command(int argc, char *argv[],
				      unsigned int test_mask)
{
	if ((test_mask & (1 << INTERNAL)) == (1U << INTERNAL)) {
		printf("Run internal test...\n");
		return run_internal_app(argc, argv);
	} else if ((test_mask & (1 << CALLBACKOBJ)) == (1U << CALLBACKOBJ)) {
		printf("Run callback obj test...\n");
		return run_tzecotestapp_test(argc, argv, CALLBACKOBJ);
	} else if ((test_mask & (1 << MEMORYOBJ)) == (1U << MEMORYOBJ)) {
		printf("Run memory obj test...\n");
		return run_tzecotestapp_test(argc, argv, MEMORYOBJ);
	} else if ((test_mask & (1 << PRINT_TZ_DIAGNOSTICS)) ==
		   (1U << PRINT_TZ_DIAGNOSTICS)) {
		printf("Run TZ Diagnostics and print those...\n");
		return run_tz_diagnostics_test(argc, argv);
	} else {
		usage();
		return -1;
	}
}

static unsigned int parse_command(int argc, char *const argv[])
{
	int command = 0;
	unsigned int ret = 0;

	while ((command = getopt_long(argc, argv, "icmdh", testopts, NULL)) !=
		-1) {
		switch (command) {
		case 'i':
			ret = 1 << INTERNAL;
			break;
		case 'c':
			ret = 1 << CALLBACKOBJ;
			break;
		case 'm':
			ret = 1 << MEMORYOBJ;
			break;
		case 'd':
			ret = 1 << PRINT_TZ_DIAGNOSTICS;
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
		}

		if (command == (int)('q') || command == (int)('e'))
			break;
	}

	optind = 1;

	return ret;
}

int main(int argc, char *argv[])
{
	unsigned int test_mask = parse_command(argc, argv);
	return run_smcinvoke_test_command(argc, argv, test_mask);
}
