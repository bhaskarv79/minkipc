// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <stdlib.h>

#include "mink_teec.h"
#include "MinkCom.h"

#include "IClientEnv.h"
#include "IGPSession.h"
#include "IGPAppClient.h"
#include "CGPAppClient.h"
#include "CWait_open.h"
#include "IWait.h"
#include "memscpy.h"

/**
 * @brief Get a MINK AppClient Object.
 *
 * @param root_obj The MINK root object for initiating communication with QTEE.
 * @param app_client The MINK AppClient object requested by the client.
 * @return Object_OK on success.
 *         Object_ERROR_* on failure.
 */
static int32_t mink_get_app_client(Object root_obj, Object *app_client)
{
	int32_t rv = Object_OK;
	Object client_env = Object_NULL;

	rv = MinkCom_getClientEnvObject(root_obj, &client_env);
	if (Object_isERROR(rv)) {
		MSGE("MinkCom_getClientEnvObject failed: 0x%x\n", rv);
		goto err_client_env;
	}

	/* Get the GPAppClient */
	rv = IClientEnv_open(client_env, CGPAppClient_UID, app_client);
	if (Object_isERROR(rv)) {
		MSGE("IClientEnv_open failed: %d\n", rv);
		goto err_app_client;
	}

err_app_client:
	Object_ASSIGN_NULL(client_env);

err_client_env:

	return rv;
}

/**
 * @brief Open a session with a Trusted Application over MINK-IPC.
 *
 * @param app_client The MINK AppClient object representing an opened context
 *                   with QTEE.
 * @param waiter_cbo The MINK Waiter Callback object to allow QTEE to request
 *                   cancellation of an invoked operation.
 * @param destination The UUID of the destination Trusted Application.
 * @param cancel_code A cancellation code to identify the cancellation request
 *                    on behalf of QTEE.
 * @param connection_method The method of connection to use.
 * @param connection_data Any necessary data required to support the connection
 *                        method chosen.
 * @param tee_paramTypes The type of the parameters in this request.
 * @param tee_exParamTypes The type of the extended parameters in this request
 *                         for use by QTEE.
 * @param m_params The MINK parameters passed to the MINK API in this request.
 * @param session The MINK object returned by QTEE to represent this session.
 * @param result The result returned from TEE.
 * @param eorigin The origin of the result from TEE.
 * @return Object_OK on success.
 *         Object_ERROR_* on failure.
 */
static int32_t
mink_open_session(Object app_client, Object waiter_cbo,
		  const TEEC_UUID *destination, uint32_t cancel_code,
		  uint32_t connection_method, uint32_t connection_data,
		  uint32_t tee_paramTypes, uint32_t tee_exParamTypes,
		  MINK_Parameter *m_params, Object *session,
		  TEEC_Result *result, uint32_t *eorigin)
{
	int32_t rv = Object_OK;
	uint32_t mem_sz_out[MAX_NUM_PARAMS] = { 0 };

	rv = IGPAppClient_openSession(app_client,
				      (const char *)destination,
				      sizeof(TEEC_UUID),
				      waiter_cbo,
				      cancel_code,
				      connection_method,
				      connection_data,
				      tee_paramTypes,
				      tee_exParamTypes,
				      m_params[0].in_buf.buf,
				      m_params[0].in_buf.len,
				      m_params[1].in_buf.buf,
				      m_params[1].in_buf.len,
				      m_params[2].in_buf.buf,
				      m_params[2].in_buf.len,
				      m_params[3].in_buf.buf,
				      m_params[3].in_buf.len,
				      m_params[0].out_buf.buf,
				      m_params[0].out_buf.len,
				      m_params[0].out_buf.len_out,
				      m_params[1].out_buf.buf,
				      m_params[1].out_buf.len,
				      m_params[1].out_buf.len_out,
				      m_params[2].out_buf.buf,
				      m_params[2].out_buf.len,
				      m_params[2].out_buf.len_out,
				      m_params[3].out_buf.buf,
				      m_params[3].out_buf.len,
				      m_params[3].out_buf.len_out,
				      m_params[0].mem_obj,
				      m_params[1].mem_obj,
				      m_params[2].mem_obj,
				      m_params[3].mem_obj,
				      &mem_sz_out[0],
				      &mem_sz_out[1],
				      &mem_sz_out[2],
				      &mem_sz_out[3],
				      session,
				      result,
				      eorigin);

	if (Object_isERROR(rv)) {
		MSGE("IGPAppClient_openSession failed: %d\n", rv);

		if (Object_ERROR_DEFUNCT == rv) {
			*result = TEEC_ERROR_TARGET_DEAD;
			*eorigin = TEEC_ORIGIN_TEE;
		} else if (Object_ERROR_BUSY == rv) {
			*result = TEEC_ERROR_BUSY;
			*eorigin = TEEC_ORIGIN_TEE;
		} else if (Object_ERROR_KMEM == rv ||
			   Object_ERROR_NOSLOTS == rv) {
			*result = TEEC_ERROR_OUT_OF_MEMORY;
			*eorigin = TEEC_ORIGIN_TEE;
		} else {
			*result = TEEC_ERROR_GENERIC;
			*eorigin = TEEC_ORIGIN_COMMS;
		}
	}

	for (size_t i = 0; i < MAX_NUM_PARAMS; i++)
		if (mem_sz_out[i] != 0)
			*m_params[i].out_buf.len_out = mem_sz_out[i];
	return rv;
}

/**
 * @brief Invoke a command within a session to a Trusted Application over
 * MINK-IPC.
 *
 * @param session The MINK object returned by QTEE to represent this session.
 * @param command_id Identifier for the command to invoke.
 * @param cancel_code A cancellation code to identify the cancellation request
 *                    on behalf of QTEE.
 * @param tee_paramTypes The type of the parameters in this request.
 * @param tee_exParamTypes The type of the extended parameters in this request
 *                         for use by QTEE.
 * @param m_params The MINK parameters passed to the MINK API in this request.
 * @param result The result returned from TEE.
 * @param eorigin The origin of the result from TEE.
 * @return Object_OK on success.
 *         Object_ERROR_* on failure.
 */
static int32_t mink_invoke_command(Object session, uint32_t command_id,
				   uint32_t cancel_code,
				   uint32_t tee_paramTypes,
				   uint32_t tee_exParamTypes,
				   MINK_Parameter *m_params,
				   TEEC_Result *result, uint32_t *eorigin)
{
	int32_t rv = Object_OK;
	uint32_t mem_sz_out[MAX_NUM_PARAMS] = { 0 };

	rv = IGPSession_invokeCommand(session,
				      command_id,
				      cancel_code,
				      MINK_TEEC_TIMEOUT_INFINITE,
				      tee_paramTypes,
				      tee_exParamTypes,
				      m_params[0].in_buf.buf,
				      m_params[0].in_buf.len,
				      m_params[1].in_buf.buf,
				      m_params[1].in_buf.len,
				      m_params[2].in_buf.buf,
				      m_params[2].in_buf.len,
				      m_params[3].in_buf.buf,
				      m_params[3].in_buf.len,
				      m_params[0].out_buf.buf,
				      m_params[0].out_buf.len,
				      m_params[0].out_buf.len_out,
				      m_params[1].out_buf.buf,
				      m_params[1].out_buf.len,
				      m_params[1].out_buf.len_out,
				      m_params[2].out_buf.buf,
				      m_params[2].out_buf.len,
				      m_params[2].out_buf.len_out,
				      m_params[3].out_buf.buf,
				      m_params[3].out_buf.len,
				      m_params[3].out_buf.len_out,
				      m_params[0].mem_obj,
				      m_params[1].mem_obj,
				      m_params[2].mem_obj,
				      m_params[3].mem_obj,
				      &mem_sz_out[0],
				      &mem_sz_out[1],
				      &mem_sz_out[2],
				      &mem_sz_out[3],
				      result,
				      eorigin);

	if (Object_isERROR(rv)) {
		MSGE("IGPSession_invokeCommand failed: %d\n", rv);

		if (Object_ERROR_DEFUNCT == rv) {
			*result = TEEC_ERROR_TARGET_DEAD;
			*eorigin = TEEC_ORIGIN_TEE;
		} else if (Object_ERROR_BUSY == rv) {
			*result = TEEC_ERROR_BUSY;
			*eorigin = TEEC_ORIGIN_TEE;
		} else if (Object_ERROR_KMEM == rv ||
			   Object_ERROR_NOSLOTS == rv) {
			*result = TEEC_ERROR_OUT_OF_MEMORY;
			*eorigin = TEEC_ORIGIN_TEE;
		} else {
			MSGE("Error communicating with TA: %d\n", rv);
			*result = TEEC_ERROR_GENERIC;
			*eorigin = TEEC_ORIGIN_COMMS;
		}

		if (eorigin) {
			*eorigin = TEEC_ORIGIN_TEE;
		}
	}

	for (size_t i = 0; i < MAX_NUM_PARAMS; i++)
		if (mem_sz_out[i] != 0)
			*m_params[i].out_buf.len_out = mem_sz_out[i];

	return rv;
}

/**
 * @brief Get the TEE_* type corresponding to a TEEC_* MemRef parameter type.
 *
 * @param teec_type The TEEC_* type defined by the Global Platform TEE Client
 *                  API specification.
 * @param op The operation payload for the request being sent.
 * @param i Index of the parameter for which conversion is required.
 * @return TEE_* type for a Memory Reference parameter.
 *         TEEC_* type for any other parameter.
 */
static uint32_t get_tee_type(uint32_t teec_type, TEEC_Operation *op, size_t i)
{
	uint32_t flags = 0;

	switch (teec_type) {
	case TEEC_MEMREF_PARTIAL_INPUT:
		return TEE_PARAM_TYPE_MEMREF_INPUT;
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		return TEE_PARAM_TYPE_MEMREF_OUTPUT;
	case TEEC_MEMREF_PARTIAL_INOUT:
		return TEE_PARAM_TYPE_MEMREF_INOUT;
	case TEEC_MEMREF_WHOLE:

		flags = op->params[i].memref.parent->flags;

		if ((flags & TEEC_MEM_INPUT) && (flags & TEEC_MEM_OUTPUT))
			return TEE_PARAM_TYPE_MEMREF_INOUT;

		if (flags & TEEC_MEM_INPUT)
			return TEE_PARAM_TYPE_MEMREF_INPUT;

		if (flags & TEEC_MEM_OUTPUT)
			return TEE_PARAM_TYPE_MEMREF_OUTPUT;

		break;
	default:
		break;
	}

	return teec_type;
}

/**
 * @brief Convert TEEC_* types to TEE_* types for Memory Reference parameters.
 *
 * @param op The operation payload for the request being sent.
 * @param tee_pType The parameter type encoding for the operation payload.
 */
static void tee_types_from_teec_types(TEEC_Operation *op, uint32_t *tee_pType)
{
	uint32_t teec_type = TEEC_NONE;
	uint32_t tee_type = TEEC_NONE;
	*tee_pType = op->paramTypes;

	for (size_t i = 0; i < MAX_NUM_PARAMS; i++) {
		teec_type = TEEC_PARAM_TYPE_GET(op->paramTypes, i);
		tee_type = get_tee_type(teec_type, op, i);

		/* In-place modification of mask */
		*tee_pType = TEEC_PARAM_TYPE_SET(tee_type, i, *tee_pType);
	}
}

/**
 * @brief Initialize the MINK parameters.
 *
 * @param m_params The MINK parameters to be passed to a MINK API.
 */
static void mink_params_INIT(MINK_Parameter *m_params)
{
	for (size_t i = 0; i < MAX_NUM_PARAMS; i++) {
		m_params[i].in_buf.buf = NULL;
		m_params[i].in_buf.len = 0;
		m_params[i].in_buf.sh_obj_index = 0;

		m_params[i].out_buf.buf = NULL;
		m_params[i].out_buf.len = 0;
		m_params[i].out_buf.len_out = &m_params[i].out_buf.len;

		m_params[i].mem_obj = Object_NULL;
		m_params[i].mem_obj_params.offset = 0;
		m_params[i].mem_obj_params.size = 0;
		m_params[i].mem_obj_params.sharedObjIndex = 0;
	}
}

/**
 * @brief Check whether two memory objects represent the same memory.
 *
 * @param mo1 The first memory object.
 * @param mo2 The second memory object.
 * @return TRUE If the memory objects are equivalent.
 * @return FALSE If the memory objects are not equivalent.
 */
static bool is_mem_obj_equal(Object mo1, Object mo2)
{
	int32_t rv = Object_OK;

	void *mo1_addr, *mo2_addr;
	size_t mo1_size, mo2_size;

	rv = MinkCom_getMemoryObjectInfo(mo1, &mo1_addr, &mo1_size);
	if (Object_isERROR(rv))
		return false;

	rv = MinkCom_getMemoryObjectInfo(mo2, &mo2_addr, &mo2_size);
	if (Object_isERROR(rv))
		return false;

	/* The memory represented by a memory object is mmap'd only once, hence
	 * the same memory object can never be backed by two different address
	 */
	if (((uintptr_t)mo1_addr == (uintptr_t)mo2_addr) &&
	    (mo1_size == mo2_size))
		return true;

	return false;
}

/**
 * @brief Copy the contents of Shared Memory to a Memory object represented
 *        memory.
 *
 * @param shm The Shared Memory to copy from.
 * @param mo The Memory Object to copy to.
 * @return Object_OK on success.
 *         Object_ERROR_* on failure.
 */
static int32_t copy_to_mem_object(TEEC_SharedMemory *shm, Object mo)
{
	int32_t rv = Object_OK;
	void *mo_addr;
	size_t mo_size;

	rv = MinkCom_getMemoryObjectInfo(mo, &mo_addr, &mo_size);
	if (Object_isERROR(rv))
		return rv;

	memscpy(mo_addr, mo_size, shm->buffer, shm->size);
	return rv;
}

/**
 * @brief Copy the contents of a Memory object represented memory to a Shared
 *        Memory.
 *
 * @param mo The Memory Object to copy from.
 * @param shm The Shared Memory to copy to.
 * @return Object_OK on success.
 *         Object_ERROR_* on failure.
 */
static int32_t copy_from_mem_object(Object mo, TEEC_SharedMemory *shm)
{
	int32_t rv = Object_OK;
	void *mo_addr;
	size_t mo_size;

	rv = MinkCom_getMemoryObjectInfo(mo, &mo_addr, &mo_size);
	if (Object_isERROR(rv))
		return rv;

	memscpy(shm->buffer, shm->size, mo_addr, mo_size);
	return rv;
}

/**
 * @brief Convert a MEMREF_PARTIAL_* parameter to a MEMREF_TEMP_* parameter.
 *
 * @param i Index of the parameter for which conversion is required.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 */
static void memref_temp_from_partial(size_t i, uint32_t *param_types,
				     TEEC_Parameter *params)
{
	uint32_t type = TEEC_PARAM_TYPE_GET(*param_types, i);
	TEEC_RegisteredMemoryReference memref = params[i].memref;

	memset((void *)(&params[i]), 0, sizeof(TEEC_Parameter));
	params[i].tmpref.buffer = memref.parent->buffer;
	params[i].tmpref.size = memref.parent->size;

	free((void *)memref.parent);
	/* Convert MEMREF_PARTIAL_* to MEMREF_TEMP_* type */
	*param_types = TEEC_PARAM_TYPE_SET(type ^ 0x00000008, i, *param_types);
}

/**
 * @brief Convert MEMREF_PARTIAL_* parameters to MEMREF_TEMP_* parameters.
 *
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 */
static void memref_temp_from_partial_params(uint32_t *param_types,
					    TEEC_Parameter *params)
{
	uint32_t type = TEEC_NONE;
	uint8_t converted = 0;

	for (size_t i = 0; i < MAX_NUM_PARAMS; i++) {

		type = TEEC_PARAM_TYPE_GET(*param_types, i);
		switch(type) {
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:

			converted = params[i].memref.parent->imp.converted;
			if (converted)
				memref_temp_from_partial(i, param_types,
							 params);
			break;
		default:
			break;
		}
	}
}

/**
 * @brief Convert a MEMREF_TEMP_* parameter to a MEMREF_PARTIAL_* parameter.
 *
 * @param ctx The initialized TEE context.
 * @param i Index of the parameter for which conversion is required.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 * @return TEEC_SUCCESS on success.
 *         TEEC_ERROR_* on failure.
 */
static TEEC_Result memref_temp_to_partial(TEEC_Context *ctx, size_t i,
					  uint32_t *param_types,
					  TEEC_Parameter *params)
{
	uint32_t type = TEEC_PARAM_TYPE_GET(*param_types, i);
	TEEC_TempMemoryReference tmpref = params[i].tmpref;
	size_t shm_size = sizeof(TEEC_SharedMemory);

	TEEC_SharedMemory *shm = (TEEC_SharedMemory *)malloc(shm_size);
	if (!shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

	memset((void *)&params[i], 0, sizeof(TEEC_Parameter));
	params[i].memref.parent = shm;
	params[i].memref.parent->buffer = tmpref.buffer;
	params[i].memref.parent->size = tmpref.size;
	params[i].memref.parent->flags = 0;
	params[i].memref.offset = 0;
	params[i].memref.size = tmpref.size;

	if (type == TEEC_MEMREF_TEMP_INPUT ||
	    type == TEEC_MEMREF_TEMP_INOUT)
		params[i].memref.parent->flags |= TEEC_MEM_INPUT;

	if (type == TEEC_MEMREF_TEMP_OUTPUT ||
	    type == TEEC_MEMREF_TEMP_INOUT)
		params[i].memref.parent->flags |= TEEC_MEM_OUTPUT;

	/* Convert MEMREF_TEMP_* to MEMREF_PARTIAL_* type */
	*param_types = TEEC_PARAM_TYPE_SET(type | 0x00000008, i, *param_types);

	return register_shared_memory(ctx, params[i].memref.parent, TRUE);
}

/**
 * @brief Convert MEMREF_TEMP_* parameters to MEMREF_PARTIAL_* parameters.
 *
 * @param ctx The initialized TEE context.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 * @return TEEC_SUCCESS on success.
 *         TEEC_ERROR_* on failure.
 */
static TEEC_Result memref_temp_to_partial_params(TEEC_Context *ctx,
						 uint32_t *param_types,
						 TEEC_Parameter *params)
{
	TEEC_Result result = TEEC_SUCCESS;
	uint32_t type = TEEC_NONE;
	size_t size = 0;

	for (size_t i = 0; i < MAX_NUM_PARAMS; i++) {

		type = TEEC_PARAM_TYPE_GET(*param_types, i);
		switch(type) {
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:

			size = params[i].tmpref.size;
			if (size > TEEC_SHM_MAX_HEAP_SZ) {
				result = memref_temp_to_partial(ctx, i,
								param_types,
								params);
				if (result)
					goto out_failed;
			}

			break;
		default:
			break;
		}
	}

	return result;

out_failed:
	/* Undo the conversion of TEMP params done until this point */
	memref_temp_from_partial_params(param_types, params);

	return result;
}

/**
 * @brief Update the contents of Shared Memory with it's associated Memory
 *        object.
 *
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 */
static void update_shm_memref_from_mem_obj(uint32_t param_types,
					   TEEC_Parameter *params)
{
	uint32_t type = TEEC_NONE;
	TEEC_SharedMemory *shm;
	Object mem_obj;

	for (size_t i = 0; i < MAX_NUM_PARAMS; i++) {

		type = TEEC_PARAM_TYPE_GET(param_types, i);
		switch(type) {
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
		case TEEC_MEMREF_WHOLE:

			shm = params[i].memref.parent;
			mem_obj = shm->imp.mem_obj;
			if (!Object_isNull(mem_obj) &&
			    shm->imp.type == TEEC_MEMORY_REGISTERED)
				copy_from_mem_object(mem_obj, shm);
			break;
		default:
			break;
		}
	}
}

/**
 * @brief Convert a TEEC_VALUE_* parameter to a MINK parameter.
 *
 * @param i Index of the parameter for which conversion is required.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of TEEC parameters.
 * @param m_params The list of MINK Parameters to be assigned.
 */
static void process_value_param(size_t i, uint32_t param_types,
				TEEC_Parameter *params,
				MINK_Parameter *m_params)
{
	MINK_InBuffer *inbuf = &m_params[i].in_buf;
	MINK_OutBuffer *outbuf = &m_params[i].out_buf;

	uint32_t type = TEEC_PARAM_TYPE_GET(param_types, i);

	if (type == TEEC_VALUE_INPUT ||
	    type == TEEC_VALUE_INOUT) {
		inbuf->buf = &params[i].value;
		inbuf->len =  sizeof(TEEC_Value);
		inbuf->sh_obj_index = 0xFF; // N/A
	}

	if (type == TEEC_VALUE_OUTPUT ||
	    type == TEEC_VALUE_INOUT) {
		outbuf->buf = &params[i].value;
		outbuf->len =  sizeof(TEEC_Value);
	}
}

/**
 * @brief Convert a TEEC_MEMREF_TEMP_* parameter to a MINK parameter.
 *
 * @param i Index of the parameter for which conversion is required.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of TEEC parameters.
 * @param m_params The list of MINK Parameters to be assigned.
 * @param etype The parameter type encoding for extended parameters
 *              in this request for use by QTEE.
 */
static void process_memref_temp(size_t i, uint32_t param_types,
				TEEC_Parameter *params,
				MINK_Parameter *m_params,
				uint32_t *etype)
{
	uint32_t type = TEEC_PARAM_TYPE_GET(param_types, i);
	MINK_InBuffer *inbuf = &m_params[i].in_buf;
	MINK_OutBuffer *outbuf = &m_params[i].out_buf;

	/* Implicitly handles NULL tmpref */
	inbuf->buf = params[i].tmpref.buffer;
	inbuf->len = params[i].tmpref.size;
	inbuf->sh_obj_index = 0;

	if (type == TEEC_MEMREF_TEMP_OUTPUT ||
	    type == TEEC_MEMREF_TEMP_INOUT) {
		outbuf->buf = params[i].tmpref.buffer;
		outbuf->len = params[i].tmpref.size;
	}
	outbuf->len_out = &params[i].tmpref.size;

	if (params[i].tmpref.buffer == NULL)
		*etype = TEEC_PARAM_TYPE_SET(TEE_EX_PARAM_TYPE_MEMREF_NULL, i,
					     *etype);
}

/**
 * @brief Get the index of the first TEEC_MEMREF_* parameter which shares a
 * Memory object with the current TEEC_MEMREF_* parameter.
 *
 * @param memref_index Index of the current TEEC_MEMREF_* parameter.
 * @param memref_mem_obj The Memory object for the current parameter.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 * @return i Index of the first shared TEEC_MEMREF_* parameter.
 *         DEFINING_INDEX_NA otherwise.
 */
static size_t get_shared_mem_obj_index(size_t memref_index, Object memref_mem_obj,
				       uint32_t param_types,
				       TEEC_Parameter *params)
{
	uint32_t type = TEEC_NONE;
	TEEC_SharedMemory *shm;
	Object mem_obj;
	for (size_t i = 0; i < memref_index; i++) {

		type = TEEC_PARAM_TYPE_GET(param_types, i);
		switch(type) {
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
		case TEEC_MEMREF_WHOLE:

			shm = params[i].memref.parent;
			mem_obj = shm->imp.mem_obj;
			if (!Object_isNull(mem_obj) &&
			    is_mem_obj_equal(mem_obj, memref_mem_obj))

				return i;
			break;
		default:
			break;
		}
	}

	return DEFINING_INDEX_NA;
}

/**
 * @brief Assign extended parameters for the TEEC_MEMREF_* parameters sharing
 *        Memory objects.
 *
 * @param index Index of the current TEEC_MEMREF_* parameter.
 * @param shm_index Index of the first TEEC_MEMREF_* parameter which shares a
 *                  Memory object with the current TEEC_MEMREF_* parameter.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param tee_exParamTypes The parameter type encoding for extended parameters
 *                         in this request for use by QTEE.
 */
static void assign_extended_params(size_t index, int shm_index,
				   uint32_t param_type,
				   uint32_t *tee_exParamTypes)
{
	uint32_t etype = 0;
	/* The parameter at 'index' shares a memory object with some other
	 * parameter.
	 */
	etype = TEEC_PARAM_TYPE_SET(TEE_EX_PARAM_TYPE_MEMREF_DUP, index,
				    *tee_exParamTypes);

	/* Inform QTEE that the parameter at 'shm_index' is the one hosting
	 * the memory object shared by the parameter at 'index'.
	 */
	if (param_type == TEEC_MEMREF_PARTIAL_OUTPUT ||
	    param_type == TEEC_MEMREF_PARTIAL_INOUT)
		etype = TEEC_PARAM_TYPE_SET(TEE_EX_PARAM_TYPE_MEMREF_FORCE_RW,
					    shm_index, etype);

	*tee_exParamTypes = etype;
}

/**
 * @brief Convert a TEEC_MEMREF_WHOLE parameter to a MINK parameter.
 *
 * @param i Index of the parameter for which conversion is required.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 * @param m_params The list of MINK Parameters to be assigned.
 * @param tee_exParamTypes The parameter type encoding for extended parameters
 *                         in this request for use by QTEE.
 */
static void process_memref_whole(size_t i, uint32_t param_types,
				 TEEC_Parameter *params,
				 MINK_Parameter *m_params,
				 uint32_t *tee_exParamTypes)
{
	uint32_t type = TEEC_PARAM_TYPE_GET(param_types, i);
	TEEC_SharedMemory *shm = params[i].memref.parent;
	Object memref_mem_obj = shm->imp.mem_obj;
	size_t shm_obj_index = 0;

	/* Pointers to Mink parameters to be assigned */
	MINK_InBuffer *inbuf = &m_params[i].in_buf;
	MINK_OutBuffer *outbuf = &m_params[i].out_buf;
	Object *mem_obj = &m_params[i].mem_obj;
	MemoryObjectParams *mem_obj_params = &m_params[i].mem_obj_params;

	/* This whole memory reference is backed by a memory object */
	if (!Object_isNull(memref_mem_obj)) {

		/* We need to set the memory object and it's parameters */
		*mem_obj = memref_mem_obj;
		mem_obj_params->offset = 0;
		mem_obj_params->size = params[i].memref.parent->size;

		/* In case of TEEC_MEMORY_ALLOCATED, shm->buffer already
		 * points to memory object backed memory, thus no need for copy.
		 */
		if (shm->imp.type == TEEC_MEMORY_REGISTERED)
			copy_to_mem_object(shm, memref_mem_obj);

		inbuf->buf = mem_obj_params;
		inbuf->len = sizeof(*mem_obj_params);

		/* Does this memory reference share it's memory object with
		 * another memory reference? */
		shm_obj_index = get_shared_mem_obj_index(i, memref_mem_obj,
							 param_types,
							 params);

		if (shm_obj_index != DEFINING_INDEX_NA)
			assign_extended_params(i, shm_obj_index, type,
					       tee_exParamTypes);

		inbuf->sh_obj_index = shm_obj_index;

		if (params[i].memref.parent->flags & TEEC_MEM_OUTPUT)
			outbuf->len_out = &params[i].memref.size;
	} else {
		inbuf->buf = params[i].memref.parent->buffer;
		inbuf->len = params[i].memref.parent->size;
		inbuf->sh_obj_index = 0;

		if (params[i].memref.parent->flags & TEEC_MEM_OUTPUT) {
			outbuf->buf = params[i].memref.parent->buffer;
			outbuf->len = params[i].memref.parent->size;
			/* As per the GP spec, even if type is MEMREF_WHOLE,
			 * we must update the size here
			 */
			outbuf->len_out = &params[i].memref.size;
		}
	}
}

/**
 * @brief Convert a TEEC_MEMREF_PARTIAL_* parameter to a MINK parameter.
 *
 * @param i Index of the parameter for which conversion is required.
 * @param param_types The parameter type encoding for the list of parameters.
 * @param params The list of parameters.
 * @param m_params The list of MINK Parameters to be assigned.
 * @param tee_exParamTypes The parameter type encoding for extended parameters
 *                         in this request for use by QTEE.
 */
static void process_memref_partial(size_t i, uint32_t param_types,
				   TEEC_Parameter *params,
				   MINK_Parameter *m_params,
				   uint32_t *tee_exParamTypes)
{
	uint32_t type = TEEC_PARAM_TYPE_GET(param_types, i);
	TEEC_SharedMemory *shm = params[i].memref.parent;
	Object memref_mem_obj = shm->imp.mem_obj;
	size_t shm_obj_index = 0;

	/* Pointers to Mink parameters to be assigned */
	MINK_InBuffer *inbuf = &m_params[i].in_buf;
	MINK_OutBuffer *outbuf = &m_params[i].out_buf;
	Object *mem_obj = &m_params[i].mem_obj;
	MemoryObjectParams *mem_obj_params = &m_params[i].mem_obj_params;

	/* This partial memory reference is backed by a memory object */
	if (!Object_isNull(memref_mem_obj)) {

		/* We need to set the memory object and it's parameters */
		*mem_obj = memref_mem_obj;
		mem_obj_params->offset = params[i].memref.offset;
		mem_obj_params->size = params[i].memref.size;

		/* In case of TEEC_MEMORY_ALLOCATED, shm->buffer already
		 * points to memory object backed memory, thus no need for copy.
		 */
		if (shm->imp.type == TEEC_MEMORY_REGISTERED)
			copy_to_mem_object(shm, memref_mem_obj);

		inbuf->buf = mem_obj_params;
		inbuf->len = sizeof(*mem_obj_params);

		/* Does this memory reference share it's memory object with
		 * another memory reference? */
		shm_obj_index = get_shared_mem_obj_index(i, memref_mem_obj,
							 param_types,
							 params);

		if (shm_obj_index != DEFINING_INDEX_NA)
			assign_extended_params(i, shm_obj_index, type,
					       tee_exParamTypes);

		inbuf->sh_obj_index = shm_obj_index;

		if (type == TEEC_MEMREF_PARTIAL_OUTPUT ||
		    type == TEEC_MEMREF_PARTIAL_INOUT)
			outbuf->len_out = &params[i].memref.size;
	} else {
		inbuf->buf = params[i].memref.parent->buffer
			     + params[i].memref.offset;
		inbuf->len = params[i].memref.size;
		inbuf->sh_obj_index = 0;

		if (type == TEEC_MEMREF_PARTIAL_OUTPUT ||
		    type == TEEC_MEMREF_PARTIAL_INOUT) {
			outbuf->buf = params[i].memref.parent->buffer
				      + params[i].memref.offset;
			outbuf->len = params[i].memref.size;
			outbuf->len_out = &params[i].memref.size;
		}
	}
}

/**
 * @brief Convert TEEC_* parameters to MINK parameters.
 *
 * @param param_types The parameter type encoding for the operation payload.
 * @param params The list of TEEC_* parameters in operation payload.
 * @param m_params The MINK parameters to be passed to a MINK API.
 * @param tee_exParamTypes The extended parameters type encoding in this
 *                         request for use by QTEE.
 */
static void mink_params_from_teec_params(uint32_t param_types,
					 TEEC_Parameter *params,
					 MINK_Parameter *m_params,
					 uint32_t *tee_exParamTypes)
{
	uint32_t type = TEEC_NONE;

	for (size_t i = 0; i < MAX_NUM_PARAMS; i++) {

		type = TEEC_PARAM_TYPE_GET(param_types, i);
		switch(type) {
		case TEEC_VALUE_INPUT:
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:

			process_value_param(i, param_types, params, m_params);
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:

			process_memref_temp(i, param_types, params, m_params,
					    tee_exParamTypes);
			break;
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:

			process_memref_partial(i, param_types, params, m_params,
					       tee_exParamTypes);

			break;
		case TEEC_MEMREF_WHOLE:

			process_memref_whole(i, param_types, params, m_params,
					     tee_exParamTypes);
			break;
		default:
			break;
		}
	}
}

TEEC_Result initialize_context(TEEC_Context *ctx)
{
	TEEC_Result ret = TEEC_SUCCESS;
	int32_t rv = Object_OK;

	Object root_obj = Object_NULL;
	Object app_client = Object_NULL;
	Object waiter_cbo = Object_NULL;

	rv = MinkCom_getRootEnvObject(&root_obj);
	if (Object_isERROR(rv)) {
		MSGE("MinkCom_getRootEnvObject failed: 0x%x\n", rv);
		return TEEC_ERROR_GENERIC;
	}

	/* Get the GP App client object */
	rv = mink_get_app_client(root_obj, &app_client);
	if (Object_isERROR(rv)) {
		MSGE("mink_get_app_client failed: %d\n", rv);
		ret = TEEC_ERROR_GENERIC;
		goto err_gp_app_client;
	}

	/* Get the Cancellation CBO */
	rv = CWait_open(&waiter_cbo);
	if (Object_isERROR(rv)) {
		MSGE("CWait_open failed: 0x%x\n", rv);
		ret = TEEC_ERROR_GENERIC;
		goto err_waiter_cbo;
	}

	/* Store these Mink Objects for the current
	 * context
	 */
	ctx->imp.root_obj = root_obj;
	ctx->imp.app_client = app_client;
	ctx->imp.waiter_cbo = waiter_cbo;

	return ret;

err_waiter_cbo:
	Object_ASSIGN_NULL(app_client);

err_gp_app_client:
	Object_ASSIGN_NULL(root_obj);

	return ret;
}

void finalize_context(TEEC_Context *ctx)
{
	Object_ASSIGN_NULL(ctx->imp.root_obj);
	Object_ASSIGN_NULL(ctx->imp.waiter_cbo);
	Object_ASSIGN_NULL(ctx->imp.app_client);
}

TEEC_Result open_session(TEEC_Context *ctx, TEEC_Session *session,
			 const TEEC_UUID *destination, uint32_t conn_method,
			 const void *connection_data, TEEC_Operation *op,
			 uint32_t *ret_origin)
{
	int32_t ret = Object_OK;

	TEEC_Result result = TEEC_SUCCESS;
	uint32_t eorigin = TEEC_ORIGIN_COMMS;
	uint32_t conn_data = 0;
	if (connection_data)
		conn_data = *(const uint32_t *)connection_data;

	uint32_t cancel_code = 0;

	if (ret_origin) {
		*ret_origin = TEEC_ORIGIN_COMMS;
	}

	uint32_t tee_paramTypes = 0;
	uint32_t tee_exParamTypes = 0;
	MINK_Parameter m_params[MAX_NUM_PARAMS];
	mink_params_INIT(m_params);

	if (op) {
		cancel_code = (rand() & CANCEL_CODE_MASK);
		op->imp.cancel_code = cancel_code;
		op->imp.session = session;

		result = memref_temp_to_partial_params(ctx, &(op->paramTypes),
						       op->params);
		if (result)
			return result;

		mink_params_from_teec_params(op->paramTypes, op->params,
					     m_params, &tee_exParamTypes);

		tee_types_from_teec_types(op, &tee_paramTypes);
	}

	ret = mink_open_session(ctx->imp.app_client, ctx->imp.waiter_cbo,
				destination, cancel_code, conn_method,
				conn_data, tee_paramTypes, tee_exParamTypes,
				m_params, &(session->imp.session_obj), &result,
				&eorigin);

	if (ret)
		MSGE("mink_open_session() failed: %d\n", ret);

	if (result) {
		/* If we have an error originating from trusted app, then
		 * returned session object is not NULL and needs to be assigned
		 * NULL. But if we have an error originating from TEE or
		 * transport, then no session object is created.
		 */
		if (eorigin == TEEC_ORIGIN_TRUSTED_APP)
			Object_ASSIGN_NULL(session->imp.session_obj);
	} else {
		session->imp.ctx = ctx;
	}

	if (ret_origin)
		*ret_origin = eorigin;

	if (op) {
		update_shm_memref_from_mem_obj(op->paramTypes, op->params);

		memref_temp_from_partial_params(&(op->paramTypes), op->params);
	}

	return result;
}

void close_session(TEEC_Session *session)
{
	Object_ASSIGN_NULL(session->imp.session_obj);
	session->imp.ctx = NULL;
}

TEEC_Result invoke_command(TEEC_Session *session, uint32_t command_id,
			   TEEC_Operation *op, uint32_t *ret_origin)
{
	TEEC_Result ret = TEEC_SUCCESS;

	TEEC_Result result = TEEC_SUCCESS;
	uint32_t eorigin = TEEC_ORIGIN_COMMS;
	uint32_t cancel_code = 0;

	TEEC_Context *ctx = session->imp.ctx;

	if (ret_origin) {
		*ret_origin = TEEC_ORIGIN_COMMS;
	}

	uint32_t tee_paramTypes = 0;
	uint32_t tee_exParamTypes = 0;
	MINK_Parameter m_params[MAX_NUM_PARAMS];
	mink_params_INIT(m_params);

	if (op) {
		cancel_code = (rand() & CANCEL_CODE_MASK);
		op->imp.cancel_code = cancel_code;
		op->imp.session = session;

		memref_temp_to_partial_params(ctx, &(op->paramTypes),
					      op->params);

		mink_params_from_teec_params(op->paramTypes, op->params,
					     m_params, &tee_exParamTypes);

		tee_types_from_teec_types(op, &tee_paramTypes);
	}

	ret = mink_invoke_command(session->imp.session_obj, command_id,
				  cancel_code, tee_paramTypes, tee_exParamTypes,
				  m_params, &result, &eorigin);

	if (ret)
		MSGE("mink_invoke_command() failed: %d\n", ret);

	if (ret_origin)
		*ret_origin = eorigin;

	if (op) {
		update_shm_memref_from_mem_obj(op->paramTypes, op->params);

		memref_temp_from_partial_params(&(op->paramTypes), op->params);
	}

	return result;
}

TEEC_Result register_shared_memory(TEEC_Context *ctx, TEEC_SharedMemory *shm,
				   uint8_t convert)
{
	int32_t rv = Object_OK;
	Object root_obj = ctx->imp.root_obj;
	Object mo = Object_NULL;

	/* Based on size, we might need to use a MINK Memory Object */
	if (shm->size > TEEC_SHM_MAX_HEAP_SZ) {

		rv = MinkCom_getMemoryObject(root_obj, shm->size, &mo);
		if (Object_isERROR(rv))
			return TEEC_ERROR_GENERIC;
	}

	/* This shared memory is a Registered Memory */
	shm->imp.type = TEEC_MEMORY_REGISTERED;

	/* Is this being converted from a TempMemoryReference? */
	shm->imp.converted = convert;

	shm->imp.mem_obj = mo;
	shm->imp.ctx = ctx;

	return TEEC_SUCCESS;
}

TEEC_Result allocate_shared_memory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	int32_t rv = Object_OK;
	Object root_obj = ctx->imp.root_obj;
	Object mo = Object_NULL;
	/* mo is page aligned, thus mo_size > shm->size when used */
	size_t mo_size;

	if (shm->size > TEEC_SHM_MAX_HEAP_SZ) {

		/* Larger memory sizes need to be backed by a
		 * MINK Memory Object
		 */
		rv = MinkCom_getMemoryObject(root_obj, shm->size, &mo);
		if (Object_isERROR(rv))
			return TEEC_ERROR_GENERIC;

		rv = MinkCom_getMemoryObjectInfo(mo, &shm->buffer, &mo_size);
		if (Object_isERROR(rv)) {
			Object_ASSIGN_NULL(mo);
			return TEEC_ERROR_GENERIC;
		}
	} else {
		shm->buffer = malloc(shm->size);
		if (!shm->buffer)
			return TEEC_ERROR_OUT_OF_MEMORY;
	}

	/* This shared memory is a Registered Memory */
	shm->imp.type = TEEC_MEMORY_ALLOCATED;
	shm->imp.mem_obj = mo;
	shm->imp.ctx = ctx;

	return TEEC_SUCCESS;
}

void release_shared_memory(TEEC_SharedMemory *shm)
{
	if (shm->imp.type == TEEC_MEMORY_ALLOCATED) {
		if(shm->size <= TEEC_SHM_MAX_HEAP_SZ)
			free(shm->buffer);

		shm->buffer = NULL;
		shm->size = 0;
	}

	/* If there's a backing memory object, release it */
	Object_ASSIGN_NULL(shm->imp.mem_obj);

	shm->imp.converted = 0;
	shm->imp.type = TEEC_MEMORY_FREE;
	shm->imp.ctx = NULL;
}

void request_cancellation(TEEC_Operation *op)
{
	TEEC_Session *session = (TEEC_Session *)op->imp.session;
	TEEC_Context *ctx = (TEEC_Context *)session->imp.ctx;

	Object waiter_cbo = ctx->imp.waiter_cbo;
	if (Object_isNull(waiter_cbo)) {
		MSGE("Waiter CBO not available!\n");
		return;
	}

	IWait_signal(waiter_cbo, op->imp.cancel_code, IWait_EVENT_CANCEL);
}
