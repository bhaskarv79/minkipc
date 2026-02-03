// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>

#include "listener_mngr.h"

#define MAX_LISTENERS 8
static struct listener_svc listeners[] = {
#ifdef TIME_LISTENER
	{
		.service_name = "Time service",
		.is_registered = false,
		.file_name = "libtimeservice.so.1",
		.lib_handle = NULL,
	},
#endif
#ifdef TA_AUTOLOAD_LISTENER
	{
		.service_name = "TA Autoload service",
		.is_registered = false,
		.file_name = "libtaautoload.so.1",
		.lib_handle = NULL,
	},
#endif
#ifdef FS_LISTENER
	{
		.service_name = "FS service",
		.is_registered = false,
		.file_name = "libfsservice.so.1",
		.lib_handle = NULL,
	},
#endif
#ifdef GPFS_LISTENER
	{
		.service_name = "GPFS service",
		.is_registered = false,
		.file_name = "libgpfsservice.so.1",
		.lib_handle = NULL,
	},
#endif
#ifdef RPMB_LISTENER
	{
		.service_name = "rpmb service",
		.is_registered = false,
		.file_name = "librpmbservice.so.1",
		.lib_handle = NULL,
	},
#endif
};

/**
 * @brief De-initialize a listener service.
 *
 * De-initialize a listener service by invoking the de-init callback defined by
 * the listener.
 */
static void deinit_listener_svc(size_t i)
{
	listener_deinit deinit_func;

	deinit_func = (listener_deinit)dlsym(listeners[i].lib_handle,
					     "deinit");
	if (deinit_func == NULL) {
		MSGE("dlsym(deinit) not found in lib %s: %s\n",
		listeners[i].file_name, dlerror());
		return;
	}

	(*deinit_func)();
}

/**
 * @brief Stop listener services.
 *
 * Stops all listener services waiting for a listener request from QTEE.
 */
static void stop_listeners_services(void)
{
	size_t idx = 0;
	size_t n_listeners = sizeof(listeners)/sizeof(struct listener_svc);

	MSGD("Total listener services to be stopped = %ld\n", n_listeners);

	for (idx = 0; idx < n_listeners; idx++) {
		/* Resource cleanup for registered listeners */
		if(listeners[idx].is_registered) {
			deinit_listener_svc(idx);

			listeners[idx].is_registered = false;
		}

		/* Close lib_handle for all listeners */
		if(listeners[idx].lib_handle != NULL) {
			dlclose(listeners[idx].lib_handle);
			listeners[idx].lib_handle = NULL;
		}
	}
}

/**
 * @brief Initialize a listener service.
 *
 * Initialize a listener service by invoking the init callback defined by
 * the listener.
 */
static int init_listener_svc(size_t i)
{
	listener_init init_func;
	int ret = 0;

	listeners[i].lib_handle = dlopen(listeners[i].file_name,
					 RTLD_NOW);
	if (listeners[i].lib_handle == NULL) {
		MSGE("dlopen(%s, RLTD_NOW) failed: %s\n",
		     listeners[i].file_name, dlerror());
		return -1;
	}

	init_func = (listener_init)dlsym(listeners[i].lib_handle,
					 "init");
	if (init_func == NULL) {
		MSGE("dlsym(init) not found in lib %s: %s\n",
		     listeners[i].file_name, dlerror());
		return -1;
	}

	ret = (*init_func)();
	if (ret < 0) {
		MSGE("Init for %s failed: %d", listeners[i].service_name, ret);
		return -1;
	}

	listeners[i].is_registered = true;

	return ret;
}

int start_listener_services(void)
{
	int ret = 0;
	size_t idx = 0;
	size_t n_listeners = sizeof(listeners)/sizeof(struct listener_svc);

	MSGD("Total listener services to start = %ld\n", n_listeners);

	for (idx = 0; idx < n_listeners; idx++) {

		ret = init_listener_svc(idx);
		if (ret) {
			MSGE("init_listener_svc failed: 0x%x\n", ret);
			goto fail;
		}
	}

	return ret;

fail:
	stop_listeners_services();
	return ret;

}
