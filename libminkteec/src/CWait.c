// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "mink_teec.h"

#include "CWait_open.h"
#include "IWait.h"
#include "IWait_invoke.h"

#include "qlist.h"

#define TYPE_WAITER_ITEM 0
#define TYPE_SIGNAL_ITEM 1

#define MSEC_PER_SEC (1000L)

typedef struct {
	uint32_t events;
	uint32_t code;
	bool signaled;
	/* Protect the CV */
	pthread_mutex_t mutex;
	pthread_cond_t condition;
} waiter_item;

typedef struct {
	uint32_t events;
	uint32_t code;
} signal_item;

typedef struct {
	QNode qn;

	uint8_t type;
	union {
		waiter_item w_item;
		signal_item s_item;
	} item;
} list_item;

typedef struct {
	atomic_int refs;

	QList list;
	/* Protect the QList */
	pthread_mutex_t lock;
} CWait;

static int32_t CWait_retain(CWait *me)
{
	atomic_fetch_add(&me->refs, 1);
	return Object_OK;
}

static void QList_free(QList *list)
{
	QNode *node = QList_pop(list);
	while (node) {
		free(node);
		node = QList_pop(list);
	}
}

static int32_t CWait_release(CWait *me)
{
	if (atomic_fetch_sub(&me->refs, 1) == 1) {
		QList_free(&me->list);
		pthread_mutex_destroy(&me->lock);
		free(me);
	}

	return Object_OK;
}

/**
 * @brief Signal the waiter with the specified event(s).
 *
 * @param list A pointer to the list of waiter/signal items.
 * @param code The unique identifier code for the event to signal.
 * @param events The type of event to signal.
 * @return bool TRUE if the waiter was signalled.
 *              FALSE if the waiter wasn't signalled.
 */
static bool signal_waiter_item(QList *list, uint32_t code, uint32_t events)
{
	QNode *node = NULL;
	list_item *l_item = NULL;
	waiter_item *w_item = NULL;
	bool signaled = false;

	QLIST_FOR_ALL(list, node)
	{
		l_item = container_of(node, list_item, qn);
		if (l_item->type != TYPE_WAITER_ITEM)
			continue;

		w_item = &l_item->item.w_item;
		if ((w_item->events & events) &&
		    ((w_item->code == 0 || w_item->code == code))) {
			pthread_mutex_lock(&w_item->mutex);

			w_item->signaled = true;
			w_item->events &= events;

			/* Match, wake up the waiter! */
			pthread_cond_signal(&w_item->condition);
			signaled = true;

			pthread_mutex_unlock(&w_item->mutex);

			/* Multiple (event, code) pairs not possible */
			break;
		}
	}

	return signaled;
}

/**
 * @brief Find a signal item in the waiter/signal list.
 *
 * @param list A pointer to the list of waiter/signal items.
 * @param code The unique identifier code for the event to signal.
 * @param events The type of event to signal.
 * @param events_out The type of event returned to QTEE.
 * @return bool TRUE if the signal item was found.
 *              FALSE if the signal item was not found.
 */
static bool get_signal_item(QList *list, uint32_t code, uint32_t events,
			    uint32_t *events_out)
{
	QNode *node = NULL;
	list_item *l_item = NULL;
	signal_item *s_item = NULL;
	bool found = false;

	QLIST_FOR_ALL(list, node)
	{
		l_item = container_of(node, list_item, qn);
		if (l_item->type != TYPE_SIGNAL_ITEM)
			continue;

		s_item = &l_item->item.s_item;
		if ((s_item->events & events) &&
		    ((s_item->code == code || s_item->code == 0))) {
			*events_out = (s_item->events & events);

			found = true;
			break;
		}
	}

	if (found) {
		QNode_dequeue(node);
		free(l_item);
	}

	return found;
}

/**
 * @brief Adds a signal item to the waiter/signal list.
 *
 * @param list A pointer to the list of waiter/signal items.
 * @param code The unique identifier code for the event to signal.
 * @param events The type of event to signal.
 * @return list_item The newly queued signal item.
 *         NULL on failure.
 */
static list_item *queue_signal_item(QList *list, uint32_t code, uint32_t events)
{
	list_item *l_item = (list_item *)malloc(sizeof(list_item));
	if (!l_item)
		return NULL;

	l_item->type = TYPE_SIGNAL_ITEM;
	l_item->item.s_item.events = events;
	l_item->item.s_item.code = code;

	QList_appendNode(list, (QNode *)l_item);

	return l_item;
}

/**
 * @brief Adds a waiter item to the waiter/signal list.
 *
 * @param list A pointer to the list of waiter/signal items.
 * @param code The unique identifier code for the event to wait for.
 * @param events The type of event to wait for.
 * @return list_item The newly queued waiter item.
 *         NULL on failure.
 */
static list_item *queue_waiter_item(QList *list, uint32_t code, uint32_t events)
{
	list_item *l_item = (list_item *)malloc(sizeof(list_item));
	if (!l_item)
		return NULL;

	l_item->type = TYPE_WAITER_ITEM;

	waiter_item *w_item = &(l_item->item.w_item);
	w_item->events = events;
	w_item->code = code;
	w_item->signaled = false;
	pthread_mutex_init(&w_item->mutex, NULL);
	pthread_cond_init(&w_item->condition, NULL);

	QList_appendNode(list, (QNode *)l_item);

	return l_item;
}

/**
 * @brief Dequeue and clear the waiter item from the list.
 *
 * @param l_item The waiter item to be cleared.
 */
static void clear_waiter_item(list_item *l_item)
{
	QNode_dequeue(&l_item->qn);

	waiter_item *w_item = &(l_item->item.w_item);
	pthread_mutex_destroy(&w_item->mutex);
	pthread_cond_destroy(&w_item->condition);

	free(l_item);
}

/**
 * @brief Compute the wakeup time in terms of timespec from milliseconds.
 *
 * @param msec Time in milliseconds before we wake up.
 * @param wakeup wakeup time in terms of timespec.
 */
static void compute_wakeup_time(uint32_t msec, struct timespec *wakeup)
{
	struct timespec start;
	clock_gettime(CLOCK_REALTIME, &start);

	/* pthread_cond_timedwait() resolves to the system clock, which
	 * has OS tick resolution. We account for this by waiting at
	 * least that long to guarantee TEE_Wait() times.
	 */
	long tick_sec = sysconf(_SC_CLK_TCK);
	if ((tick_sec > 0) && (msec < (uint32_t)(MSEC_PER_SEC / tick_sec)))
		msec = (uint32_t)(MSEC_PER_SEC / tick_sec);

	/* We don't consider the case of tv_sec overflowing (it's UTC
	 * and that's a time and date quite a bit in the future), and
	 * tv_nsec cannot overflow, since it comes as the sum of number
	 * from a system API (start.tv_nsec), therefore < 1e9, and a
	 * number which is at most 1e9-1 (999 ms)
	 */
	wakeup->tv_sec = start.tv_sec + (time_t)(msec / 1000);
	wakeup->tv_nsec = start.tv_nsec + (long)((msec % 1000) * 1000000);
	if (wakeup->tv_nsec > 1000000000) {
		wakeup->tv_sec += (wakeup->tv_nsec / 1000000000);
		wakeup->tv_nsec %= 1000000000;
	}
}

/**
 * @brief Wait for the specified amount of milliseconds for an event to occur.
 *
 * @param w_item The waiter item representing this wait request.
 * @param wakeup Time until wakeup from the waiting request.
 * @param msec Time in milliseconds for which to wait.
 * @param events_out The event signalled to the waiter item.
 * @return Object_OK on success.
 *         Object_ERROR* on failure.
 */
static int32_t wait_for_signal(waiter_item *w_item, struct timespec wakeup,
			       uint32_t msec, uint32_t *events_out)
{
	int32_t rv = Object_OK;
	int wait_ret = 0;

	pthread_mutex_lock(&w_item->mutex);
	while (!w_item->signaled) {
		if (msec != IWait_WAIT_INFINITE) {
			/* We use pthread_cond_timedwait() to sleep.
			* If the specified time is in the past, then we will
			* get an ETIMEDOUT return. If it returns with 0, and
			* the condition wasn't signaled, then it was a spurious
			* wake up, and we simply sleep again.
			*/
			wait_ret = pthread_cond_timedwait(
				&w_item->condition, &w_item->mutex, &wakeup);
			if (wait_ret == ETIMEDOUT)
				break;
		} else {
			wait_ret = pthread_cond_wait(&w_item->condition,
						     &w_item->mutex);
		}

		if (wait_ret) {
			rv = Object_ERROR;
			break;
		}

		/* If wait_ret is 0, it's still possible that we suffered a
		 * spurious wake-up. To ensure that we were correctly woken up,
		 * we check the w_item->signaled variable at the top of the
		 * loop. If this was in-fact a spurious wakeup call,
		 * we would sleep less this time around.
		 */
	}
	pthread_mutex_unlock(&w_item->mutex);

	if (w_item->signaled)
		/* Report the event that was signaled */
		*events_out = w_item->events;

	return rv;
}

static int32_t CWait_wait(CWait *me, uint32_t msec, uint32_t code,
			  uint32_t events, uint32_t *events_out)
{
	int32_t rv = Object_OK;
	list_item *l_item = NULL;
	waiter_item *w_item = NULL;
	struct timespec wakeup;

	if (events == IWait_EVENT_NONE || msec == 0) {
		*events_out = 0;
		return Object_OK;
	}

	pthread_mutex_lock(&me->lock);
	/* We are being asked to wait with a non-zero millisecond timeout.
	 * But first, let's check if there is a signal pending for us, if so
	 * we'll return early!
	 */
	if (get_signal_item(&me->list, code, events, events_out)) {
		pthread_mutex_unlock(&me->lock);
		return Object_OK;
	}

	/* Nobody queued a signal for this wait request, so now we have to
	 * queue a waiter item (to receive the signal) and wait.
	 */
	l_item = queue_waiter_item(&me->list, code, events);
	w_item = &(l_item->item.w_item);
	pthread_mutex_unlock(&me->lock);

	/* Compute our wakeup/wait time in preparation of signal wait */
	if (msec != IWait_WAIT_INFINITE)
		compute_wakeup_time(msec, &wakeup);

	rv = wait_for_signal(w_item, wakeup, msec, events_out);

	/* Clear the waiter item */
	pthread_mutex_lock(&me->lock);
	clear_waiter_item(l_item);
	pthread_mutex_unlock(&me->lock);

	return rv;
}

static int32_t CWait_signal(CWait *me, uint32_t code, uint32_t events)
{
	bool signaled = false;

	pthread_mutex_lock(&me->lock);

	signaled = signal_waiter_item(&me->list, code, events);

	if (!signaled && code)
		/* If nobody was waiting on this signal, we queue it to the
		 * list, since the TA can attempt to wait on it later.
		 * Note that we do this only if a cancel code is passed, i.e.
		 * signals with no cancel code that don't find a matching waiter
		 * are ignored.
		 */
		queue_signal_item(&me->list, code, events);

	pthread_mutex_unlock(&me->lock);

	return Object_OK;
}

static IWait_DEFINE_INVOKE(IWait_invoke, CWait_, CWait *);

int32_t CWait_open(Object *objOut)
{
	CWait *me = (CWait *)malloc(sizeof(CWait));
	if (!me)
		return Object_ERROR;

	atomic_init(&me->refs, 1);
	QList_construct(&me->list);
	pthread_mutex_init(&me->lock, NULL);

	*objOut = (Object){ IWait_invoke, me };

	return Object_OK;
}
