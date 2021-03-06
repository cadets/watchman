/*-
 * Copyright (c) 2011, 2013 Robert N. M. Watson
 * Copyright (c) 2012-2013 Jonathan Anderson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include "watchman_internal.h"

/*
 * Routines for managing WATCHMAN per-thread state, used in per-thread automata.
 * Kernel and userspace implementations differ quite a lot, due to very
 * different guarantees for kernel per-thread storage and perthread
 * thread-specific state.  For example, the kernel implementation guarantees
 * that space will be available if the initial watchman_class allocation
 * succeedes, and instruments thread create and destroy to ensure this is the
 * case.  However, it has to do a lot more book-keeping, and allocates space
 * that might never be used.  In userspace, per-thread state is allocated the
 * first time WATCHMAN sees the thread, but malloc may fail, meaning that WATCHMAN
 * has to handle the possibility of not finding the state it needs.
 */

#ifdef _KERNEL

/*
 * Registration state for per-thread storage.
 */
static eventhandler_tag	watchman_perthread_thread_ctor_tag;
static eventhandler_tag	watchman_perthread_thread_dtor_tag;
static eventhandler_tag watchman_perthread_process_dtor_tag;

static void
watchman_perthread_process_dtor(__unused void *arg, struct proc *p)
{
	struct thread *td;

	td = FIRST_THREAD_IN_PROC(p);
	if (td != NULL && td->td_watchman != NULL)
		watchman_store_reset(td->td_watchman);
}

static void
watchman_perthread_thread_ctor(__unused void *arg, struct thread *td)
{
	struct watchman_store *store;
	uint32_t error;

	store = watchman_malloc(sizeof(*store));
	error = watchman_store_init(store, WATCHMAN_CONTEXT_THREAD,
	    WATCHMAN_MAX_CLASSES, WATCHMAN_MAX_INSTANCES);
	watchman_assert(error == WATCHMAN_SUCCESS, ("watchman_store_init failed"));
	td->td_watchman = store;
}

static void
watchman_perthread_thread_dtor(__unused void *arg, struct thread *td)
{
	struct watchman_store *store;

	store = td->td_watchman;
	td->td_watchman = NULL;
	watchman_store_free(store);
}

static void
watchman_perthread_sysinit(__unused void *arg)
{

	watchman_perthread_process_dtor_tag = EVENTHANDLER_REGISTER(process_dtor,
	    watchman_perthread_process_dtor, NULL, EVENTHANDLER_PRI_ANY);
	watchman_perthread_thread_ctor_tag = EVENTHANDLER_REGISTER(thread_ctor,
	    watchman_perthread_thread_ctor, NULL, EVENTHANDLER_PRI_ANY);
	watchman_perthread_thread_dtor_tag = EVENTHANDLER_REGISTER(thread_dtor,
	    watchman_perthread_thread_dtor, NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(watchman_perthread, SI_SUB_WATCHMAN, SI_ORDER_FIRST,
    watchman_perthread_sysinit, NULL);

#endif /* !_KERNEL */

int
watchman_class_perthread_postinit(__unused struct watchman_class *c)
{
	return 0;
}

void
watchman_class_perthread_acquire(__unused struct watchman_class *c)
{
}

void
watchman_class_perthread_release(__unused struct watchman_class *c)
{
}

void
watchman_class_perthread_destroy(__unused struct watchman_class *c)
{
}
