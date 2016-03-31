/*-
 * Copyright (c) 2011, 2013 Robert N. M. Watson
 * Copyright (c) 2011 Anil Madhavapeddy
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
#include "watchman_key.h"

#ifdef _KERNEL
MALLOC_DEFINE(M_WATCHMAN, "watchman", "WATCHMAN internal state");
#else
#include <inttypes.h>
#include <stdio.h>
#endif


int
watchman_class_init(struct watchman_class *tclass, enum watchman_context context,
	uint32_t instances)
{
	assert(tclass != NULL);
	assert(context >= 0);
	assert(instances > 0);
	// TODO: write a WATCHMAN assertion about locking here.

	tclass->tc_limit = instances;

	tclass->tc_context = context;
	tclass->tc_limit = instances;
	tclass->tc_free = instances;
	tclass->tc_instances =
		watchman_malloc(instances * sizeof(tclass->tc_instances[0]));

	switch (context) {
	case WATCHMAN_CONTEXT_GLOBAL:
		return watchman_class_global_postinit(tclass);

	case WATCHMAN_CONTEXT_THREAD:
		return watchman_class_perthread_postinit(tclass);

	default:
		assert(0 && "unhandled WATCHMAN context");
		return (WATCHMAN_ERROR_UNKNOWN);
	}
}


void
watchman_class_destroy(struct watchman_class *class)
{
	watchman_free(class->tc_instances);
	switch (class->tc_context) {
	case WATCHMAN_CONTEXT_GLOBAL:
		watchman_class_global_destroy(class);
		break;

	case WATCHMAN_CONTEXT_THREAD:
		watchman_class_perthread_destroy(class);
		break;
	}
}


int
watchman_match(struct watchman_class *tclass, const struct watchman_key *pattern,
	    struct watchman_instance **array, uint32_t *size)
{
	assert(tclass != NULL);
	assert(pattern != NULL);
	assert(array != NULL);
	assert(size != NULL);

	// Assume that any and every instance could match.
	if (*size < tclass->tc_limit) {
		*size = tclass->tc_limit;
		return (WATCHMAN_ERROR_ENOMEM);
	}

	// Copy matches into the array.
	*size = 0;
	for (uint32_t i = 0; i < tclass->tc_limit; i++) {
		struct watchman_instance *inst = tclass->tc_instances + i;
		if (watchman_instance_active(inst)
		    && watchman_key_matches(pattern, &inst->ti_key)) {
			array[*size] = inst;
			*size += 1;
		}
	}

	return (WATCHMAN_SUCCESS);
}



int32_t
watchman_instance_new(struct watchman_class *tclass, const struct watchman_key *name,
	uint32_t state, struct watchman_instance **out)
{
	assert(tclass != NULL);
	assert(name != NULL);
	assert(out != NULL);

	// A new instance must not look inactive.
	if ((state == 0) && (name->tk_mask == 0))
		return (WATCHMAN_ERROR_EINVAL);

	if (tclass->tc_free == 0)
		return (WATCHMAN_ERROR_ENOMEM);

	for (uint32_t i = 0; i < tclass->tc_limit; i++) {
		struct watchman_instance *inst = tclass->tc_instances + i;
		if (watchman_instance_active(inst))
			continue;

		// Initialise the new instance.
		inst->ti_key = *name;
		inst->ti_state = state;

		tclass->tc_free--;
		*out = inst;

		return (WATCHMAN_SUCCESS);
	}

	watchman_assert(0, ("no free instances but tc_free was > 0"));
	return (WATCHMAN_ERROR_ENOMEM);
}

int
watchman_instance_clone(struct watchman_class *tclass,
	const struct watchman_instance *orig, struct watchman_instance **copy)
{
	return watchman_instance_new(tclass, &orig->ti_key, orig->ti_state, copy);
}

void
watchman_instance_clear(struct watchman_instance *tip)
{

	bzero(tip, sizeof(*tip));
	assert(!watchman_instance_active(tip));
}

void
watchman_class_put(struct watchman_class *tsp)
{
	switch (tsp->tc_context) {
	case WATCHMAN_CONTEXT_GLOBAL:
		return watchman_class_global_release(tsp);

	case WATCHMAN_CONTEXT_THREAD:
		return watchman_class_perthread_release(tsp);

	default:
		assert(0 && "unhandled WATCHMAN context");
	}
}

void
watchman_class_reset(struct watchman_class *c)
{

	DEBUG(libwatchman.class.reset, "watchman_class_reset %s\n",
	      c->tc_automaton->ta_name);

	bzero(c->tc_instances, sizeof(c->tc_instances[0]) * c->tc_limit);
	c->tc_free = c->tc_limit;
}
