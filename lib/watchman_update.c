/*-
 * Copyright (c) 2012 Jonathan Anderson
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

#ifndef _KERNEL
#include <stdbool.h>
#include <inttypes.h>
#endif


static void watchman_update_class_state(struct watchman_class *, struct watchman_store *,
	uint32_t symbol, const struct watchman_key *);


void
watchman_sunrise(enum watchman_context context, const struct watchman_lifetime *l)
{
	__unused int ret;
	assert(l != NULL);

	struct watchman_store *store;
	ret = watchman_store_get(context, WATCHMAN_MAX_CLASSES,
			WATCHMAN_MAX_INSTANCES, &store);
	assert(ret == WATCHMAN_SUCCESS);
	assert(store->ts_lifetime_count < store->ts_length);

	watchman_lifetime_state *ls = NULL;

	// TODO: lock global store

	const uint32_t lifetimes = store->ts_lifetime_count;
	for (uint32_t i = 0; i < lifetimes; i++) {
	    if (same_static_lifetime(l, store->ts_lifetimes + i)) {
		    ls = store->ts_lifetimes + i;
		    break;
	    }
	}

	if (ls == NULL) {
		ls = store->ts_lifetimes + lifetimes;
		store->ts_lifetime_count++;

		ls->tls_begin = l->tl_begin;
		ls->tls_end = l->tl_end;
	}

	ev_sunrise(context, l);
}


void
watchman_sunset(enum watchman_context context, const struct watchman_lifetime *l)
{
	__unused int ret;
	assert(l != NULL);

	ev_sunset(context, l);

	struct watchman_store *store;
	ret = watchman_store_get(context, WATCHMAN_MAX_CLASSES,
			WATCHMAN_MAX_INSTANCES, &store);
	assert(ret == WATCHMAN_SUCCESS);
	assert(store->ts_lifetime_count < store->ts_length);

	watchman_lifetime_state *ls = NULL;

	const uint32_t lifetimes = store->ts_lifetime_count;
	for (uint32_t i = 0; i < lifetimes; i++) {
		if (same_static_lifetime(l, store->ts_lifetimes + i)) {
			ls = store->ts_lifetimes + i;
			break;
		}
	}

	assert(ls != NULL && "watchman_sunset() without corresponding sunrise");

	watchman_key empty_key;
	empty_key.tk_mask = 0;

	const size_t static_classes =
		sizeof(ls->tls_classes) / sizeof(ls->tls_classes[0]);

	for (size_t i = 0; i < static_classes; i++) {
		watchman_class *class = ls->tls_classes[i];
		if (class == NULL)
			break;

		watchman_update_class_state(class, store,
			class->tc_automaton->ta_cleanup_symbol, &empty_key);
	}

	bzero(ls->tls_classes, sizeof(ls->tls_classes));

	const size_t dynamic_classes = ls->tls_dyn_count;
	for (size_t i = 0; i < dynamic_classes; i++) {
		watchman_class *class = ls->tls_dyn_classes[i];
		if (class == NULL)
			break;

		watchman_update_class_state(class, store,
			class->tc_automaton->ta_cleanup_symbol, &empty_key);
	}

	bzero(ls->tls_dyn_classes,
	      ls->tls_dyn_count * sizeof(ls->tls_classes[0]));
}


void
watchman_update_state(enum watchman_context watchman_context,
	const struct watchman_automaton *autom, uint32_t symbol,
	const struct watchman_key *pattern)
{
	struct watchman_store *store;
	int ret = watchman_store_get(watchman_context, WATCHMAN_MAX_CLASSES,
			WATCHMAN_MAX_INSTANCES, &store);
	assert(ret == WATCHMAN_SUCCESS);

	struct watchman_class *class;
	ret = watchman_class_get(store, autom, &class);
	assert(ret == WATCHMAN_SUCCESS);

	watchman_update_class_state(class, store, symbol, pattern);

	watchman_class_put(class);
}


static void
watchman_update_class_state(struct watchman_class *class, struct watchman_store *store,
	uint32_t symbol, const struct watchman_key *pattern)
{
	int err;
	const struct watchman_automaton *autom = class->tc_automaton;

	// Make space for cloning existing instances.
	size_t cloned = 0;
	const size_t max_clones = class->tc_free;
	struct clone_info {
		watchman_instance *old;
		const watchman_transition *transition;
	} clones[max_clones];

	// Has this class been initialised?
	bool initialised = false;
	watchman_lifetime_state *lifetime = NULL;
	const uint32_t lifetimes = store->ts_lifetime_count;
	for (uint32_t i = 0; i < lifetimes; i++) {
		if (!same_static_lifetime(autom->ta_lifetime,
			    store->ts_lifetimes + i))
			continue;

		initialised = true;
		lifetime = store->ts_lifetimes + i;
		break;
	}

	if (!initialised) {
		 ev_ignored(class, symbol, pattern);
		 return;

	} else if (class->tc_limit == class->tc_free) {
		// Late initialisation: find the init transition and pretend
		// it has already been taken.
		struct watchman_instance *inst = NULL;

		for (uint32_t i = 0; i < autom->ta_alphabet_size; i++) {
			const watchman_transitions *trans =
				autom->ta_transitions + i;

			for (uint32_t j = 0; i < trans->length; i++) {
				const watchman_transition *t =
					trans->transitions + j;

				if (!(t->flags & WATCHMAN_TRANS_INIT))
					continue;

				static const watchman_key empty = { .tk_mask = 0 };

				err = watchman_instance_new(class, &empty,
				                         t->to, &inst);

				if (err != WATCHMAN_SUCCESS) {

					ev_err(autom, symbol, err,
					       "failed to initialise instance");
					return;
				}

				break;
			}
		}

		if (inst == NULL) {
			// The automaton does not have an init transition!
			err = WATCHMAN_ERROR_EINVAL;
			ev_err(autom, symbol, err,
			       "automaton has no init transition");
			return;
		}

		assert(watchman_instance_active(inst));
		ev_new_instance(class, inst);

		// Register this class for eventual cleanup.
		watchman_lifetime_state *ls = lifetime;
		const size_t static_classes =
			sizeof(ls->tls_classes) / sizeof(ls->tls_classes[0]);

		size_t i;
		for (i = 0; i < static_classes; i++) {
			if (ls->tls_classes[i] != NULL)
				continue;

			ls->tls_classes[i] = class;
			break;
		}

		if (i == static_classes) {
#ifdef _KERNEL
			/*
			 * TODO(JA): we should also do the dynamic thing,
			 *           but we might have to do it by noting
			 *           that we don't have enough space and
			 *           leaving the allocation for a later time
			 *           when we know it's safe.
			 */
			ev_err(autom, symbol, WATCHMAN_ERROR_ENOMEM,
			       "out of static registration space in lifetime");
#else
			static size_t unit_size =
				sizeof(ls->tls_dyn_classes[0]);

			watchman_class ***dyn_classes = &ls->tls_dyn_classes;

			if (ls->tls_dyn_capacity == 0) {
				// Need to create a fresh allocation.
				size_t count = 8;
				*dyn_classes = calloc(count, unit_size);
				ls->tls_dyn_capacity = count;
			} else {
				size_t count = 2 * ls->tls_dyn_capacity;
				*dyn_classes = realloc(*dyn_classes,
						       count * unit_size);
				ls->tls_dyn_capacity = count;
			}

			assert(ls->tls_dyn_count < ls->tls_dyn_capacity);
			ls->tls_dyn_classes[ls->tls_dyn_count++] = class;
#endif
		}
	}


	// Did we match any instances?
	bool matched_something = false;

	// When we're done, do we need to clean up the class?
	bool cleanup_required = false;


	// What transitions can we take?
	const watchman_transitions *trans = autom->ta_transitions + symbol;
	assert(trans->length > 0);
	assert(trans->length < 10000);

	// Iterate over existing instances, figure out what to do with each.
	err = WATCHMAN_SUCCESS;
	int expected = class->tc_limit - class->tc_free;
	for (uint32_t i = 0; expected > 0 && (i < class->tc_limit); i++) {
		assert(class->tc_instances != NULL);
		watchman_instance *inst = class->tc_instances + i;

		const watchman_transition *trigger = NULL;
		enum watchman_action_t action =
			watchman_action(inst, pattern, trans, &trigger);
		expected -= action == IGNORE ? 0 : 1;

		switch (action) {
		case FAIL:
			ev_bad_transition(class, inst, symbol);
			break;

		case IGNORE:
			// TODO(JA): this should become unreachable
			break;

		case UPDATE:
			if (have_transitions)
				ev_transition(class, inst, trigger);
			inst->ti_state = trigger->to;
			matched_something = true;

			if (trigger->flags & WATCHMAN_TRANS_CLEANUP)
				ev_accept(class, inst);

			break;

		case FORK: {
			if (cloned >= max_clones) {
				err = WATCHMAN_ERROR_ENOMEM;
				ev_err(autom, symbol, err, "too many clones");
				return;
			}

			struct clone_info *clone = clones + cloned++;
			clone->old = inst;
			clone->transition = trigger;
			matched_something = true;
			break;
		}

		case JOIN:
#ifndef	NDEBUG
			{
			int target = -1;
			for (uint32_t j = 0; j < class->tc_limit; j++) {
				watchman_instance *t = class->tc_instances + j;
				if (t->ti_state == trigger->to) {
					target = j;
					break;
				}
			}
			assert(target >= 0);
			}
#endif
			watchman_instance_clear(inst);
			break;
		}

		if (trigger && (trigger->flags & WATCHMAN_TRANS_CLEANUP))
			cleanup_required = true;
	}

	// Move any clones into the class.
	for (size_t i = 0; i < cloned; i++) {
		struct clone_info *c = clones + i;
		struct watchman_instance *clone;
		err = watchman_instance_clone(class, c->old, &clone);
		if (err != WATCHMAN_SUCCESS) {
			ev_err(autom, symbol, err, "failed to clone instance");
			return;
		}

		watchman_key new_name = *pattern;
		new_name.tk_mask &= c->transition->to_mask;
		err = watchman_key_union(&clone->ti_key, &new_name);
		if (err != WATCHMAN_SUCCESS) {
			ev_err(autom, symbol, err, "failed to union keys");
			return;
		}

		clone->ti_state = c->transition->to;

		ev_clone(class, c->old, clone, c->transition);

		if (c->transition->flags & WATCHMAN_TRANS_CLEANUP)
			ev_accept(class, clone);
	}

	if (!matched_something)
		ev_no_instance(class, symbol, pattern);

	// Does it cause class cleanup?
	if (cleanup_required)
		watchman_class_reset(class);
}

enum watchman_action_t
watchman_action(const watchman_instance *inst, const watchman_key *event_data,
	const watchman_transitions *trans, const watchman_transition* *trigger)
{
	assert(trigger != NULL);

	if (!watchman_instance_active(inst))
		return IGNORE;

	/*
	 * We allowed to ignore this instance if its name doesn't match
	 * any of the given transitions.
	 */
	bool ignore = true;

	for (size_t i = 0; i < trans->length; i++) {
		const watchman_transition *t = trans->transitions + i;

		if (t->from == inst->ti_state) {
			assert(inst->ti_key.tk_mask == t->from_mask);

			/*
			 * We need to match events against a pattern based on
			 * data from the event, but ignoring parts that are
			 * extraneous to this transition.
			 *
			 * For instance, if the event is 'foo(x,y) == z', we
			 * know what the values of x, y and z are, but the
			 * transition in question may only care about x and z:
			 * 'foo(x,*) == z'.
			 */
			watchman_key pattern = *event_data;
			pattern.tk_mask &= t->from_mask;

			/*
			 * Losing information implies a join
			 * (except during automaton instance cleanup).
			 */
			if (!SUBSET(t->from_mask, t->to_mask)
			    && ((t->flags & WATCHMAN_TRANS_CLEANUP) == 0)) {
				*trigger = t;
				return JOIN;
			}

			/*
			 * Does the transition cause key data to be added
			 * to the instance's name?
			 */
			if (SUBSET(t->to_mask, t->from_mask)) {
				/*
				 * No: just just update the instance
				 *     if its (masked) name matches.
				 */
				watchman_key masked_name = inst->ti_key;
				masked_name.tk_mask &=
					(pattern.tk_mask | pattern.tk_freemask);

				if (watchman_key_matches(&pattern, &masked_name)) {
					*trigger = t;
					return UPDATE;
				}

			} else {
				/*
				 * Yes: we need to fork the generic instance
				 *      into a more specific one.
				 */
				if (watchman_key_matches(&pattern, &inst->ti_key)) {
					*trigger = t;
					return FORK;
				}
			}

			/*
			 * If we are in the right state but don't match on
			 * the pattern, even with a mask, move on to the
			 * next transition.
			 */
			continue;
		}

		/*
		 * We are not in the correct state for this transition, so
		 * we can't take it.
		 *
		 * If we match the pattern, however, it means that *some*
		 * transition must match; we are no longer allowed to ignore
		 * this instance.
		 */
		if (watchman_key_matches(event_data, &inst->ti_key))
			ignore = false;
	}

	if (ignore)
		return IGNORE;

	else
		return FAIL;
}

printf_type __watchman_printf = (printf_type)printf;
