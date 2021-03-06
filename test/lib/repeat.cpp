/**
 * @file repeat.cpp
 * Stress test: runs automata through their paces many times.
 *
 * Commands for llvm-lit:
 * RUN: clang %cxxflags %ldflags %s -o %t
 * RUN: %t
 */

#include "watchman_internal.h"
#include "test_helpers.h"

#include <assert.h>
#include <err.h>
#include <stdio.h>

int	do_test_run(enum watchman_context);

const int32_t INSTANCES = 4;


int
main(int argc, char **argv)
{
	install_default_signal_handler();

	struct watchman_store *store;

	enum watchman_context context = WATCHMAN_CONTEXT_THREAD;
	check(watchman_store_get(context, 2, INSTANCES, &store));
	for (size_t i = 0; i < INSTANCES + 1; i++)
		do_test_run(context);

	context = WATCHMAN_CONTEXT_GLOBAL;
	check(watchman_store_get(context, 2, INSTANCES, &store));
	for (size_t i = 0; i < INSTANCES + 1; i++)
		do_test_run(context);

	return 0;
}


/*
 * Simulate a simple automaton:
 *
 * 0 --(event A <<init>>)--> 1
 * 1 --(event B(x))--> 2
 * 1 --(event C <<cleanup>>) --> 3
 * 2 --(event B(x))--> 2
 * 2 --(event C <<cleanup>>)--> 3
 * 2 --(event D)--> 4
 * 4 --(event C <<cleanup>>)--> 3
 *
 * or, by events:
 * A    : [ (0->1) ] <<init>>
 * B(x) : [ (1->2), (2->2) ]
 * C    : [ (1->3), (2->3), (4->3) ] <<cleanup>>
 * D    : [ (2->4) ]
 */

#define	INIT	WATCHMAN_TRANS_INIT
#define	CLEAN	WATCHMAN_TRANS_CLEANUP

struct watchman_transition a[] = {
	{ .from = 0, .from_mask = 0, .to = 1, .to_mask = 0, .flags = INIT },
};

const struct watchman_transitions A = {
	.length = sizeof(a) / sizeof(a[0]), .transitions = a
};

struct watchman_transition b[] = {
	{ .from = 1, .from_mask = 0, .to = 2, .to_mask = 1, .flags = 0 },
	{ .from = 2, .from_mask = 1, .to = 2, .to_mask = 1, .flags = 0 },
};

const struct watchman_transitions B = {
	.length = sizeof(b) / sizeof(b[0]), .transitions = b
};

struct watchman_transition c[] = {
	{ .from = 1, .from_mask = 0, .to = 3, .to_mask = 1, .flags = CLEAN },
	{ .from = 2, .from_mask = 1, .to = 3, .to_mask = 1, .flags = CLEAN },
	{ .from = 4, .from_mask = 1, .to = 3, .to_mask = 1, .flags = CLEAN },
};

const struct watchman_transitions C = {
	.length = sizeof(c) / sizeof(c[0]), .transitions = c
};

struct watchman_transition d[] = {
	{ .from = 2, .from_mask = 1, .to = 4, .to_mask = 1, .flags = 0},
};

const struct watchman_transitions D = {
	.length = sizeof(d) / sizeof(d[0]), .transitions = d
};

const struct watchman_transitions all_transitions[] = { A, B, C, D };
const char *event_names[] = { "A", "B(x)", "C", "D" };


const struct watchman_lifetime lifetime = {
	.tl_begin = {
		.tle_repr = "init",
		.tle_length = sizeof("init"),
		.tle_hash = 0,
	},
	.tl_end = {
		.tle_repr = "cleanup",
		.tle_length = sizeof("cleanup"),
		.tle_hash = 1,
	},
};

const struct watchman_automaton automaton = {
	.ta_name = (__FILE__ ":test_automaton"),
	.ta_description = "this is where the original source should go",
	.ta_transitions = all_transitions,
	.ta_symbol_names = event_names,
	.ta_lifetime = &lifetime,
};


int
do_test_run(enum watchman_context context)
{
	const struct watchman_key nothing = { .tk_mask = 0 };
	struct watchman_key others[INSTANCES];
	for (size_t i = 0; i < INSTANCES; i++) {
		others[i].tk_mask = 1;
		others[i].tk_keys[0] = i;
	}

	/* event A: */
	const struct watchman_key *k = &nothing;
	watchman_update_state(context, &automaton, 0, k);


	/* event B (but only on some instances): */
	for (size_t i = 0; i < INSTANCES / 2; i += 2) {
		const struct watchman_key *k = others + i;
		watchman_update_state(context, &automaton, 1, k);
	}


	/* event B again: */
	for (size_t i = 0; i < INSTANCES / 2; i += 2) {
		const struct watchman_key *k = others + i;
		watchman_update_state(context, &automaton, 1, k);
	}


	/* event D: */
	for (size_t i = 0; i < INSTANCES / 2; i += 2) {
		const struct watchman_key *k = others + i;
		watchman_update_state(context, &automaton, 3, k);
	}


	/* event C: */
	for (size_t i = 0; i < INSTANCES / 2; i++) {
		const struct watchman_key *k = others + i;
		watchman_update_state(context, &automaton, 2, k);
	}

	return 0;
}
