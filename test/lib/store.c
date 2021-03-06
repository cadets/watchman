/**
 * @file store.c
 * Tests automata class storage.
 *
 * Commands for llvm-lit:
 * RUN: clang %cflags %ldflags %s -o %t
 * RUN: %t
 */

#include "watchman_internal.h"
#include "test_helpers.h"

#include <assert.h>
#include <err.h>
#include <stdio.h>


static void	check_store(struct watchman_store*);

const int	CLASSES = 4;

int
main(int argc, char **argv)
{
	install_default_signal_handler();

	struct watchman_store *global_store, *perthread;

	check(watchman_store_get(WATCHMAN_CONTEXT_GLOBAL, CLASSES, 1, &global_store));
	check(watchman_store_get(WATCHMAN_CONTEXT_THREAD, CLASSES, 1, &perthread));

	check_store(global_store);
	check_store(perthread);

	return 0;
}


#define name(i) (__FILE__ "#" #i)
#define desc(i) ("Automaton class " #i)

static void
check_store(struct watchman_store *store)
{
	assert(store != NULL);

	struct watchman_lifetime lifetime = {
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

	struct watchman_automaton descriptions[CLASSES];
	struct watchman_class *classes[CLASSES];

	for (unsigned int i = 0; i < CLASSES; i++) {
		struct watchman_automaton *descrip = descriptions + i;
		descrip->ta_name = name(i);
                descrip->ta_lifetime = &lifetime;

		check(watchman_class_get(store, descrip, classes + i));

		struct watchman_instance *instance;
		struct watchman_key key;
		key.tk_mask = 1;
		key.tk_keys[0] = 42 + i;

		intptr_t state = 2 * i + 42;

		check(watchman_instance_new(classes[i], &key, state, &instance));
		assert(instance != NULL);
		assert(watchman_instance_active(instance));
		assert(instance->ti_state == 2 * i + 42);
		assert(instance->ti_key.tk_mask == 1);
		assert(instance->ti_key.tk_keys[0] == 42 + i);

		watchman_class_put(classes[i]);
	}

	struct watchman_class *JUNK = (struct watchman_class*) 0xF00BA5;
	struct watchman_class *junk = JUNK;

	struct watchman_automaton descrip = {
		.ta_name = "store.cpp:i+1",
		.ta_description = "valid automaton, invalid watchman_class*",
		.ta_alphabet_size = 42,
	};

	int err = watchman_class_get(store, &descrip, &junk);
	if (err != WATCHMAN_ERROR_ENOENT)
		errx(1, "watchman_class_get() did not report ENOENT: %s",
		     watchman_strerror(err));

	if (junk != JUNK)
		errx(1, "watchman_class_get() clobbered output variable when"
		        " returning an error");
}
