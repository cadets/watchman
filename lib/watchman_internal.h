/*-
 * Copyright (c) 2011, 2013 Robert N. M. Watson
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

#ifndef WATCHMAN_INTERNAL_H
#define	WATCHMAN_INTERNAL_H

#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * @addtogroup watchman
 * @{
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _KERNEL
#include "opt_kdb.h"
#include "opt_kdtrace.h"
#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/systm.h>

#include <machine/_inttypes.h>
#else
#include <assert.h>
#include <err.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <watchman.h>

/** Is @a x a subset of @a y? */
#define	SUBSET(x,y) (((x) & (y)) == (x))

#ifdef _KERNEL
/** Emulate simple POSIX assertions. */
#define assert(cond) KASSERT((cond), ("Assertion failed: '%s'", #cond))
#endif


/**
 * The current runtime state of a WATCHMAN lifetime.
 */
struct watchman_lifetime_state {
	struct watchman_lifetime_event	 tls_begin;
	struct watchman_lifetime_event	 tls_end;

	/** A place to register a few classes that share this lifetime. */
	struct watchman_class*		 tls_classes[32];

	/** A place to register more classes that share this lifetime. */
	struct watchman_class*		*tls_dyn_classes;

	/** The number of values @ref tls_dyn_classes can hold. */
	uint32_t			 tls_dyn_capacity;

	/** The number of values currently in @ref tls_dyn_classes. */
	uint32_t			 tls_dyn_count;
};

/**
 * Call this if things go catastrophically, unrecoverably wrong.
 */
void	watchman_die(int32_t errnum, const char *event) __attribute__((noreturn));

/**
 * Reset all automata in a store to the inactive state.
 */
void	watchman_store_reset(struct watchman_store *store);

/**
 * Clean up a @ref watchman_store.
 */
void	watchman_store_free(struct watchman_store*);


/**
 * Reset a @ref watchman_class for re-use from a clean state.
 */
void	watchman_class_reset(struct watchman_class*);

/**
 * Clean up a @ref watchman_class.
 */
void	watchman_class_destroy(struct watchman_class*);


/**
 * Create a new @ref watchman_instance.
 *
 * The caller is responsible for locking the class if needed.
 */
int32_t	watchman_instance_new(struct watchman_class *tclass,
	    const struct watchman_key *name, uint32_t state,
	    struct watchman_instance **out);

/**
 * Checks whether or not a WATCHMAN automata instance is active (in use).
 *
 * @param  i    pointer to a <b>valid</b> @ref watchman_instance
 *
 * @returns     1 if active, 0 if inactive
 */
static inline int32_t
watchman_instance_active(const struct watchman_instance *i)
{
	assert(i != NULL);

	return ((i->ti_state != 0) || (i->ti_key.tk_mask != 0));
}

static inline bool
same_lifetime(const struct watchman_lifetime *x, const struct watchman_lifetime *y)
{
	assert(x != NULL);
	assert(y != NULL);

	return (x->tl_begin.tle_length == y->tl_begin.tle_length)
		&& (x->tl_end.tle_length == y->tl_end.tle_length)
		&& (x->tl_begin.tle_hash == y->tl_begin.tle_hash)
		&& (x->tl_end.tle_hash == y->tl_end.tle_hash)
		&& (strncmp(x->tl_begin.tle_repr, y->tl_begin.tle_repr,
		            x->tl_begin.tle_length) == 0)
		&& (strncmp(x->tl_end.tle_repr, y->tl_end.tle_repr,
		            x->tl_end.tle_length) == 0)
		;
}

/**
 * Compare the static parts of a @ref watchman_lifetime_state with a
 * @ref watchman_lifetime.
 */
static inline bool
same_static_lifetime(const struct watchman_lifetime *x,
	const struct watchman_lifetime_state *y)
{
	assert(x != NULL);
	assert(y != NULL);

	return (x->tl_begin.tle_length == y->tls_begin.tle_length)
		&& (x->tl_end.tle_length == y->tls_end.tle_length)
		&& (x->tl_begin.tle_hash == y->tls_begin.tle_hash)
		&& (x->tl_end.tle_hash == y->tls_end.tle_hash)
		&& (strncmp(x->tl_begin.tle_repr, y->tls_begin.tle_repr,
		            x->tl_begin.tle_length) == 0)
		&& (strncmp(x->tl_end.tle_repr, y->tls_end.tle_repr,
		            x->tl_end.tle_length) == 0)
		;
}


/** Clone an existing instance into a new instance. */
int32_t	watchman_instance_clone(struct watchman_class *tclass,
	    const struct watchman_instance *orig, struct watchman_instance **copy);

/** Zero an instance for re-use. */
void	watchman_instance_clear(struct watchman_instance *tip);


/**
 * Find all automata instances in a class that match a particular key.
 *
 * The caller is responsible for locking the class if necessary.
 *
 * @param[in]     tclass   the class of automata to match
 * @param[in]     key      must remain valid as long as the iterator is in use
 * @param[out]    array    a caller-allocated array to store matches in
 * @param[in,out] size     in: size of array. out: number of instances.
 *
 * @returns    a standard WATCHMAN error code (e.g., WATCHMAN_ERROR_ENOMEM)
 */
int32_t	watchman_match(struct watchman_class *tclass, const struct watchman_key *key,
	    struct watchman_instance **array, uint32_t *size);



/** Actions that can be taken by @ref watchman_update_state. */
enum watchman_action_t {
	/** The instance's state should be updated. */
	UPDATE,

	/** The instance should be copied to a new instance. */
	FORK,

	/** The instance should be merged into another instance. */
	JOIN,

	/** The instance is irrelevant to the given transitions. */
	IGNORE,

	/** The instance matches, but there are no valid transitions for it. */
	FAIL
};

/**
 * What is the correct action to perform on a given @ref watchman_instance to
 * satisfy a set of @ref watchman_transitions?
 *
 * @param[out]   trigger    the @ref watchman_transition that triggered the action
 */
enum watchman_action_t	watchman_action(const struct watchman_instance*,
	    const struct watchman_key*, const struct watchman_transitions*,
	    const struct watchman_transition** trigger);

static __inline uint32_t
fnv_hash32(uint32_t x)
{
	return x * ((uint32_t) 0x01000193UL);
}

static __inline uint64_t
fnv_hash64(uint32_t x)
{
	return x * ((uint64_t) 0x100000001b3ULL);
}

#ifndef __unused
#if __has_attribute(unused)
#define __unused __attribute__((unused))
#else
#define __unused
#endif
#endif

// Kernel vs userspace implementation details.
#ifdef _KERNEL

/** In the kernel, panic really means panic(). */
#define watchman_panic(...) panic(__VA_ARGS__)

/** Our @ref watchman_assert has the same signature as @ref KASSERT. */
#define watchman_assert(...) KASSERT(__VA_ARGS__)

#define watchman_malloc(len) malloc(len, M_WATCHMAN, M_WAITOK | M_ZERO)
#define watchman_free(x) free(x, M_WATCHMAN)

#define watchman_lock(l) mtx_lock(l)
#define watchman_unlock(l) mtx_unlock(l)

#else	/* !_KERNEL */

/** @a errx() is the userspace equivalent of panic(). */
#define watchman_panic(...) errx(1, __VA_ARGS__)

/** POSIX @a assert() doesn't let us provide an error message. */
#define watchman_assert(condition, ...) assert(condition)

#define watchman_malloc(len) calloc(1, len)
#define watchman_free(x) free(x)

#define watchman_lock(l) \
	do { __debug int err = pthread_mutex_lock(l); assert(err == 0); } while(0)

#define watchman_unlock(l) \
	do { __debug int err = pthread_mutex_unlock(l); assert(err == 0); } while(0)

#endif


/*
 * Assertion state definition is internal to watchman so we can change it as
 * we need to.
 */
struct watchman_class {
	/**
	 * Static automaton description.
	 */
	const struct watchman_automaton *tc_automaton;
	enum watchman_context	 tc_context;	/* Global, thread... */

	uint32_t		 tc_limit;	/* Maximum instances. */
	uint32_t		 tc_free;	/* Unused instances. */
	struct watchman_instance	*tc_instances;	/* Instances of this class. */

#ifdef _KERNEL
	struct mtx		 tc_lock;	/* Synchronise tc_table. */
#else
	pthread_mutex_t		 tc_lock;	/* Synchronise tc_table. */
#endif
};


typedef struct watchman_automaton		watchman_automaton;
typedef struct watchman_class		watchman_class;
typedef struct watchman_instance		watchman_instance;
typedef struct watchman_key		watchman_key;
typedef struct watchman_lifetime_event	watchman_lifetime_event;
typedef struct watchman_lifetime_state	watchman_lifetime_state;
typedef struct watchman_store		watchman_store;
typedef struct watchman_transition		watchman_transition;
typedef struct watchman_transitions	watchman_transitions;


/**
 * @internal Definition of @ref watchman_store.
 *
 * Modifications to this structure should only be made while a lock is held
 * or in a thread-local context.
 */
struct watchman_store {
	/** Number of slots to hold WATCHMAN classes. */
	uint32_t		 ts_length;

	/** Actual slots that classes might be stored in. */
	struct watchman_class	*ts_classes;

	/**
	 * Information about live/dead automata classes; may be shared among
	 * automata.
	 *
	 * For instance, the lifetime [enter syscall, exit syscall] is shared
	 * by many automata we've written for the FreeBSD kernel. Each
	 * @ref watchman_store should only record these events once.
	 */
	struct watchman_lifetime_state *ts_lifetimes;

	/** The number of lifetimes that we currently know about. */
	uint32_t		ts_lifetime_count;
};

/**
 * Initialise @ref watchman_store internals.
 * Locking is the responsibility of the caller.
 */
int	watchman_store_init(watchman_store*, enum watchman_context context,
		uint32_t classes, uint32_t instances);

/**
 * Initialize @ref watchman_class internals.
 * Locking is the responsibility of the caller.
 */
int	watchman_class_init(struct watchman_class*, enum watchman_context context,
		uint32_t instances);

/*
 * XXXRW: temporarily, maximum number of classes and instances are hard-coded
 * constants.  In the future, this should somehow be more dynamic.
 */
#define	WATCHMAN_MAX_CLASSES		128
#define	WATCHMAN_MAX_INSTANCES		128

#if defined(_KERNEL) && defined(MALLOC_DECLARE)
/*
 * Memory type for WATCHMAN allocations in the kernel.
 */
MALLOC_DECLARE(M_WATCHMAN);
#endif

/*
 * Context-specific automata management:
 */
int32_t	watchman_class_global_postinit(struct watchman_class*);
void	watchman_class_global_acquire(struct watchman_class*);
void	watchman_class_global_release(struct watchman_class*);
void	watchman_class_global_destroy(struct watchman_class*);

int32_t	watchman_class_perthread_postinit(struct watchman_class*);
void	watchman_class_perthread_acquire(struct watchman_class*);
void	watchman_class_perthread_release(struct watchman_class*);
void	watchman_class_perthread_destroy(struct watchman_class*);

/*
 * Event notification:
 */
#if defined(_KERNEL) && defined(KDTRACE_HOOKS)
extern const struct watchman_event_handlers dtrace_handlers;
#endif

void	ev_sunrise(enum watchman_context, const struct watchman_lifetime *);
void	ev_sunset(enum watchman_context, const struct watchman_lifetime *);
void	ev_new_instance(struct watchman_class *, struct watchman_instance *);
void	ev_transition(struct watchman_class *, struct watchman_instance *,
	    const struct watchman_transition *);
void	ev_clone(struct watchman_class *, struct watchman_instance *orig,
	    struct watchman_instance *copy, const struct watchman_transition *);
void	ev_no_instance(struct watchman_class *, uint32_t symbol,
	    const struct watchman_key *);
void	ev_bad_transition(struct watchman_class *, struct watchman_instance *,
	    uint32_t symbol);
void	ev_err(const struct watchman_automaton *, int symbol, int errnum,
	    const char *);
void	ev_accept(struct watchman_class *, struct watchman_instance *);
void	ev_ignored(const struct watchman_class *, uint32_t symbol,
	    const struct watchman_key *);

/*
 * Debug helpers.
 */

/** Do a @a sprintf() into a buffer, checking bounds appropriately. */
#define	SAFE_SPRINTF(current, end, ...) do {				\
	int written = snprintf(current, end - current, __VA_ARGS__);	\
	if ((written > 0) && (current + written < end))			\
		current += written;					\
} while (0)

#define print(...)	printf(__VA_ARGS__)

#ifdef _KERNEL
#define error(...)	printf(__VA_ARGS__)
#else
#define error(...)	fprintf(stderr, __VA_ARGS__)
#endif

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdio.h>
#endif


/** Are we in (verbose) debug mode? */
int32_t	watchman_debugging(const char*);

#ifndef NDEBUG

#define __debug

/** Emit debugging information with a debug name (e.g., watchman.event). */
#define DEBUG(dclass, ...) \
	if (watchman_debugging(#dclass)) printf(__VA_ARGS__)

#else // NDEBUG

// When not in debug mode, some values might not get checked.
#define __debug __unused

#define DEBUG(...)

#endif

/**
 * Assert that a @ref watchman_instance is an instance of a @ref watchman_class.
 *
 * This could be expensive (a linear walk over all @ref watchman_instance in
 * @a tclass), so it should only be called from debug code.
 *
 * @param   i          the instance to test
 * @param   tclass     the expected class of @a i
 */
void	assert_instanceof(struct watchman_instance *i, struct watchman_class *tclass);

/** Print a key into a buffer. */
char*	key_string(char *buffer, const char *end, const struct watchman_key *);

/** Print a @ref watchman_key to stderr. */
void	print_key(const char *debug_name, const struct watchman_key *key);

/** Print a @ref watchman_class to stderr. */
void	print_class(const struct watchman_class*);

/** Print a human-readable version of a @ref watchman_transition. */
void	print_transition(const char *debug, const struct watchman_transition *);

/** Print a human-readable version of a @ref watchman_transition into a buffer. */
char*	sprint_transition(char *buffer, const char *end,
    const struct watchman_transition *);

/** Print a human-readable version of @ref watchman_transitions. */
void	print_transitions(const char *debug, const struct watchman_transitions *);

/** Print a human-readable version of @ref watchman_transitions into a buffer. */
char*	sprint_transitions(char *buffer, const char *end,
    const struct watchman_transitions *);

/** Flag indicating whether ev_transition should be called. */
extern int have_transitions;

/** @} */

__END_DECLS

#endif /* WATCHMAN_INTERNAL_H */
