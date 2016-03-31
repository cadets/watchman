/*-
 * Copyright (c) 2011 Robert N. M. Watson
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

#ifndef	_WATCHMAN_H
#define	_WATCHMAN_H

#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * Support library for WATCHMAN instrumentation.
 * @addtogroup libwatchman
 * @{
 */

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdint.h>		/* int32_t, uint32_t */
#endif

/**
 * Error values that can be returned by libwatchman functions.
 *
 * libwatchman functions mostly return error values, and therefore return
 * pointers, etc, via call-by-reference arguments.
 */
enum watchman_err_t {
	WATCHMAN_SUCCESS,		/* Success. */
	WATCHMAN_ERROR_ENOENT,	/* Entry not found. */
	WATCHMAN_ERROR_ENOMEM,	/* Insufficient memory. */
	WATCHMAN_ERROR_EINVAL,	/* Invalid parameters. */
	WATCHMAN_ERROR_UNKNOWN,	/* An unknown (e.g. platform) error. */
};

/**
 * Provide string versions of WATCHMAN errors.
 */
const char	*watchman_strerror(int32_t error);



/**
 * An internal description of a WATCHMAN automaton, which may be instantiated
 * a number of times with different names and current states.
 */
struct watchman_class;
struct watchman_lifetime_event;
struct watchman_transitions;

/**
 * A static description of a WATCHMAN automaton.
 */
struct watchman_automaton {
	/** A unique name, hopefully human-readable. */
	const char			*ta_name;

	/**
	 * The number of symbols in the input alphabet (events that can
	 * be observed).
	 *
	 * Input alphabet symbols are integers in the range [0,alphabet_size].
	 */
	const uint32_t			 ta_alphabet_size;

        /**
         * The symbol number used to signal cleanup.
         */
        const uint32_t                    ta_cleanup_symbol;

	/**
	 * Transitions that will be taken in response to events.
	 *
	 * The transitions that can be taken in response to event 42 will
	 * be found in transitions[42].
	 */
	const struct watchman_transitions	*ta_transitions;

	/** Original source description of the automaton. */
	const char			*ta_description;

	/** Human-readable descriptions of input symbols (for debugging). */
	const char*			*ta_symbol_names;

	/** The automaton's lifetime. */
	const struct watchman_lifetime	*ta_lifetime;
};


/**
 * A short, unique, deterministic representation of a lifetime entry/exit event,
 * a pair of which defines an automaton's lifetime.
 */
struct watchman_lifetime_event {
	/**
	 * An opaque representation of the automaton's initialisation event.
	 *
	 * This description should be short and deterministic,
	 * i.e., multiple automata that share the same init event should
	 * have exactly the same ta_init description string.
	 *
	 * This can be written by hand if needed (e.g. for testing),
	 * but in practice we generate it from protocol buffers.
	 */
	const char			*tle_repr;

	/** The length of @ref #tle_repr. */
	const uint32_t			 tle_length;

	/**
	 * A precomputed hash of @ref #tle_repr.
	 *
	 * libwatchman doesn't care what hash algorithm is used; in test code or
	 * statically-compiled clients, incrementing integers works well.
	 *
	 * All clients should be consistent, however; the WATCHMAN instrumenter
	 * uses SuperFastHash.
	 */
	const uint32_t			 tle_hash;
};


/**
 * The description of a WATCHMAN lifetime.
 */
struct watchman_lifetime {
	struct watchman_lifetime_event	tl_begin;
	struct watchman_lifetime_event	tl_end;

	/** A human-readable string for debugging. */
	const char			*tl_repr;
};


/**
 * Register a @ref watchman_automaton, receiving a @ref watchman_class back.
 *
 * The @ref watchman_automaton must exist for the lifetime of the WATCHMAN context
 * (until thread destruction in the per-thread case, indefinitely in the
 * global case).
 */
int	watchman_register(const struct watchman_automaton*, struct watchman_class**);


/**
 * A storage container for one or more @ref watchman_class objects.
 *
 * There may be one @ref watchman_store for each thread (for storing thread-local
 * automata) plus a single global @ref watchman_store.
 */
struct watchman_store;

/**
 * A context where WATCHMAN data is stored.
 *
 * WATCHMAN data can be stored in a number of places that imply different
 * synchronisation requirements. For instance, thread-local storage does not
 * require synchronisation on access, whereas global storage does.
 * On the other hand, thread-local storage cannot be used to track events
 * across multiple threads.
 */
enum watchman_context {
	WATCHMAN_CONTEXT_GLOBAL,
	WATCHMAN_CONTEXT_THREAD,
};

/**
 * Retrieve the @ref watchman_store for a context (e.g., a thread).
 *
 * If the @ref watchman_store does not exist yet, it will be created.
 *
 * @param[in]  context     @ref WATCHMAN_CONTEXT_THREAD or
 *                         @ref WATCHMAN_CONTEXT_GLOBAL
 * @param[in]  classes     number of @ref watchman_class'es to expect
 * @param[in]  instances   @ref watchman_instance count per @ref watchman_class
 * @param[out] store       return parameter for @ref watchman_store pointer
 */
int32_t	watchman_store_get(enum watchman_context context,
	                uint32_t classes, uint32_t instances,
	                struct watchman_store* *store);


/**
 * Retrieve (or create) a @ref watchman_class from a @ref watchman_store.
 *
 * Once the caller is done with the @ref watchman_class, @ref watchman_class_put
 * must be called.
 *
 * @param[in]   store    where the @ref watchman_class is expected to be stored
 * @param[in]   description   information about the automaton
 * @param[out]  tclass   the retrieved (or generated) @ref watchman_class;
 *                       only set if function returns WATCHMAN_SUCCESS
 *
 * @returns a WATCHMAN error code (WATCHMAN_SUCCESS, WATCHMAN_ERROR_EINVAL, etc.)
 */
int32_t	watchman_class_get(struct watchman_store *store,
	                const struct watchman_automaton *description,
	                struct watchman_class **tclass);

/** Release resources (e.g., locks) associated with a @ref watchman_class. */
void	watchman_class_put(struct watchman_class*);


/** A single allowable transition in a WATCHMAN automaton. */
struct watchman_transition {
	/** The state we are moving from. */
	uint32_t	from;

	/** The mask of the state we're moving from. */
	uint32_t	from_mask;

	/** The state we are moving to. */
	uint32_t	to;

	/** A mask of the keys that the 'to' state should have set. */
	uint32_t	to_mask;

	/** Things we may need to do on this transition. */
	int		flags;
};

#define	WATCHMAN_TRANS_INIT	0x02	/* May need to initialise the class. */
#define	WATCHMAN_TRANS_CLEANUP	0x04	/* Clean up the class now. */

/**
 * A set of permissible state transitions for an automata instance.
 *
 * An automaton must take exactly one of these transitions.
 */
struct watchman_transitions {
	/** The number of possible transitions in @ref #transitions. */
	uint32_t		 length;

	/** Possible transitions: exactly one must be taken. */
	struct watchman_transition	*transitions;
};

#define	WATCHMAN_KEY_SIZE		4

/**
 * A WATCHMAN instance can be identified by a @ref watchman_class and a
 * @ref watchman_key. This key represents the values of event parameters (e.g. a
 * credential passed to a security check), some of which may not be specified.
 *
 * Clients can use @ref watchman_key to look up sets of automata instances, using
 * the bitmask to specify don't-care parameters.
 *
 * Keys can hold arbitrary integers/pointers.
 */
struct watchman_key {
	/** The keys / event parameters that name this automata instance. */
	uintptr_t	tk_keys[WATCHMAN_KEY_SIZE];

	/** A bitmask of the keys that are actually set. */
	uint32_t	tk_mask;

	/** A bitmask of free variables (something is set, don't know what). */
	uint32_t	tk_freemask;
};


/**
 * Update all automata instances that match a given key to a new state.
 *
 * @param  context      where the automaton is stored
 * @param  automaton    static description of the automaton
 * @param  symbol       identifier of the input symbol (event) to be consumed
 * @param  pattern      the name extracted from the event
 */
void	watchman_update_state(enum watchman_context context,
	const struct watchman_automaton *automaton,
	uint32_t symbol, const struct watchman_key *pattern);

/**
 * We have encountered an entry bound for some automata.
 *
 * @param  context      Where the automaton is stored.
 * @param  l            Static description of the lifetime (begin, end events).
 */
void	watchman_sunrise(enum watchman_context context,
	const struct watchman_lifetime *l);

/** We have encountered an exit bound for some automata. */
void	watchman_sunset(enum watchman_context context,
	const struct watchman_lifetime*);


/** A single instance of an automaton: a name (@ref ti_key) and a state. */
struct watchman_instance {
	struct watchman_key	ti_key;
	uint32_t		ti_state;
};


/*
 * Event notification:
 */
/** An initialisation event has occurred; entering an automaton lifetime. */
typedef void	(*watchman_ev_sunrise)(enum watchman_context,
	    const struct watchman_lifetime *);

/** A cleanup event has occurred; exiting an automaton lifetime. */
typedef void	(*watchman_ev_sunset)(enum watchman_context,
	    const struct watchman_lifetime *);

/** A new @ref watchman_instance has been created. */
typedef void	(*watchman_ev_new_instance)(struct watchman_class *,
	    struct watchman_instance *);

/** A @ref watchman_instance has taken a transition. */
typedef void	(*watchman_ev_transition)(struct watchman_class *,
	    struct watchman_instance *, const struct watchman_transition*);

/** An exisiting @ref watchman_instance has been cloned because of an event. */
typedef void	(*watchman_ev_clone)(struct watchman_class *,
	    struct watchman_instance *orig, struct watchman_instance *copy,
	    const struct watchman_transition*);

/** No @ref watchman_class instance was found to match a @ref watchman_key. */
typedef void	(*watchman_ev_no_instance)(struct watchman_class *,
	    uint32_t symbol, const struct watchman_key *);

/** A @ref watchman_instance is not in the right state to take a transition. */
typedef void	(*watchman_ev_bad_transition)(struct watchman_class *,
	    struct watchman_instance *, uint32_t symbol);

/** Generic error handler. */
typedef void	(*watchman_ev_error)(const struct watchman_automaton *,
	    uint32_t symbol, int32_t errnum, const char *message);

/** A @ref watchman_instance has accepted a sequence of events. */
typedef void	(*watchman_ev_accept)(struct watchman_class *,
	    struct watchman_instance *);

/** An event is being ignored. */
typedef void	(*watchman_ev_ignored)(const struct watchman_class *,
	    uint32_t symbol, const struct watchman_key *);

/** A vector of event handlers. */
struct watchman_event_handlers {
	watchman_ev_sunrise	teh_sunrise;
	watchman_ev_sunset		teh_sunset;
	watchman_ev_new_instance	teh_init;
	watchman_ev_transition	teh_transition;
	watchman_ev_clone		teh_clone;
	watchman_ev_no_instance	teh_fail_no_instance;
	watchman_ev_bad_transition	teh_bad_transition;
	watchman_ev_error		teh_err;
	watchman_ev_accept		teh_accept;
	watchman_ev_ignored	teh_ignored;
};

/**
 * A 'meta-handler' that wraps a number of event handling vectors.
 *
 * This event handler dispatches events to any number of backends, governed
 * by @a tem_mask: if bit 0 is set, tem_handler[0] is called, etc.
 */
struct watchman_event_metahandler {
	/** The number of event handlers wrapped by this handler. */
	const uint32_t	tem_length;

	/** Which backend handlers to use; may be modified dynamically. */
	uint32_t	tem_mask;

	/** The backend event handlers. */
	const struct watchman_event_handlers* const *tem_handlers;
};

/** Register an event handler vector. */
int	watchman_set_event_handler(struct watchman_event_handlers *);

/** Register a set of event handling vectors. */
int	watchman_set_event_handlers(struct watchman_event_metahandler *);

/** The type for printf handler functions */
typedef uint32_t(*printf_type)(const char *, ...);

/** The function that will be called to log messages. */
extern printf_type __watchman_printf;

#ifdef _KERNEL
#define	WATCHMAN_KERN_PRINTF_EV	0x1
#define	WATCHMAN_KERN_PRINTERR_EV	0x2
#define	WATCHMAN_KERN_DTRACE_EV	0x4
#define	WATCHMAN_KERN_PANIC_EV	0x8
#endif

/** @} */

__END_DECLS

#endif /* _WATCHMAN_H */
