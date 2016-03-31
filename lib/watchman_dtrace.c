/*-
 * Copyright (c) 2013 Robert N. M. Watson
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

#ifdef _KERNEL
#include "opt_kdtrace.h"
#include <sys/sdt.h>

SDT_PROVIDER_DEFINE(watchman);

SDT_PROBE_DEFINE2(watchman, automata, lifetime, sunrise, sunrise,
    "enum watchman_context context", "struct watchman_lifetime *");
SDT_PROBE_DEFINE2(watchman, automata, lifetime, sunset, sunset,
    "enum watchman_context context", "struct watchman_lifetime *");
SDT_PROBE_DEFINE2(watchman, automata, instance, create, create,
    "struct watchman_class *", "struct watchman_instance *");
SDT_PROBE_DEFINE3(watchman, automata, event, transition, state-transition,
    "struct watchman_class *", "struct watchman_instance *",
    "struct watchman_transition *");
SDT_PROBE_DEFINE4(watchman, automata, instance, clone, clone,
    "struct watchman_class *", "struct watchman_instance *",
    "struct watchman_instance *", "struct watchman_transition *");
SDT_PROBE_DEFINE4(watchman, automata, fail, no_instance, no-instance-match,
    "struct watchman_class *", "const char *", "uint32_t",
    "struct watchman_transitions *");
SDT_PROBE_DEFINE3(watchman, automata, fail, bad_transition, bad-transition,
    "struct watchman_class *", "struct watchman_instance *",
    "uint32_t");
SDT_PROBE_DEFINE4(watchman, automata, fail, other_err, other-error,
    "struct watchman_class *", "uint32_t", "int32_t", "const char *");
SDT_PROBE_DEFINE2(watchman, automata, success, accept, accept,
    "struct watchman_class *", "struct watchman_instance *");
SDT_PROBE_DEFINE3(watchman, automata, event, ignored, ignored-event,
    "struct watchman_class *", "uint32_t", "struct watchman_key *");

static void
sunrise(enum watchman_context c, const struct watchman_lifetime *tl)
{

	SDT_PROBE(watchman, automata, lifetime, sunrise, c, tl, 0, 0, 0);
}

static void
sunset(enum watchman_context c, const struct watchman_lifetime *tl)
{

	SDT_PROBE(watchman, automata, lifetime, sunset, c, tl, 0, 0, 0);
}

static void
new_instance(struct watchman_class *tcp, struct watchman_instance *tip)
{

	SDT_PROBE(watchman, automata, instance, create, tcp, tip, 0, 0, 0);
}

static void
transition(struct watchman_class *tcp, struct watchman_instance *tip,
    const struct watchman_transition *ttp)
{

	SDT_PROBE(watchman, automata, event, transition, tcp, tip, ttp, 0, 0);
}

static void
clone(struct watchman_class *tcp, struct watchman_instance *origp,
    struct watchman_instance *copyp, const struct watchman_transition *ttp)
{

	SDT_PROBE(watchman, automata, instance, clone, tcp, origp, copyp, ttp, 0);
}

static void
no_instance(struct watchman_class *tcp, uint32_t symbol,
    const struct watchman_key *tkp)
{
	char instbuf[200];
	char *c = instbuf;
	const char *end = instbuf + sizeof(instbuf);

	SAFE_SPRINTF(c, end, "%d/%d instances\n",
		tcp->tc_limit - tcp->tc_free, tcp->tc_limit);

	for (uint32_t i = 0; i < tcp->tc_limit; i++) {
		const struct watchman_instance *inst = tcp->tc_instances + i;
		if (!watchman_instance_active(inst))
			continue;

		SAFE_SPRINTF(c, end, "    %2u: state %d, ", i, inst->ti_state);
		c = key_string(c, end, &inst->ti_key);
		SAFE_SPRINTF(c, end, "\n");
	}

	char keybuf[20];
	key_string(keybuf, keybuf + sizeof(keybuf), tkp);

	SDT_PROBE(watchman, automata, fail, no_instance,
		tcp, instbuf, symbol, keybuf, 0);
}

static void
bad_transition(struct watchman_class *tcp, struct watchman_instance *tip,
    uint32_t symbol)
{

	SDT_PROBE(watchman, automata, fail, bad_transition, tcp, tip, symbol,
		0, 0);
}

static void
err(const struct watchman_automaton *tap, uint32_t symbol, int32_t errnum,
    const char *message)
{

	SDT_PROBE(watchman, automata, fail, other_err,
		tap, symbol, errnum, message, 0);
}

static void
accept(struct watchman_class *tcp, struct watchman_instance *tip)
{

	SDT_PROBE(watchman, automata, success, accept, tcp, tip, 0, 0, 0);
}

static void
ignored(const struct watchman_class *tcp, uint32_t symbol,
    const struct watchman_key *tkp)
{

	SDT_PROBE(watchman, automata, event, ignored, tcp, symbol, tkp, 0, 0);
}

const struct watchman_event_handlers dtrace_handlers = {
	.weh_sunrise			= sunrise,
	.weh_sunset			= sunset,
	.weh_init			= new_instance,
	.weh_transition			= transition,
	.weh_clone			= clone,
	.weh_fail_no_instance		= no_instance,
	.weh_bad_transition		= bad_transition,
	.weh_err			= err,
	.weh_accept			= accept,
	.weh_ignored			= ignored,
};

#endif /* _KERNEL */
