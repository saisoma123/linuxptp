// SPDX-License-Identifier: BSD-2-Clause
/*
 * bmca_ta.c — OP-TEE TA for BMCA decision
 *
 * This TA receives a snapshot of BMCA-relevant state from the host
 * (foreign datasets + scalars), constructs the local default dataset
 * securely, runs a comparator-equivalent BMCA decision, and returns
 * a decided port_state as a single byte.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "bmca_ta.h"
#include <trace.h>
#include "fsm.h"

/* =========================
 * Enum values – ADJUST THESE
 * =========================
 * Make sure these match your host's enum port_state and BMCA mode values.
 * (If you share a header with exact values, include that here instead.)
 */
#define PS_LISTENING 4
#define PS_MASTER 6
#define PS_PASSIVE 7
#define PS_SLAVE 9
#define PS_GRAND_MASTER 10 /* your tree has a distinct value */
/* Some trees define PS_GRAND_MASTER distinct; others alias to PS_MASTER.
 * If your code expects a distinct "grand master" state, set it here.
 * Otherwise set PS_GRAND_MASTER == PS_MASTER.
 */

/* BMCA_NOOP value must match host's (used in early-return path). */
#define BMCA_NOOP 1 /* adjust to your tree */

/* Return codes consistent with linuxptp logic. */
#define A_BETTER_TOPO 2
#define A_BETTER 1
#define B_BETTER -1
#define B_BETTER_TOPO -2

/* =========================
 * Secure DefaultDS (stub)
 * =========================
 * In production, provision these into secure storage, or set them from
 * a secure commissioning flow. For now, we keep them as TA-internal
 * statics initialized at TA start.
 */
static struct
{
	uint8_t priority1;
	uint8_t priority2;
	struct BmcaClockQuality quality;
	uint8_t identity[8];
} g_secure_defaultds;

/* Build local clock_ds from secure DefaultDS */
static void make_clock_ds(struct BmcaDataset *out)
{
	TEE_MemFill(out, 0, sizeof(*out));
	TEE_MemMove(out->identity, g_secure_defaultds.identity, sizeof(out->identity));
	out->priority1 = g_secure_defaultds.priority1;
	out->priority2 = g_secure_defaultds.priority2;
	out->quality = g_secure_defaultds.quality;

	/* BMCA invariants for default DS */
	out->stepsRemoved = 0;
	TEE_MemMove(out->sender.clockIdentity, g_secure_defaultds.identity, 8);
	out->sender.portNumber = 0;
	TEE_MemMove(out->receiver.clockIdentity, g_secure_defaultds.identity, 8);
	out->receiver.portNumber = 0;
	IMSG("BMCA TA DS method finished");
}

/* =========================
 * Comparators on wire structs
 * ========================= */

static int portid_cmp(const struct BmcaPortIdentity *a,
											const struct BmcaPortIdentity *b)
{
	int diff = TEE_MemCompare(a->clockIdentity, b->clockIdentity, 8);
	if (diff == 0)
	{
		/* promote to signed int to avoid uint wrap surprises */
		int pa = (int)a->portNumber;
		int pb = (int)b->portNumber;
		diff = (pa - pb);
	}
	return diff;
}

static int dscmp2(const struct BmcaDataset *a,
									const struct BmcaDataset *b)
{
	int diff;
	unsigned int A = a ? a->stepsRemoved : 0U;
	unsigned int B = b ? b->stepsRemoved : 0U;

	if (A + 1 < B)
		return A_BETTER;
	if (B + 1 < A)
		return B_BETTER;

	/* error-1 cases: retain topology tie-breaks */
	if (A < B)
	{
		diff = portid_cmp(&b->receiver, &b->sender);
		if (diff < 0)
			return A_BETTER;
		if (diff > 0)
			return A_BETTER_TOPO;
		return 0; /* error-1 */
	}
	if (A > B)
	{
		diff = portid_cmp(&a->receiver, &a->sender);
		if (diff < 0)
			return B_BETTER;
		if (diff > 0)
			return B_BETTER_TOPO;
		return 0; /* error-1 */
	}

	diff = portid_cmp(&a->sender, &b->sender);
	if (diff < 0)
		return A_BETTER_TOPO;
	if (diff > 0)
		return B_BETTER_TOPO;

	if (a->receiver.portNumber < b->receiver.portNumber)
		return A_BETTER_TOPO;
	if (a->receiver.portNumber > b->receiver.portNumber)
		return B_BETTER_TOPO;

	/* error-2 */
	return 0;
}

static int dscmp(const struct BmcaDataset *a,
								 const struct BmcaDataset *b)
{
	int diff;

	if (a == b)
		return 0;
	if (a && !b)
		return A_BETTER;
	if (b && !a)
		return B_BETTER;

	diff = TEE_MemCompare(a->identity, b->identity, sizeof(a->identity));
	if (!diff)
		return dscmp2(a, b);

	if (a->priority1 < b->priority1)
		return A_BETTER;
	if (a->priority1 > b->priority1)
		return B_BETTER;

	if (a->quality.clockClass < b->quality.clockClass)
		return A_BETTER;
	if (a->quality.clockClass > b->quality.clockClass)
		return B_BETTER;

	if (a->quality.clockAccuracy < b->quality.clockAccuracy)
		return A_BETTER;
	if (a->quality.clockAccuracy > b->quality.clockAccuracy)
		return B_BETTER;

	if (a->quality.offsetScaledLogVariance <
			b->quality.offsetScaledLogVariance)
		return A_BETTER;
	if (a->quality.offsetScaledLogVariance >
			b->quality.offsetScaledLogVariance)
		return B_BETTER;

	if (a->priority2 < b->priority2)
		return A_BETTER;
	if (a->priority2 > b->priority2)
		return B_BETTER;

	/* final tie-breaker is identity ordering */
	return diff < 0 ? A_BETTER : B_BETTER;
}

/* =========================
 * BMCA decision core (TA)
 * =========================
 * Mirrors the host logic, but works on BmcaDataset and scalar inputs.
 */
static uint8_t bmca_decide(const struct BmcaInput *in)
{
	struct BmcaDataset clock_ds;
	const struct BmcaDataset *clock_best = in->has_clock_best ? &in->clock_best : NULL;
	const struct BmcaDataset *port_best = in->has_port_best ? &in->port_best : NULL;
	uint8_t ps = in->current_port_state;

	/* Build local dataset from secure defaults */
	make_clock_ds(&clock_ds);
	IMSG("BMCA TA DS worked");

	/* Early return paths (match host bmc_state_decision) */
	if (!port_best && in->bmca_mode == BMCA_NOOP)
		return ps;

	if (!port_best && ps == PS_LISTENING)
		return ps;

	/* Primary decision branches */
	if (in->clock_class <= 127)
	{
		if (dscmp(&clock_ds, port_best) > 0)
			return PS_GRAND_MASTER; /* M1 */
		else
			return PS_PASSIVE; /* P1 */
	}

	if (dscmp(&clock_ds, clock_best) > 0)
		return PS_GRAND_MASTER; /* M2 */

	if (in->clock_best_is_this_port)
		return PS_SLAVE; /* S1 */

	if (dscmp(clock_best, port_best) == A_BETTER_TOPO)
		return PS_PASSIVE; /* P2 */
	else
		return PS_MASTER; /* M3 */
}


static uint8_t ta_run_ptp_fsm(const struct BmcaFsmInput *in)
{
    enum port_state state = (enum port_state)in->state;
    enum fsm_event  event    = (enum fsm_event)in->event;
    int             mdiff = (int)in->mdiff;

    enum port_state next = state;
		if (EV_INITIALIZE == event || EV_POWERUP == event)
		return PS_INITIALIZING;

	switch (state) {
	case PS_INITIALIZING:
		switch (event) {
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_INIT_COMPLETE:
			next = PS_LISTENING;
			break;
		default:
			break;
		}
		break;

	case PS_FAULTY:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_CLEARED:
			next = PS_INITIALIZING;
			break;
		default:
			break;
		}
		break;

	case PS_DISABLED:
		if (EV_DESIGNATED_ENABLED == event)
			next = PS_INITIALIZING;
		break;

	case PS_LISTENING:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES:
			next = PS_MASTER;
			break;
		case EV_RS_MASTER:
			next = PS_PRE_MASTER;
			break;
		case EV_RS_GRAND_MASTER:
			next = PS_GRAND_MASTER;
			break;
		case EV_RS_SLAVE:
			next = PS_UNCALIBRATED;
			break;
		case EV_RS_PASSIVE:
			next = PS_PASSIVE;
			break;
		default:
			break;
		}
		break;

	case PS_PRE_MASTER:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_QUALIFICATION_TIMEOUT_EXPIRES:
			next = PS_MASTER;
			break;
		case EV_RS_SLAVE:
			next = PS_UNCALIBRATED;
			break;
		case EV_RS_PASSIVE:
			next = PS_PASSIVE;
			break;
		default:
			break;
		}
		break;

	case PS_MASTER:
	case PS_GRAND_MASTER:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_RS_SLAVE:
			next = PS_UNCALIBRATED;
			break;
		case EV_RS_PASSIVE:
			next = PS_PASSIVE;
			break;
		default:
			break;
		}
		break;

	case PS_PASSIVE:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES:
			next = PS_MASTER;
			break;
		case EV_RS_MASTER:
			next = PS_PRE_MASTER;
			break;
		case EV_RS_GRAND_MASTER:
			next = PS_GRAND_MASTER;
			break;
		case EV_RS_SLAVE:
			next = PS_UNCALIBRATED;
			break;
		default:
			break;
		}
		break;

	case PS_UNCALIBRATED:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES:
			next = PS_MASTER;
			break;
		case EV_MASTER_CLOCK_SELECTED:
			next = PS_SLAVE;
			break;
		case EV_RS_MASTER:
			next = PS_PRE_MASTER;
			break;
		case EV_RS_GRAND_MASTER:
			next = PS_GRAND_MASTER;
			break;
		case EV_RS_SLAVE:
			next = PS_UNCALIBRATED;
			break;
		case EV_RS_PASSIVE:
			next = PS_PASSIVE;
			break;
		default:
			break;
		}
		break;

	case PS_SLAVE:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES:
			next = PS_MASTER;
			break;
		case EV_SYNCHRONIZATION_FAULT:
			next = PS_UNCALIBRATED;
			break;
		case EV_RS_MASTER:
			next = PS_PRE_MASTER;
			break;
		case EV_RS_GRAND_MASTER:
			next = PS_GRAND_MASTER;
			break;
		case EV_RS_SLAVE:
			if (mdiff)
				next = PS_UNCALIBRATED;
			break;
		case EV_RS_PASSIVE:
			next = PS_PASSIVE;
			break;
		default:
			break;
		}
		break;
	}

    return (uint8_t)next;
}

static uint8_t ta_run_ptp_slave_fsm(const struct BmcaFsmInput *in)
{
    enum port_state state = (enum port_state)in->state;
    enum fsm_event  event    = (enum fsm_event)in->event;
    int             mdiff = (int)in->mdiff;

    enum port_state next = state;
		if (EV_INITIALIZE == event || EV_POWERUP == event)
		return PS_INITIALIZING;

	switch (state) {
	case PS_INITIALIZING:
		switch (event) {
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_INIT_COMPLETE:
			next = PS_LISTENING;
			break;
		default:
			break;
		}
		break;

	case PS_FAULTY:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_CLEARED:
			next = PS_INITIALIZING;
			break;
		default:
			break;
		}
		break;

	case PS_DISABLED:
		if (EV_DESIGNATED_ENABLED == event)
			next = PS_INITIALIZING;
		break;

	case PS_LISTENING:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES:
		case EV_RS_MASTER:
		case EV_RS_GRAND_MASTER:
		case EV_RS_PASSIVE:
			next = PS_LISTENING;
			break;
		case EV_RS_SLAVE:
			next = PS_UNCALIBRATED;
			break;
		default:
			break;
		}
		break;

	case PS_UNCALIBRATED:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES:
		case EV_RS_MASTER:
		case EV_RS_GRAND_MASTER:
		case EV_RS_PASSIVE:
			next = PS_LISTENING;
			break;
		case EV_MASTER_CLOCK_SELECTED:
			next = PS_SLAVE;
			break;
		default:
			break;
		}
		break;

	case PS_SLAVE:
		switch (event) {
		case EV_DESIGNATED_DISABLED:
			next = PS_DISABLED;
			break;
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES:
		case EV_RS_MASTER:
		case EV_RS_GRAND_MASTER:
		case EV_RS_PASSIVE:
			next = PS_LISTENING;
			break;
		case EV_SYNCHRONIZATION_FAULT:
			next = PS_UNCALIBRATED;
			break;
		case EV_RS_SLAVE:
			if (mdiff)
				next = PS_UNCALIBRATED;
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}

    return (uint8_t)next;
}

/* =========================
 * TA Entry Points
 * ========================= */

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
																		TEE_Param __unused params[4],
																		void **sess_ctx __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
																						 TEE_PARAM_TYPE_NONE,
																						 TEE_PARAM_TYPE_NONE,
																						 TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* No per-session state required for BMCA */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
	/* Nothing to free — stateless TA session */
}

/* Command dispatcher */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
																			uint32_t cmd_id,
																			uint32_t param_types,
																			TEE_Param params[4])
{
	switch (cmd_id)
	{
	case TA_BMCA_CMD_DECIDE:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
																	 TEE_PARAM_TYPE_MEMREF_OUTPUT,
																	 TEE_PARAM_TYPE_NONE,
																	 TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		if (!params[0].memref.buffer || !params[1].memref.buffer)
			return TEE_ERROR_BAD_PARAMETERS;

		if (params[0].memref.size < sizeof(struct BmcaInput) ||
				params[1].memref.size < sizeof(struct BmcaOutput))
			return TEE_ERROR_SHORT_BUFFER;

		const struct BmcaInput *in = (const struct BmcaInput *)params[0].memref.buffer;
		struct BmcaOutput *out = (struct BmcaOutput *)params[1].memref.buffer;

		/* Optional hardening */
		TEE_MemFill(out, 0, params[1].memref.size);

		out->decided_state = bmca_decide(in);

		/* Tell host how many bytes we wrote */
		params[1].memref.size = sizeof(struct BmcaOutput);
		IMSG("BMCA TA decide ran");
		return TEE_SUCCESS;
	}
	case TA_BMCA_CMD_SET_DEFAULT_DS:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
																	 TEE_PARAM_TYPE_NONE,
																	 TEE_PARAM_TYPE_NONE,
																	 TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		if (!params[0].memref.buffer ||
				params[0].memref.size < sizeof(struct BmcaDefaultDS))
			return TEE_ERROR_SHORT_BUFFER;

		const struct BmcaDefaultDS *d =
				(const struct BmcaDefaultDS *)params[0].memref.buffer;

		/* Commit to secure defaults */
		g_secure_defaultds.priority1 = d->priority1;
		g_secure_defaultds.priority2 = d->priority2;
		g_secure_defaultds.quality = d->quality;
		TEE_MemMove(g_secure_defaultds.identity, d->identity, sizeof(d->identity));
		IMSG("BMCA default ran");
		return TEE_SUCCESS;
	}

	case TA_BMCA_CMD_PING:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, 0, 0, 0);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		params[0].value.a = 0xBAAA; /* magic */
		return TEE_SUCCESS;
	}

	case TA_BMCA_CMD_PTP_FSM:
    {
        uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE);
        if (param_types != exp)
            return TEE_ERROR_BAD_PARAMETERS;

        if (!params[0].memref.buffer || !params[1].memref.buffer)
            return TEE_ERROR_BAD_PARAMETERS;

        if (params[0].memref.size < sizeof(struct BmcaFsmInput) ||
            params[1].memref.size < sizeof(struct BmcaFsmOutput))
            return TEE_ERROR_SHORT_BUFFER;

        const struct BmcaFsmInput *in =
            (const struct BmcaFsmInput *)params[0].memref.buffer;
        struct BmcaFsmOutput *out =
            (struct BmcaFsmOutput *)params[1].memref.buffer;

        TEE_MemFill(out, 0, params[1].memref.size);

        out->next_state = ta_run_ptp_fsm(in);
        params[1].memref.size = sizeof(struct BmcaFsmOutput);

        IMSG("BMCA TA PTP_FSM ran (state=%u ev=%u mdiff=%d -> next=%u)",
             in->state, in->event, in->mdiff, out->next_state);

        return TEE_SUCCESS;
    }

    case TA_BMCA_CMD_PTP_SLAVE_FSM:
    {
        uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE);
        if (param_types != exp)
            return TEE_ERROR_BAD_PARAMETERS;

        if (!params[0].memref.buffer || !params[1].memref.buffer)
            return TEE_ERROR_BAD_PARAMETERS;

        if (params[0].memref.size < sizeof(struct BmcaFsmInput) ||
            params[1].memref.size < sizeof(struct BmcaFsmOutput))
            return TEE_ERROR_SHORT_BUFFER;

        const struct BmcaFsmInput *in =
            (const struct BmcaFsmInput *)params[0].memref.buffer;
        struct BmcaFsmOutput *out =
            (struct BmcaFsmOutput *)params[1].memref.buffer;

        TEE_MemFill(out, 0, params[1].memref.size);

        out->next_state = ta_run_ptp_slave_fsm(in);
        params[1].memref.size = sizeof(struct BmcaFsmOutput);

        IMSG("BMCA TA PTP_SLAVE_FSM ran (state=%u ev=%u mdiff=%d -> next=%u)",
             in->state, in->event, in->mdiff, out->next_state);

        return TEE_SUCCESS;
    }

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
