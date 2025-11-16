#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "../register_ta.h"

#define TG_MAX_CORES   4
#define TRACE_WINDOW   32  /* for SchedTrace sliding window */

/* MRU state */
static int32_t g_mru_core = -1;

/* Random policy state (simple xorshift) */
static uint64_t g_rand_state = 0x123456789ABCDEF0ULL;

/* Frequency policy state */
static uint32_t g_freq_count[TG_MAX_CORES] = {0};

/* SchedTrace sliding window state */
static int8_t schedtrace_window[TRACE_WINDOW];
static int    schedtrace_pos    = 0;
static int    schedtrace_filled = 0;

/* Clamp core id into [0, TG_MAX_CORES-1] */
typedef struct {
	uint64_t proxy_id;
	bool registered;
} sess_ctx_t;

static volatile uint32_t g_trust_ok = 1; // watchdog will update later

static const int64_t ERROR_THRESHOLD_NS = 462692; // 0.4 milliseconds

static const int64_t PASSIVE_ERROR = 100000; // placeholder

static int32_t tg_clamp_core(int32_t c)
{
    if (c < 0) return 0;
    if (c >= TG_MAX_CORES) return TG_MAX_CORES - 1;
    return c;
}

static uint32_t tg_rand32(void)
{
    uint32_t x = (uint32_t)g_rand_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rand_state = x;
    return x;
}


static uint64_t rand_u64(void) {
	uint64_t x = 0;
	TEE_GenerateRandom(&x, sizeof(x));
	return x ? x : 0xA5A5A5A5DEADBEEFULL; // avoid zero id
}

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptypes, TEE_Param params[4], void **sess_ctx) {
	(void)ptypes; (void)params;
	sess_ctx_t *s = TEE_Malloc(sizeof(*s), TEE_MALLOC_FILL_ZERO);
	if (!s) return TEE_ERROR_OUT_OF_MEMORY;
	*sess_ctx = s;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
	if (sess_ctx) TEE_Free(sess_ctx);
}

static TEE_Result cmd_register(sess_ctx_t *s, uint32_t ptypes, TEE_Param params[4]) {
	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
	                    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	// Very simple secret check (replace with HUK/KDF later)
	const struct tg_register_in *in = params[0].memref.buffer;
	if (params[0].memref.size != sizeof(*in)) return TEE_ERROR_BAD_PARAMETERS;

	// (Optional) verify in->device_secret matches provisioned secret…
	// For now accept anything for bring-up.

	struct tg_register_out *out = params[1].memref.buffer;
	if (params[1].memref.size < sizeof(*out)) return TEE_ERROR_SHORT_BUFFER;

	s->proxy_id = rand_u64();
	s->registered = true;

	out->proxy_hi = (uint32_t)(s->proxy_id >> 32);
	out->proxy_lo = (uint32_t)(s->proxy_id & 0xffffffffu);

	// Initialize trust_ok to 1 on first registration
	g_trust_ok = 1;
	return TEE_SUCCESS;
}

static TEE_Result cmd_get_trust(uint32_t ptypes, TEE_Param params[4]) {
	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
	                    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	struct tg_trust_out *out = params[0].memref.buffer;
	if (params[0].memref.size < sizeof(*out)) return TEE_ERROR_SHORT_BUFFER;
	out->trust_ok = g_trust_ok ? 1u : 0u;
	return TEE_SUCCESS;
}

static TEE_Result cmd_get_secure_time(uint32_t ptypes, TEE_Param params[4])
{
	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
	                    TEE_PARAM_TYPE_NONE,
	                    TEE_PARAM_TYPE_NONE,
	                    TEE_PARAM_TYPE_NONE) != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	struct tg_time_out *out = params[0].memref.buffer;
	if (params[0].memref.size < sizeof(*out))
		return TEE_ERROR_SHORT_BUFFER;

	TEE_Time t;
	TEE_GetTAPersistentTime(&t);


	out->seconds     = (uint64_t)t.seconds;
	/* TEE_Time gives milliseconds; convert to nanoseconds */
	out->nanoseconds = (uint32_t)t.millis * 1000000u;

	return TEE_SUCCESS;
}

static TEE_Result cmd_watchdog_error(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
		                TEE_PARAM_TYPE_MEMREF_OUTPUT,
		                TEE_PARAM_TYPE_NONE,
		                TEE_PARAM_TYPE_NONE);

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

  if (params[0].memref.size != sizeof(struct tg_watchdog_error_in) ||
      params[1].memref.size != sizeof(struct tg_watchdog_error_out))
      return TEE_ERROR_BAD_PARAMETERS;
	struct tg_watchdog_error_in *in =
		(struct tg_watchdog_error_in *)params[0].memref.buffer;

	struct tg_watchdog_error_out *out =
    (struct tg_watchdog_error_out *)params[1].memref.buffer;

	int64_t phc = in->err_ns;
	

	TEE_Time st;
	TEE_GetTAPersistentTime(&st);

	int64_t secure_ns = (int64_t)((uint64_t)st.seconds * 1000000000LL) + (int64_t)((uint32_t)st.millis * 1000000u);


	int64_t err = (phc - secure_ns) - ERROR_THRESHOLD_NS;

	int64_t sec  = err / 1000000000LL;
  int64_t nsec = err % 1000000000LL;

  if (nsec < 0) {
  	sec  -= 1;
    nsec += 1000000000LL;
  }

  out->seconds     = sec;
  out->nanoseconds = (int32_t)nsec;

	/* If |error| > threshold, mark trust as broken */
	if (err > ERROR_THRESHOLD_NS || err < -ERROR_THRESHOLD_NS) {
		g_trust_ok = 0;
	}

	return TEE_SUCCESS;
}

static TEE_Result cmd_set_baseline_time(uint32_t ptypes,
                                        TEE_Param params[4])
{
    if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE) != ptypes)
        return TEE_ERROR_BAD_PARAMETERS;

    struct tg_set_time_in *in = params[0].memref.buffer;
    if (params[0].memref.size < sizeof(*in))
        return TEE_ERROR_SHORT_BUFFER;

    TEE_Time t;
    t.seconds = in->phc_seconds;
    t.millis  = in->phc_nanoseconds / 1000000; // ns → ms

    TEE_Result r = TEE_SetTAPersistentTime(&t);
    if (r != TEE_SUCCESS)
        return r;


    return TEE_SUCCESS;
}

static TEE_Result tg_compute_base_diff(int64_t phc_ns,
                                       int32_t actual_core,
                                       int32_t predicted_core,
                                       int64_t *out_diff_ns)
{
    TEE_Time t;
    TEE_Result r = TEE_GetTAPersistentTime(&t);
    if (r != TEE_SUCCESS)
        return r;

    int64_t secure_ns =
        (int64_t)(uint64_t)t.seconds * 1000000000LL +
        (int64_t)(uint32_t)t.millis * 1000000LL;

    int64_t secure_adj = secure_ns;
    /* IPI penalty only if policy mispredicted the core */
    if (predicted_core != actual_core) {
        secure_adj -= 54780; // extra latency from IPI interrupt across all cores
    }
    else {
        secure_adj -= 27435; // baseline passive mode overhead
    }

    *out_diff_ns = (phc_ns - secure_adj) - PASSIVE_ERROR;
    return TEE_SUCCESS;
}


static int32_t schedtrace_predict(void)
{
    if (schedtrace_filled == 0)
        return -1;  /* cold start */

    uint32_t freq[TG_MAX_CORES] = {0};

    for (int i = 0; i < schedtrace_filled; i++) {
        int8_t c = schedtrace_window[i];
        if (c >= 0 && c < TG_MAX_CORES)
            freq[c]++;
    }

    int32_t best_core = 0;
    uint32_t best_cnt = freq[0];

    for (int i = 1; i < TG_MAX_CORES; i++) {
        if (freq[i] > best_cnt) {
            best_cnt = freq[i];
            best_core = i;
        }
    }
    return best_core;
}


static TEE_Result cmd_passive_mru(uint32_t ptypes, TEE_Param params[4])
{
    const uint32_t exp =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (ptypes != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size != sizeof(struct tg_passive_policy_in) ||
        params[1].memref.size != sizeof(struct tg_passive_policy_out))
        return TEE_ERROR_BAD_PARAMETERS;

    struct tg_passive_policy_in  *in  = params[0].memref.buffer;
    struct tg_passive_policy_out *out = params[1].memref.buffer;

    int32_t actual_core = tg_clamp_core(in->core_id);

    int32_t predicted_core;
    if (g_mru_core < 0)
        predicted_core = actual_core; /* cold start */
    else
        predicted_core = g_mru_core;

    int64_t base_diff_ns;
    TEE_Result r = tg_compute_base_diff(in->phc_ns,
                                        actual_core,
                                        predicted_core,
                                        &base_diff_ns);
    if (r != TEE_SUCCESS)
        return r;

    out->base_diff_ns = base_diff_ns;

    /* update MRU */
    g_mru_core = actual_core;

    return TEE_SUCCESS;
}

static TEE_Result cmd_passive_random(uint32_t ptypes, TEE_Param params[4])
{
    const uint32_t exp =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (ptypes != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size != sizeof(struct tg_passive_policy_in) ||
        params[1].memref.size != sizeof(struct tg_passive_policy_out))
        return TEE_ERROR_BAD_PARAMETERS;

    struct tg_passive_policy_in  *in  = params[0].memref.buffer;
    struct tg_passive_policy_out *out = params[1].memref.buffer;

    int32_t actual_core = tg_clamp_core(in->core_id);

    int32_t predicted_core = tg_rand32() % TG_MAX_CORES;

    int64_t base_diff_ns;
    TEE_Result r = tg_compute_base_diff(in->phc_ns,
                                        actual_core,
                                        predicted_core,
                                        &base_diff_ns);
    if (r != TEE_SUCCESS)
        return r;

    out->base_diff_ns = base_diff_ns;
    return TEE_SUCCESS;
}

static TEE_Result cmd_passive_freq(uint32_t ptypes, TEE_Param params[4])
{
    const uint32_t exp =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (ptypes != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size != sizeof(struct tg_passive_policy_in) ||
        params[1].memref.size != sizeof(struct tg_passive_policy_out))
        return TEE_ERROR_BAD_PARAMETERS;

    struct tg_passive_policy_in  *in  = params[0].memref.buffer;
    struct tg_passive_policy_out *out = params[1].memref.buffer;

    int32_t actual_core = tg_clamp_core(in->core_id);

    /* choose core with max historical count */
    int32_t predicted_core = 0;
    uint32_t best = g_freq_count[0];

    for (int i = 1; i < TG_MAX_CORES; i++) {
        if (g_freq_count[i] > best) {
            best = g_freq_count[i];
            predicted_core = i;
        }
    }

    int64_t base_diff_ns;
    TEE_Result r = tg_compute_base_diff(in->phc_ns,
                                        actual_core,
                                        predicted_core,
                                        &base_diff_ns);
    if (r != TEE_SUCCESS)
        return r;

    out->base_diff_ns = base_diff_ns;

    /* update frequency counts */
    g_freq_count[actual_core]++;

    return TEE_SUCCESS;
}

static TEE_Result cmd_passive_schedtrace(uint32_t ptypes, TEE_Param params[4])
{
    const uint32_t exp =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (ptypes != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size != sizeof(struct tg_passive_policy_in) ||
        params[1].memref.size != sizeof(struct tg_passive_policy_out))
        return TEE_ERROR_BAD_PARAMETERS;

    struct tg_passive_policy_in  *in  = params[0].memref.buffer;
    struct tg_passive_policy_out *out = params[1].memref.buffer;

    int32_t actual_core = tg_clamp_core(in->core_id);

    int32_t predicted_core = schedtrace_predict();
    if (predicted_core < 0)
        predicted_core = actual_core; /* cold start */

    int64_t base_diff_ns;
    TEE_Result r = tg_compute_base_diff(in->phc_ns,
                                        actual_core,
                                        predicted_core,
                                        &base_diff_ns);
    if (r != TEE_SUCCESS)
        return r;

    out->base_diff_ns = base_diff_ns;

    /* update sliding window trace */
    schedtrace_update(actual_core);

    return TEE_SUCCESS;
}




TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t ptypes, TEE_Param params[4]) {
	sess_ctx_t *s = (sess_ctx_t *)sess_ctx;
	switch (cmd_id) {
	case TG_CMD_REGISTER:  return cmd_register(s, ptypes, params);
	case TG_CMD_GET_TRUST: return cmd_get_trust(ptypes, params);
	case TG_CMD_GET_SECURE_TIME: return cmd_get_secure_time(ptypes, params);
	case TG_CMD_WATCHDOG_ERROR: return cmd_watchdog_error(ptypes, params);
	case TG_CMD_SET_TIME: return cmd_set_baseline_time(ptypes, params);
  case TG_CMD_PASSIVE_MRU:
        return cmd_passive_mru(ptypes, params);
  case TG_CMD_PASSIVE_RANDOM:
        return cmd_passive_random(ptypes, params);
  case TG_CMD_PASSIVE_FREQ:
        return cmd_passive_freq(ptypes, params);
  case TG_CMD_PASSIVE_SCHEDTRACE:
        return cmd_passive_schedtrace(ptypes, params);
	default:               return TEE_ERROR_NOT_SUPPORTED;
	}
}
