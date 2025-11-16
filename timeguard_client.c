#include <tee_client_api.h>
#include "timeguard_client.h"
#include "trusted_applications/register_ta.h"
#include "print.h"


static TEEC_Context g_ctx;
static TEEC_Session g_sess;
static uint64_t g_proxy_id;

bool tg_register(const uint8_t device_secret[32]) {
	TEEC_Result r;
	TEEC_UUID uuid = TA_TIMEGUARD_UUID;
	r = TEEC_InitializeContext(NULL, &g_ctx); if (r) return false;
	r = TEEC_OpenSession(&g_ctx, &g_sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
	if (r) return false;

	struct tg_register_in in = {0};
	if (device_secret) __builtin_memcpy(in.device_secret, device_secret, 32);

	struct tg_register_out out = {0};
	TEEC_Operation op = {0};
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
	                                 TEEC_MEMREF_TEMP_OUTPUT,
	                                 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = &in;
	op.params[0].tmpref.size   = sizeof(in);
	op.params[1].tmpref.buffer = &out;
	op.params[1].tmpref.size   = sizeof(out);

	r = TEEC_InvokeCommand(&g_sess, TG_CMD_REGISTER, &op, NULL);
	if (r) return false;

	g_proxy_id = ((uint64_t)out.proxy_hi << 32) | out.proxy_lo;
	return true;
}

bool tg_get_trust(uint8_t *trust_ok) {
	if (!trust_ok) return false;
	struct tg_trust_out out = {0};
	TEEC_Operation op = {0};
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
	                                 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = &out;
	op.params[0].tmpref.size   = sizeof(out);
	TEEC_Result r = TEEC_InvokeCommand(&g_sess, TG_CMD_GET_TRUST, &op, NULL);
	if (r) return false;
	*trust_ok = (uint8_t)(out.trust_ok ? 1 : 0);
	return true;
}

bool tg_get_secure_time(struct tg_time_out *out_time)
{
	if (!out_time)
		return false;

	struct tg_time_out out = {0};
	TEEC_Operation op = {0};

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
	                                 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = &out;
	op.params[0].tmpref.size   = sizeof(out);

	TEEC_Result r = TEEC_InvokeCommand(&g_sess, TG_CMD_GET_SECURE_TIME,
	                                   &op, NULL);
	if (r)
		return false;

	*out_time = out;
	return true;
}

bool tg_watchdog_error(int64_t err_ns, struct tg_watchdog_error_out *out_err)
{
    struct tg_watchdog_error_in in = { .err_ns = err_ns };
		
    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &in;
    op.params[0].tmpref.size   = sizeof(in);

		op.params[1].tmpref.buffer = out_err;
    op.params[1].tmpref.size   = sizeof(*out_err);

    if (TEEC_InvokeCommand(&g_sess, TG_CMD_WATCHDOG_ERROR, &op, NULL) != TEEC_SUCCESS)
        return false;

    uint8_t trust_ok;
    tg_get_trust(&trust_ok);
    return trust_ok;
}

bool tg_set_baseline_time(uint64_t sec, uint32_t nsec)
{
    struct tg_set_time_in in = {
        .phc_seconds = sec,
        .phc_nanoseconds = nsec
    };

    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &in;
    op.params[0].tmpref.size   = sizeof(in);

    TEEC_Result r = TEEC_InvokeCommand(&g_sess,
                                       TG_CMD_SET_TIME,
                                       &op, NULL);

		pr_notice("TG_CMD_SET_TIME InvokeCommand result: 0x%x\n", r);																	 

    return r == TEEC_SUCCESS;
}


uint64_t tg_proxy_id(void) { return g_proxy_id; }
