#include <tee_client_api.h>
#include "tg_proto.h"

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

uint64_t tg_proxy_id(void) { return g_proxy_id; }
