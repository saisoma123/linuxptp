#pragma once
#include <stdint.h>

#define TA_TIMEGUARD_UUID \
	{ 0x7f3b8d40, 0x6c6a, 0x4f2b, \
	  { 0x91, 0x4c, 0x39, 0x38, 0x9d, 0x12, 0x44, 0xa1 } }

enum {
	TG_CMD_REGISTER   = 0x0001, // in: device_secret[32],  out: proxy_id (u64)
	TG_CMD_GET_TRUST  = 0x0002,  // out: trust_ok (0/1)
	TG_CMD_GET_SECURE_TIME = 0x0003,  // out: secure time
	TG_CMD_WATCHDOG_ERROR  = 0x0004,
	TG_CMD_SET_TIME  = 0x0005,
};

struct tg_register_in {
	uint8_t device_secret[32];   // simple shared secret for now
};

struct tg_register_out {
	uint32_t proxy_hi;           // high 32-bits of proxy_id
	uint32_t proxy_lo;           // low  32-bits of proxy_id
};

struct tg_trust_out {
	uint32_t trust_ok;           // 0 or 1
};

struct tg_time_out {
	uint64_t seconds;            // secure time seconds
	uint32_t nanoseconds;        // secure time nanoseconds (0..1e9-1)
};

struct tg_set_time_in {
    uint64_t phc_seconds;
    uint32_t phc_nanoseconds;
};

struct tg_watchdog_error_in {
	int64_t err_ns;   // error = phc_time_ns - secure_time_ns (precomputed in normal world)
};