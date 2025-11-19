#pragma once
#include <stdint.h>
#include <stdbool.h>

bool tg_register(const uint8_t device_secret[32]); // returns true on success
bool tg_get_trust(uint8_t *trust_ok);
uint64_t tg_proxy_id(void);
bool tg_get_secure_time(struct tg_time_out *out_time);