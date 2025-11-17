#include <stdint.h>
#include <stdbool.h>
#include "trusted_applications/register_ta.h"
bool tg_register(const uint8_t device_secret[32]); // returns true on success
bool tg_get_trust(uint8_t *trust_ok);
uint64_t tg_proxy_id(void);
bool tg_get_secure_time(struct tg_time_out *out_time);
bool tg_set_baseline_time(uint64_t sec, uint32_t nsec);
bool tg_passive_mru(uint64_t phc_ns, int32_t core_id, struct tg_passive_policy_out *out);
bool tg_passive_random(uint64_t phc_ns, int32_t core_id, struct tg_passive_policy_out *out);
bool tg_passive_freq(uint64_t phc_ns, int32_t core_id, struct tg_passive_policy_out *out);
bool tg_passive_schedtrace(uint64_t phc_ns, int32_t core_id, struct tg_passive_policy_out *out);
