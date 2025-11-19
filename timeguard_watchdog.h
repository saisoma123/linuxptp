#pragma once
#include <stdint.h>

void   tg_watchdog_sample_simple(int64_t phc_time_ns);
double tg_watchdog_get_mean_err(void);
bool tg_watchdog_error(int64_t err_ns)
int64_t tg_get_instant_error(int64_t phc_time_ns)