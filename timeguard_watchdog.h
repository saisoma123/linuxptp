#include <stdint.h>
#include "trusted_applications/register_ta.h"

void   tg_watchdog_sample_simple(int64_t phc_time_ns);
double tg_watchdog_get_mean_err(void);
int64_t tg_get_instant_error(int64_t phc_time_ns);
bool tg_watchdog_error(int64_t err_ns, struct tg_watchdog_error_out *out_err);
