#include <stdint.h>
#include <stdio.h>
#include "timeguard_client.h"
#include "trusted_applications/register_ta.h"
#include <tee_client_api.h>
#include <time.h>

static int64_t g_sum_err_ns = 0;
static uint64_t g_cnt = 0;


static FILE *g_logf = NULL;

static void tg_open_log(void)
{
    if (!g_logf) {
        g_logf = fopen("timeguard_watchdog.log", "a");
        if (!g_logf) {
            fprintf(stderr, "timeguard: failed to open watchdog log\n");
        }
    }
}



static inline int64_t secure_time_to_ns(const struct tg_time_out *t)
{
    return (int64_t)t->seconds * 1000000000LL + (int64_t)t->nanoseconds;
}

void tg_watchdog_sample_simple(int64_t phc_time_ns)
{
    struct tg_time_out st = {0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (!tg_get_secure_time(&st)) {
        fprintf(stderr, "timeguard: get_secure_time failed\n");
        return;
    }

    int64_t sec_ns = secure_time_to_ns(&st);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t dt_ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    int64_t err_ns = phc_time_ns - (sec_ns - (int64_t)(dt_ns));

    g_sum_err_ns += err_ns;
    g_cnt++;

    tg_open_log();

    double mean = (double)g_sum_err_ns / (double)g_cnt;

    if (g_logf) {
        fprintf(g_logf,
            "sample=%llu mean_err=%.2f ns last_err=%lld ns\n",
            (unsigned long long)g_cnt,
            mean,
            (long long)err_ns);
        fflush(g_logf);
    }
}

double tg_watchdog_get_mean_err(void)
{
    if (g_cnt == 0) return 0.0;
    return (double)g_sum_err_ns / (double)g_cnt;
}

int64_t tg_get_instant_error(int64_t phc_time_ns)
{
    struct tg_time_out st = {0};

    /* Get secure time from TA */
    if (!tg_get_secure_time(&st)) {
        return 0;   
    }

    /* Convert secure time to ns */
    int64_t secure_ns =
        (int64_t)st.seconds * 1000000000LL +
        (int64_t)st.nanoseconds;

    /* Return instant error */
    return phc_time_ns - secure_ns;
}
