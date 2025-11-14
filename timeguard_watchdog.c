#include <stdint.h>
#include <stdio.h>
#include "timeguard_client.h"
#include "trusted_applications/register_ta.h"
#include <tee_client_api.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/ptp_clock.h>

#define FD_TO_CLOCKID(fd)   ((clockid_t) ((~(fd) << 3) | 3))


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

static int64_t phc_get_time_ns(const char *ptp_path)
{
    int fd = open(ptp_path, O_RDONLY);
    if (fd < 0)
        return 0;   // or any sentinel you want

    clockid_t clkid = FD_TO_CLOCKID(fd);
        //      id = clkid;
    struct timespec ts;
    if (clock_gettime(clkid, &ts) < 0) {
        close(fd);
        return 0;
    }

    close(fd);

    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}



static inline int64_t secure_time_to_ns(const struct tg_time_out *t)
{
    return (int64_t)t->seconds * 1000000000LL + (int64_t)t->nanoseconds;
}

void tg_watchdog_sample_simple(int64_t phc_time_ns)
{
//      int64_t phc_ns = phc_get_time_ns("/dev/ptp0");
//      uint64_t sec  = phc_ns / 1000000000LL;    // convert ns  ^f^r seconds
//      uint32_t nsec = phc_ns % 1000000000LL;
//      tg_set_baseline_time(sec, nsec);

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
    int64_t err_ns = phc_time_ns - (sec_ns - (int64_t) dt_ns);

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
