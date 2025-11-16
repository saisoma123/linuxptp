/**
 * @file ptp4l.c
 * @brief PTP Boundary Clock or Transparent Clock main program
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clock.h"
#include "config.h"
#include "ntpshm.h"
#include "pi.h"
#include "print.h"
#include "raw.h"
#include "sad.h"
#include "sk.h"
#include "transport.h"
#include "udp6.h"
#include "uds.h"
#include "util.h"
#include "version.h"
#include "timeguard_client.h"
#include "timeguard_watchdog.h"
#include <time.h>
#include <unistd.h>
#include <fcntl.h>          
#include <linux/ptp_clock.h>

#define FD_TO_CLOCKID(fd)   ((clockid_t) ((~(fd) << 3) | 3))

static void timeguard_init(void)
{
	uint8_t dev_secret[32] = {0}; 
	// For bring-up you can leave zeros; TA currently accepts anything.
	if (!tg_register(dev_secret)) {
		pr_err("timeguard: register failed; continuing without watchdog\n");
	} else {
		pr_info("timeguard: registered, proxy_id=0x%016llx\n",
		        (unsigned long long)tg_proxy_id());
	}
}

static int64_t phc_get_time_ns(const char *ptp_path)
{
    int fd = open(ptp_path, O_RDONLY);
    if (fd < 0)
        return 0;   // or any sentinel you want

    clockid_t clkid = FD_TO_CLOCKID(fd);
	//	id = clkid;
    struct timespec ts;
    if (clock_gettime(clkid, &ts) < 0) {
        close(fd);
        return 0;
    }

    close(fd);

    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}


static void timeguard_policy_c_step(void)
{
     int m = 1;
     int n = 5;
     int64_t tS = 1000000000LL; // placeholder

     int64_t p = (m * tS) / n;
     int64_t slot = p / 10;

     struct timespec now;
     clock_gettime(CLOCK_MONOTONIC, &now);
     int64_t now_ns = now.tv_sec * 1000000000LL + now.tv_nsec;

     static int64_t next_inspect_time = 0;
     if (next_inspect_time == 0) {
         int r = rand() % 11;
         next_inspect_time = now_ns + r * slot;
     }

    if (now_ns < next_inspect_time)
         return;

    int64_t phc_ns = phc_get_time_ns("/dev/ptp0");

    struct tg_watchdog_error_out err_out;
    bool trusted = tg_watchdog_error(phc_ns, &err_out);
    pr_notice("err_out: sec=%ld  ns=%ld\n",
          (long)err_out.seconds,
          (long)err_out.nanoseconds);
    pr_notice("trusted: %s\n", trusted ? "true" : "false");
    if(!trusted) {
			struct timex tx_step;
			memset(&tx_step, 0, sizeof(tx_step));

			tx_step.modes = ADJ_SETOFFSET | ADJ_NANO;

			/* Relative step of +10   s. In ADJ_NANO, tv_usec is nanoseconds. */
			tx_step.time.tv_sec  = err_out.seconds;
			tx_step.time.tv_usec = err_out.nanoseconds;   /* 10   s = 10,000 ns */

			if (tx_step.time.tv_usec < 0) {
							tx_step.time.tv_sec  -= 1;
							tx_step.time.tv_usec += 1000000000L;
			}
      int fd = open("/dev/ptp0", O_RDONLY);
      if (fd < 0)
        return;   // or any sentinel you want

      clockid_t clkid = FD_TO_CLOCKID(fd);

       if (clock_adjtime(clkid, &tx_step) < 0) {
              pr_notice("Correction step failed");
      }
		}
    int r2 = rand() % 11;
    next_inspect_time = now_ns + r2 * slot;
}


static inline int64_t secure_time_to_ns(const struct tg_time_out *t)
{
    return (int64_t)t->seconds * 1000000000LL + (int64_t)t->nanoseconds;
}


static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" Delay Mechanism\n\n"
		" -A        Auto, starting with E2E\n"
		" -E        E2E, delay request-response (default)\n"
		" -P        P2P, peer delay mechanism\n\n"
		" Network Transport\n\n"
		" -2        IEEE 802.3\n"
		" -4        UDP IPV4 (default)\n"
		" -6        UDP IPV6\n\n"
		" Time Stamping\n\n"
		" -H        HARDWARE (default)\n"
		" -S        SOFTWARE\n"
		" -L        LEGACY HW\n\n"
		" Other Options\n\n"
		" -f [file] read configuration from 'file'\n"
		" -i [dev]  interface device to use, for example 'eth0'\n"
		"           (may be specified multiple times)\n"
		" -p [dev]  Clock device to use, default auto\n"
		"           (ignored for SOFTWARE/LEGACY HW time stamping)\n"
		" -s        client only synchronization mode (overrides configuration file)\n"
		" -l [num]  set the logging level to 'num'\n"
		" -m        print messages to stdout\n"
		" -q        do not print messages to the syslog\n"
		" -v        prints the software version and exits\n"
		" -h        prints this message and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *config = NULL, *req_phc = NULL, *progname;
	enum clock_type type = CLOCK_TYPE_ORDINARY;
	int c, err = -1, index, cmd_line_print_level;
	struct clock *clock = NULL;
	struct option *opts;
	struct config *cfg;

	if (handle_term_signals())
		return -1;

	cfg = config_create();
	if (!cfg) {
		return -1;
	}
	opts = config_long_options(cfg);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv, "AEP246HSLf:i:p:sl:mqvh",
				       opts, &index))) {
		switch (c) {
		case 0:
			if (config_parse_option(cfg, opts[index].name, optarg))
				goto out;
			break;
		case 'A':
			if (config_set_int(cfg, "delay_mechanism", DM_AUTO))
				goto out;
			break;
		case 'E':
			if (config_set_int(cfg, "delay_mechanism", DM_E2E))
				goto out;
			break;
		case 'P':
			if (config_set_int(cfg, "delay_mechanism", DM_P2P))
				goto out;
			break;
		case '2':
			if (config_set_int(cfg, "network_transport",
					    TRANS_IEEE_802_3))
				goto out;
			break;
		case '4':
			if (config_set_int(cfg, "network_transport",
					    TRANS_UDP_IPV4))
				goto out;
			break;
		case '6':
			if (config_set_int(cfg, "network_transport",
					    TRANS_UDP_IPV6))
				goto out;
			break;
		case 'H':
			if (config_set_int(cfg, "time_stamping", TS_HARDWARE))
				goto out;
			break;
		case 'S':
			if (config_set_int(cfg, "time_stamping", TS_SOFTWARE))
				goto out;
			break;
		case 'L':
			if (config_set_int(cfg, "time_stamping", TS_LEGACY_HW))
				goto out;
			break;
		case 'f':
			config = optarg;
			break;
		case 'i':
			if (!config_create_interface(optarg, cfg))
				goto out;
			break;
		case 'p':
			req_phc = optarg;
			break;
		case 's':
			if (config_set_int(cfg, "clientOnly", 1)) {
				goto out;
			}
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &cmd_line_print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX))
				goto out;
			config_set_int(cfg, "logging_level", cmd_line_print_level);
			break;
		case 'm':
			config_set_int(cfg, "verbose", 1);
			break;
		case 'q':
			config_set_int(cfg, "use_syslog", 0);
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'h':
			usage(progname);
			return 0;
		case '?':
			usage(progname);
			goto out;
		default:
			usage(progname);
			goto out;
		}
	}

	if (config && (c = config_read(config, cfg))) {
		return c;
	}

	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	assume_two_step = config_get_int(cfg, NULL, "assume_two_step");
	sk_check_fupsync = config_get_int(cfg, NULL, "check_fup_sync");
	sk_tx_timeout = config_get_int(cfg, NULL, "tx_timestamp_timeout");
	sk_hwts_filter_mode = config_get_int(cfg, NULL, "hwts_filter");

	ptp_hdr_ver = config_get_int(cfg, NULL, "ptp_minor_version");
	ptp_hdr_ver = (ptp_hdr_ver << 4) | PTP_MAJOR_VERSION;

	if (sad_create(cfg)) {
		goto out;
	}

	if (config_get_int(cfg, NULL, "clock_servo") == CLOCK_SERVO_NTPSHM) {
		config_set_int(cfg, "kernel_leap", 0);
		config_set_int(cfg, "sanity_freq_limit", 0);
	}

	if (STAILQ_EMPTY(&cfg->interfaces)) {
		fprintf(stderr, "no interface specified\n");
		usage(progname);
		goto out;
	}

	type = config_get_int(cfg, NULL, "clock_type");
	switch (type) {
	case CLOCK_TYPE_ORDINARY:
		if (cfg->n_interfaces > 1) {
			type = CLOCK_TYPE_BOUNDARY;
		}
		break;
	case CLOCK_TYPE_BOUNDARY:
		if (cfg->n_interfaces < 2) {
			fprintf(stderr, "BC needs at least two interfaces\n");
			goto out;
		}
		break;
	case CLOCK_TYPE_P2P:
		if (cfg->n_interfaces < 2) {
			fprintf(stderr, "TC needs at least two interfaces\n");
			goto out;
		}
		if (DM_P2P != config_get_int(cfg, NULL, "delay_mechanism")) {
			fprintf(stderr, "P2P_TC needs P2P delay mechanism\n");
			goto out;
		}
		break;
	case CLOCK_TYPE_E2E:
		if (cfg->n_interfaces < 2) {
			fprintf(stderr, "TC needs at least two interfaces\n");
			goto out;
		}
		if (DM_E2E != config_get_int(cfg, NULL, "delay_mechanism")) {
			fprintf(stderr, "E2E_TC needs E2E delay mechanism\n");
			goto out;
		}
		break;
	case CLOCK_TYPE_MANAGEMENT:
		goto out;
	}

	clock = clock_create(type, cfg, req_phc);
	if (!clock) {
		fprintf(stderr, "failed to create a clock\n");
		goto out;
	}
	timeguard_init();
	err = 0;
        int64_t phc_ns = phc_get_time_ns("/dev/ptp0");
        uint64_t sec  = phc_ns / 1000000000LL;    // convert ns → seconds
	uint32_t nsec = phc_ns % 1000000000LL;    
        tg_set_baseline_time(sec, nsec);
	//struct timespec last_adj = {0};	        
	while (is_running()) {
             timeguard_policy_c_step();

             //   struct timespec now;
    	     //   clock_gettime(CLOCK_MONOTONIC, &now);
             //   if (now.tv_sec != last_adj.tv_sec) {
             //   	last_adj = now;	        
              //  	// int64_t phc_ns = phc_get_time_ns("/dev/ptp0");
             //   	tg_watchdog_sample_simple(123);
	     //   }
                if (clock_poll(clock))
			break;	
	//	timeguard_policy_c_step();
               
	}
out:
	if (clock)
		clock_destroy(clock);
	sad_destroy(cfg);
	TA_CloseSessionEntryPoint();
        config_destroy(cfg);
	return err;
}
