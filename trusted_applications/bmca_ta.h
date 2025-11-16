/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * bmca_ta.h — Shared REE/TEE interface for BMCA decision
 */

#ifndef BMCA_TA_H
#define BMCA_TA_H

#include <stdint.h>

/* -------- TA identity --------
 * Replace with your own UUID (run `uuidgen`).
 */
#define TA_BMCA_UUID \
    {0x12345679, 0x9abc, 0x4def, {0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}}

/* -------- Command IDs -------- */
#define TA_BMCA_CMD_DECIDE 0x00000001

#define TA_BMCA_CMD_SET_DEFAULT_DS 0x00000002

#define TA_BMCA_CMD_PING 0x00000003

#define TA_BMCA_CMD_PTP_FSM         0x00000004

#define TA_BMCA_CMD_PTP_SLAVE_FSM   0x00000005


/* -------- Wire structs (must match on host & TA) -------- */
struct BmcaClockQuality
{
    uint8_t clockClass;
    uint8_t clockAccuracy;
    uint16_t offsetScaledLogVariance;
} __attribute__((packed));

struct BmcaPortIdentity
{
    uint8_t clockIdentity[8];
    uint16_t portNumber;
} __attribute__((packed));

struct BmcaDataset
{
    uint8_t identity[8];
    uint8_t priority1;
    struct BmcaClockQuality quality;
    uint8_t priority2;
    uint16_t stepsRemoved;
    struct BmcaPortIdentity sender;
    struct BmcaPortIdentity receiver;
} __attribute__((packed));

struct BmcaDefaultDS
{
    uint8_t priority1;
    uint8_t priority2;
    struct BmcaClockQuality quality; /* {clockClass, clockAccuracy, offsetScaledLogVariance} */
    uint8_t identity[8];             /* ClockIdentity (EUI-64) */
} __attribute__((packed));

/* Host → TA */
struct BmcaInput
{
    /* Foreign datasets (by value) */
    struct BmcaDataset clock_best;
    struct BmcaDataset port_best;

    /* Presence bits for the above (1 = present, 0 = absent) */
    uint8_t has_clock_best;
    uint8_t has_port_best;

    /* Runtime scalars from host */
    uint8_t current_port_state;      /* enum port_state value */
    uint8_t bmca_mode;               /* BMCA mode (e.g., BMCA_NOOP, etc.) */
    uint8_t clock_class;             /* clock_class(c) */
    uint8_t clock_best_is_this_port; /* boolean: best_port == p */

    uint8_t comparator_type;
} __attribute__((packed));

/* TA → Host */
struct BmcaOutput
{
    uint8_t decided_state; /* enum port_state value */
} __attribute__((packed));


struct BmcaFsmInput
{
    uint8_t state;  /* enum port_state (cast to uint8_t) */
    uint8_t event;  /* enum fsm_event (cast to uint8_t) */
    int32_t mdiff;  /* same semantics as fsm.c mdiff argument */
} __attribute__((packed));

struct BmcaFsmOutput
{
    uint8_t next_state; /* enum port_state value */
} __attribute__((packed));

#endif /* BMCA_TA_H */
