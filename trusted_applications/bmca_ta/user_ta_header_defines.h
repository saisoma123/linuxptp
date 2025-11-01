#pragma once

/* Reuse the UUID you already defined in bmca_ta.h */
#include "../bmca_ta.h"   /* adjust relative path if needed */

/* OP-TEE expects TA_UUID in this file */
#define TA_UUID TA_BMCA_UUID

/* Reasonable defaults; adjust if you need more heap/stack */
#define TA_FLAGS      (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE (2 * 1024)
#define TA_DATA_SIZE  (32 * 1024)
