/**
 * @file sad_tee.c
 * @brief Security Association Database OP-TEE backend (per-call TEE session)
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tee_client_api.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"
#include "trusted_applications/bmca_ta.h"


/* --------------------------------------------------------- */
/* Structure representing a key stored inside the TA.        */
/* Normal world only holds a handle + expected digest length.*/
/* --------------------------------------------------------- */
struct mac_data {
    uint32_t key_handle;        /* secure-world reference */
    size_t mac_len;             /* digest/truncation length */
    integrity_alg_type alg;
};


/* ========================================================================== */
/*                              sad_init_mac                                  */
/* ========================================================================== */

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
                              const unsigned char *key, size_t key_len)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_SharedMemory shm;
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_BMCA_UUID;
    struct mac_data *md;

    if (!key || key_len == 0) {
        pr_err("TEE: sad_init_mac: key_len is zero");
        return NULL;
    }

    md = calloc(1, sizeof(*md));
    if (!md)
        return NULL;

    /* Determine digest size needed */
    switch (algorithm) {
    case HMAC_SHA256:       md->mac_len = 32; break;
    case HMAC_SHA256_128:   md->mac_len = 16; break;
    case CMAC_AES128:       md->mac_len = 16; break;
    case CMAC_AES256:       md->mac_len = 16; break;
    default:
        pr_err("TEE: sad_init_mac: unknown algorithm");
        free(md);
        return NULL;
    }

    md->alg = algorithm;

    /* ---- Open TEE context ---- */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        pr_err("TEE: InitializeContext failed 0x%x", res);
        free(md);
        return NULL;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        pr_err("TEE: OpenSession failed 0x%x origin 0x%x", res, err_origin);
        TEEC_FinalizeContext(&ctx);
        free(md);
        return NULL;
    }

    /* ---- Allocate shared memory for key ---- */
    memset(&shm, 0, sizeof(shm));
    shm.size  = key_len;
    shm.flags = TEEC_MEM_INPUT;

    res = TEEC_AllocateSharedMemory(&ctx, &shm);
    if (res != TEEC_SUCCESS) {
        pr_err("TEE: sad_init_mac: failed to alloc shared mem 0x%x", res);
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        free(md);
        return NULL;
    }

    memcpy(shm.buffer, key, key_len);

    /* ---- Build operation ---- */
    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_VALUE_INPUT,       /* algorithm */
                        TEEC_MEMREF_WHOLE,      /* key in shared mem */
                        TEEC_VALUE_OUTPUT,      /* key_handle */
                        TEEC_NONE);

    op.params[0].value.a       = algorithm;
    op.params[1].memref.parent = &shm;
    op.params[1].memref.offset = 0;
    op.params[1].memref.size   = key_len;

    /* ---- Send command ---- */
    res = TEEC_InvokeCommand(&sess, CMD_IMPORT_KEY, &op, &err_origin);

    TEEC_ReleaseSharedMemory(&shm);
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    if (res != TEEC_SUCCESS) {
        pr_err("TEE: CMD_IMPORT_KEY failed 0x%x origin 0x%x",
               res, err_origin);
        free(md);
        return NULL;
    }

    md->key_handle = op.params[2].value.a;
    return md;
}


/* ========================================================================== */
/*                                sad_hash                                    */
/* ========================================================================== */

int sad_hash(struct mac_data *md,
             const void *data, size_t data_len,
             unsigned char *mac, size_t mac_len)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_BMCA_UUID;

    if (mac_len > md->mac_len) {
        pr_err("TEE: sad_hash: mac_len too large (given=%zu expected<=%zu)",
               mac_len, md->mac_len);
        return 0;
    }

    /* ---- Open TEE session ---- */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        pr_err("TEE: InitializeContext failed 0x%x", res);
        return 0;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        pr_err("TEE: OpenSession failed 0x%x origin 0x%x", res, err_origin);
        TEEC_FinalizeContext(&ctx);
        return 0;
    }

    /* ---- Build MAC compute op ---- */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_VALUE_INPUT,        /* key_handle */
                        TEEC_MEMREF_TEMP_INPUT,  /* input data */
                        TEEC_MEMREF_TEMP_OUTPUT, /* output mac */
                        TEEC_NONE);

    op.params[0].value.a = md->key_handle;
    op.params[1].tmpref.buffer = (void *) data;
    op.params[1].tmpref.size   = data_len;
    op.params[2].tmpref.buffer = mac;
    op.params[2].tmpref.size   = mac_len;

    /* ---- Invoke ---- */
    res = TEEC_InvokeCommand(&sess, CMD_MAC_COMPUTE, &op, &err_origin);

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    if (res != TEEC_SUCCESS)
        return 0;

    return mac_len;
}


/* ========================================================================== */
/*                               sad_verify                                   */
/* ========================================================================== */

int sad_verify(struct mac_data *md,
               const void *data, size_t data_len,
               unsigned char *mac, size_t mac_len)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_BMCA_UUID;

    /* ---- Open TEE session ---- */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        pr_err("TEE: sad_verify: InitializeContext failed 0x%x", res);
        return 1;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        pr_err("TEE: sad_verify: OpenSession failed 0x%x origin 0x%x",
               res, err_origin);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    /* ---- Build verify op ---- */
    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_VALUE_INPUT,        /* key_handle */
                        TEEC_MEMREF_TEMP_INPUT,  /* data */
                        TEEC_MEMREF_TEMP_INPUT,  /* provided MAC */
                        TEEC_NONE);

    op.params[0].value.a = md->key_handle;
    op.params[1].tmpref.buffer = (void *) data;
    op.params[1].tmpref.size   = data_len;
    op.params[2].tmpref.buffer = mac;
    op.params[2].tmpref.size   = mac_len;

    /* ---- Invoke ---- */
    res = TEEC_InvokeCommand(&sess, CMD_MAC_VERIFY, &op, &err_origin);

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    if (res == TEEC_SUCCESS)
        return 0;                   /* match */

    if (res == TEE_ERROR_MAC_INVALID)
        return 1;                   /* mismatch */

    return 1;                       /* other error */
}


/* ========================================================================== */
/*                              sad_deinit_mac                                */
/* ========================================================================== */

void sad_deinit_mac(struct mac_data *md)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_BMCA_UUID;

    if (!md)
        return;

    /* ---- Open TEE session ---- */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res == TEEC_SUCCESS) {

        res = TEEC_OpenSession(&ctx, &sess, &uuid,
                               TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

        if (res == TEEC_SUCCESS) {

            /* ---- Build delete-key op ---- */
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(
                                TEEC_VALUE_INPUT,
                                TEEC_NONE,
                                TEEC_NONE,
                                TEEC_NONE);

            op.params[0].value.a = md->key_handle;

            /* ---- Invoke ---- */
            TEEC_InvokeCommand(&sess, CMD_DELETE_KEY, &op, &err_origin);

            TEEC_CloseSession(&sess);
        }

        TEEC_FinalizeContext(&ctx);
    }

    free(md);
}
