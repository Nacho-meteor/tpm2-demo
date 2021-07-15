#ifndef ESPAI_TEST_H
#define ESPAI_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tcti_device.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108
#define EXIT_SKIP 77
#define EXIT_XFAIL 99
/* Default TCTI */
#define TCTI_DEFAULT      DEVICE_TCTI

/* Defaults for Device TCTI */
#define DEVICE_PATH_DEFAULT "/dev/tpm0"

/* Defaults for Socket TCTI connections */
#define HOSTNAME_DEFAULT "127.0.0.1"
#define PORT_DEFAULT     2321

#define TCTI_PROXY_MAGIC 0x5250584f0a000000ULL /* 'PROXY\0\0\0' */
#define TCTI_PROXY_VERSION 0x1

// /* environment variables holding TCTI config */
// #define ENV_TCTI_NAME      "TPM20TEST_TCTI_NAME"
// #define ENV_DEVICE_FILE    "TPM2OTEST_DEVICE_FILE"
// #define ENV_SOCKET_ADDRESS "TPM20TEST_SOCKET_ADDRESS"
// #define ENV_SOCKET_PORT    "TPM20TEST_SOCKET_PORT"
#define LOG_INFO(FORMAT, ...) {}
#define LOGBLOB_INFO(FORMAT, ...) {}
#define LOG_ERROR(FORMAT, ...) {}
#define LOG_DEBUG(FORMAT, ...) {}
#define LOGBLOB_DEBUG(FORMAT, ...) {}

typedef enum {
    UNKNOWN_TCTI,
    DEVICE_TCTI,
    SOCKET_TCTI,
    N_TCTI,
} TCTI_TYPE;

enum state {
    forwarding,
    intercepting
};

typedef struct {
    TCTI_TYPE tcti_type;
    char *device_file;
    char *socket_address;
    uint16_t socket_port;
} options_info;

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
              TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
    TSS2_TCTI_CONTEXT *tctiInner;
    enum state state;
} TSS2_TCTI_CONTEXT_PROXY;

void
tcti_teardown(TSS2_TCTI_CONTEXT * tcti_context)
{
    if (tcti_context) {
        Tss2_Tcti_Finalize(tcti_context);
        free(tcti_context);
    }
}

int
test_esys_get_random(ESYS_CONTEXT * esys_context);

int
test_esys_nv_ram_ordinary_index(ESYS_CONTEXT * esys_context);

#ifdef __cplusplus
}
#endif

#endif /* ESPAI_TEST_H */