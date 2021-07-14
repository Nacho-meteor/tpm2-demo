#include "esapi_test.h"

TSS2_TCTI_CONTEXT *
tcti_device_init(char const *device_path)
{
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = Tss2_Tcti_Device_Init(NULL, &size, 0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr,
                "Failed to get allocation size for device tcti context: "
                "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        fprintf(stderr,
                "Allocation for device TCTI context failed: %s\n",
                strerror(errno));
        return NULL;
    }
    rc = Tss2_Tcti_Device_Init(tcti_ctx, &size, device_path);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize device TCTI context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

static TSS2_TCTI_CONTEXT_PROXY*
tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx)
{
    TSS2_TCTI_CONTEXT_PROXY *ctxi = (TSS2_TCTI_CONTEXT_PROXY*)ctx;
    if (ctxi == NULL || ctxi->magic != TCTI_PROXY_MAGIC) {
        LOG_ERROR("Bad tcti passed.");
        return NULL;
    }
    return ctxi;
}

static TSS2_RC
tcti_proxy_transmit(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        return TSS2_RC_SUCCESS;
    }

    rval = Tss2_Tcti_Transmit(tcti_proxy->tctiInner, command_size,
        command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    return rval;
}

uint8_t yielded_response[] = {
    0x80, 0x01,             /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A, /* Response Size 10 */
    0x00, 0x00, 0x09, 0x08  /* TPM_RC_YIELDED */
};

static TSS2_RC
tcti_proxy_receive(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        *response_size = sizeof(yielded_response);
        if (response_buffer != NULL)
            memcpy(response_buffer, &yielded_response[0], sizeof(yielded_response));

        tcti_proxy->state = forwarding;
        return TSS2_RC_SUCCESS;
    }

    rval = Tss2_Tcti_Receive(tcti_proxy->tctiInner, response_size,
                             response_buffer, timeout);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI Transmit");
        return rval;
    }

    tcti_proxy->state = intercepting;

    return rval;
}

static void
tcti_proxy_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
}

static TSS2_RC
tcti_proxy_initialize(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    TSS2_TCTI_CONTEXT *tctiInner)
{
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy =
        (TSS2_TCTI_CONTEXT_PROXY*) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_proxy);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_proxy, 0, sizeof(*tcti_proxy));
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_PROXY_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_PROXY_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_proxy_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_proxy_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_proxy_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = NULL;
    tcti_proxy->tctiInner = tctiInner;
    tcti_proxy->state = forwarding;

    return TSS2_RC_SUCCESS;
}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    return test_esys_get_random(esys_context);
}

int
main(int argc, char *argv[]){
    TSS2_RC rc;
    size_t tcti_size;
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_TCTI_CONTEXT *tcti_inner;
    ESYS_CONTEXT *esys_context;
    TSS2_ABI_VERSION abiversion = { //apption binary interface
        .tssCreator = TSSWG_INTEROP,
        .tssFamily = TSS_SAPI_FIRST_FAMILY,
        .tssLevel = TSS_SAPI_FIRST_LEVEL,
        .tssVersion = TSS_SAPI_FIRST_VERSION,
    };
    int ret;
    options_info opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port = PORT_DEFAULT,
    };
    tcti_inner = tcti_device_init(opts.device_file);
    if (tcti_inner == NULL) {
        LOG_ERROR("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    rc = tcti_proxy_initialize(NULL, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("tcti initialization FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    tcti_context = calloc(1, tcti_size);
    if (tcti_inner == NULL) {
        LOG_ERROR("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
        rc = tcti_proxy_initialize(tcti_context, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("tcti initialization FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    rc = Esys_Initialize(&esys_context, tcti_context, &abiversion);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    rc = Esys_Startup(esys_context, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        LOG_ERROR("Esys_Startup FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    rc = Esys_SetTimeout(esys_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_SetTimeout FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    ret = test_invoke_esapi(esys_context);
    if (ret == EXIT_SUCCESS)
        printf("TPM GetRandom Successful !!!\n");

    Esys_Finalize(&esys_context);
    tcti_teardown(tcti_context);
    return ret;
}

int
test_esys_get_random(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;

    TPM2B_DIGEST *randomBytes;
    r = Esys_GetRandom(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 48, &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom FAILED! Response Code : 0x%x", r);
        goto error;
    }
    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

    LOG_INFO("GetRandom Test Passed!");

    ESYS_TR session = ESYS_TR_NONE;
    const TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session, TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48,
                       &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

    LOG_INFO("GetRandom with session Test Passed!");

    r = Esys_FlushContext(esys_context, session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    return EXIT_SUCCESS;

 error_cleansession:
    r = Esys_FlushContext(esys_context, session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", r);
    }
 error:
    return EXIT_FAILURE;
}