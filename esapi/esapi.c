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
    int ret;

    ret = test_esys_get_random(esys_context);
    if (ret == EXIT_SUCCESS){
        printf("Esys get random successful!!\n");
    }else{
        goto end;
    }

    ret = test_esys_nv_ram_ordinary_index(esys_context);
    if (ret == EXIT_SUCCESS){
        printf("Esys nvram write and read successful!!\n");
    }else{
        goto end;
    }

    ret = test_esys_encrypt_decrypt(esys_context);
    if (ret == EXIT_SUCCESS){
        printf("Esys encrypt and decrypt successful!!\n");
    }else{
        goto end; 
    }
end:      
    return ret;
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
    if (ret != EXIT_SUCCESS)
        LOG_ERROR("Test invoke esapi failed");

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


int
test_esys_nv_ram_ordinary_index(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;

    TPM2B_AUTH auth = {
        .size = 20,
        .buffer = {
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29
        }
    };

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD
                ),
            .authPolicy = {
                .size = 0,
                .buffer = {},
            },
            .dataSize = 32,
        }
    };

    r = Esys_NV_DefineSpace(esys_context,
                            ESYS_TR_RH_OWNER, //Auth handle
                            ESYS_TR_PASSWORD, //auth handle session
                            ESYS_TR_NONE,     //optional session
                            ESYS_TR_NONE,
                            &auth,
                            &publicInfo,
                            &nvHandle);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Error esys define nv space:0x%x", r);
        goto error;
    }

    UINT16 offset = 0;
    TPM2B_MAX_NV_BUFFER nv_test_data = { .size = 20,
                                         .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                  1, 2, 3, 4, 5, 6, 7, 8, 9}};
                                                
    TPM2B_NV_PUBLIC *nvPublic;
    TPM2B_NAME *nvName;

    r = Esys_NV_Write(esys_context,
                        nvHandle,
                        nvHandle,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &nv_test_data,
                        offset);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Error esys nv write:0x%x", r);
        goto error;
    }

    TPM2B_MAX_NV_BUFFER *nv_test_data2;

    r = Esys_NV_Read(esys_context,
                        nvHandle,
                        nvHandle,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        20,
                        0,
                        &nv_test_data2);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Error esys nv read:0x%x", r);
        goto error;
    }

    r = Esys_NV_UndefineSpace(esys_context,
                                ESYS_TR_RH_OWNER,
                                nvHandle,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE);
    if (r != TSS2_RC_SUCCESS){
        LOG_ERROR("Error esys undefine nv space:0x%x", r);
        goto error;       
    }
    return EXIT_SUCCESS;

error:
    if (nvHandle != ESYS_TR_NONE) {
        if (Esys_NV_UndefineSpace(esys_context,
                                    ESYS_TR_RH_OWNER,
                                    nvHandle,
                                    ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup nvHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

int
test_esys_encrypt_decrypt(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
    int failure_return = EXIT_FAILURE;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer= {0},
            },
            .data = {
                .size = 0,
                .buffer = {0},
            },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT | 
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {},
            },
        },
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error: TR_SetAuth:0x%x", r);
        goto error;
    }

    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context,ESYS_TR_RH_OWNER,ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE,
                            &inSensitivePrimary, &inPublic,
                            &outsideInfo, &creationPCR, &primaryHandle,
                            &outPublic, &creationData, &creationHash,
                            &creationTicket);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error: esys create primary:0x%x", r);
        goto error;
    }

    r = Esys_TR_SetAuth(esys_context, primaryHandle, &authValuePrimary);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error: TR_SetAuth:0x%x", r);
        goto error;
    }
    
    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}
    };

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 1,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0}
            },
            .data = {
                .size = 16,
                .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}
            }
        }
    };

    inSensitive2.sensitive.userAuth  = authKey2;

    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT),

            .authPolicy = {
                 .size = 0,
             },
            .parameters.symDetail = {
                 .sym = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits = {.aes = 128},
                     .mode = {.aes = TPM2_ALG_CFB}}
             },
            .unique.sym = {
                 .size = 0,
                 .buffer = {}
             }
        }
    };

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR2 = {
        .count = 0,
    };

    TPM2B_PUBLIC *outPublic2;
    TPM2B_PRIVATE *outPrivate2;
    TPM2B_CREATION_DATA *creationData2;
    TPM2B_DIGEST *creationHash2;
    TPMT_TK_CREATION *creationTicket2;

    r = Esys_Create(esys_context,
                    primaryHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive2,
                    &inPublic2,
                    &outsideInfo2,
                    &creationPCR2,
                    &outPrivate2,
                    &outPublic2,
                    &creationData2, &creationHash2, &creationTicket2);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error esys create:0x%x", r);
        goto error;
    }

    LOG_INFO("AES key created.");

    r = Esys_Load(esys_context,
                  primaryHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error esys load:0x%x", r);
        goto error;
    }

    LOG_INFO("AES key loaded.");

    r = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error esys TR_SetAuth:0x%x", r);
        goto error;
    }

    ESYS_TR keyHandle_handle = loadedKeyHandle;
    TPMI_YES_NO decrypt = TPM2_YES;
    TPMI_YES_NO encrypt = TPM2_NO;
    TPMI_ALG_SYM_MODE mode = TPM2_ALG_NULL;
    TPM2B_IV ivIn = {
        .size = 16,
        .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}
    };
    TPM2B_MAX_BUFFER inData = {
        .size = 16,
        .buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}
    };
    TPM2B_MAX_BUFFER *outData;
    TPM2B_IV *ivOut;

    r = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        encrypt,
        mode,
        &ivIn,
        &inData,
        &outData,
        &ivOut);

    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_ERROR("Command TPM2_EncryptDecrypt not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }

    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error EncryptDecrypt:0x%x", r);
        goto error;
    }

    TPM2B_MAX_BUFFER *outData2;
    TPM2B_IV *ivOut2;

    r = Esys_EncryptDecrypt(
        esys_context,
        keyHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        decrypt,
        mode,
        &ivIn,
        outData,
        &outData2,
        &ivOut2);

    if ((r == TPM2_RC_COMMAND_CODE) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER)) ||
        (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_ERROR("Command TPM2_EncryptDecrypt not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }

    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error EncryptDecrypt:0x%x", r);
        goto error;
    }

    LOGBLOB_DEBUG(&outData2->buffer[0], outData2->size, "** Decrypted data **");

    if (outData2->size != inData.size ||
        memcmp(&outData2->buffer, &inData.buffer[0], outData2->size) != 0) {
        LOG_ERROR("Error: decrypted text not  equal to origin");
        goto error;
    }

    r = Esys_FlushContext(esys_context, primaryHandle);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error during FlushContext:0x%x", r);
        goto error;
    }
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error during FlushContext:0x%x", r);
        goto error;
    }

    primaryHandle = ESYS_TR_NONE;

    r = Esys_FlushContext(esys_context, loadedKeyHandle);
    if ( r != TSS2_RC_SUCCESS ) {
        LOG_ERROR( "Error during FlushContext:0x%x", r);
        goto error;
    }

    return EXIT_SUCCESS;
error:
    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    if (loadedKeyHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, loadedKeyHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup loadedKeyHandle failed.");
        }
    }
    return failure_return;
}