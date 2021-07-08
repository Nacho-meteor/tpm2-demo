#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <tss2/tss2_fapi.h>

#define SAFE_FREE(S) if((S) != NULL) {free((void*) (S)); (S)=NULL;}
#define EXIT_ERROR 99
#define EXIT_SUCCESS 0

#define TPM_INFO                1
#define TPM_WRITE_AND_READ      0
#define TPM_ENCRYPT_AND_DECRYGT 0

#define FAPI_PROFILE "P_ECC"

char *fapi_profile = NULL;
char *tmpdir = NULL;

char *config = NULL;
char *config_path = NULL;
char *config_env = NULL;
char *remove_cmd = NULL;
char *system_dir = NULL;
char *tcti_env = "device:/dev/tpm0";

FAPI_CONTEXT *global_fapi_context = NULL;

bool file_exists (char *path) {
  struct stat   buffer;
  return (stat (path, &buffer) == 0);
}

static int
init_fapi(char *profile,FAPI_CONTEXT **fapi_context)
{
    TSS2_RC rc;
    int ret, size;

    SAFE_FREE(config);
    SAFE_FREE(config_path);
    SAFE_FREE(config_env);
    SAFE_FREE(remove_cmd);
    SAFE_FREE(system_dir);

    FILE *config_file;

    fapi_profile = profile;

    size = asprintf(&config, "{\n"
                "     \"profile_name\": \"%s\",\n"
                "     \"profile_dir\": \"" "./config/\",\n"
                "     \"user_dir\": \"%s/user/dir\",\n"
                "     \"system_dir\": \"%s/system_dir\",\n"
                "     \"system_pcrs\" : [],\n"
                "     \"log_dir\" : \"%s\",\n"
                "     \"tcti\": \"%s\",\n"
                "}\n",
                profile, tmpdir, tmpdir, tmpdir,tcti_env);

    if (size < 0) {
        printf("Out of memory\n");
        ret = EXIT_ERROR;
        goto end;
    }

    size = asprintf(&system_dir,"%s/system_dir/",tmpdir);
    if (size < 0) {
        printf("Out of memory\n");
        ret = EXIT_ERROR;
        goto end;
    }

    if (!file_exists(system_dir)) {
        int rc_mkdir = mkdir(system_dir,0777);
        if (rc_mkdir != 0) {
            printf("mkdir not possible: %i %s\n", rc_mkdir, system_dir);
            ret = EXIT_ERROR;
            goto end;
        }
    }

    size = asprintf(&config_path, "%s/fapi-config.json",tmpdir);
    if (size < 0) {
        printf("Out of memory\n");
        ret = EXIT_ERROR;
        goto end;
    }

    config_file = fopen(config_path,"w");
    if (!config_file) {
        printf("Open failed\n");
        perror(config_path);
        ret = EXIT_ERROR;
        goto end;
    }
    size = fprintf(config_file,"%s",config);
    if (size < 0) {
        printf("Out of memory\n");
        ret = EXIT_ERROR;
        goto end;
    }
    fclose(config_file);

    size = asprintf(&config_env,"TSS2_FAPICONF=%s",config_path);
    if (size < 0) {
        printf("Out of memory\n");
        ret = EXIT_ERROR;
        goto end;
    }
    putenv(config_env);
    printf("conf :%s\n",config);
    printf("conf_path :%s\n",config_path);
    printf("conf_env :%s\n",config_env);

    rc = Fapi_Initialize(fapi_context, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x\n", rc);
        ret = EXIT_ERROR;
        goto end;
    }

    global_fapi_context = *fapi_context;
    return EXIT_SUCCESS;
end:
    Fapi_Finalize(fapi_context);

    SAFE_FREE(config);
    SAFE_FREE(config_path);
    SAFE_FREE(config_env);
    SAFE_FREE(remove_cmd);
    SAFE_FREE(system_dir);

    return ret;
}

static int
test_fapi_info(FAPI_CONTEXT *context) {
    TSS2_RC rc;
    char *info ,*remove = NULL;
    FILE *info_file;
    int size;
    char filename[] = "./tpm2-info.json";

    rc = Fapi_GetInfo(context,&info);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Get tpm2 info failed\n");
        return EXIT_ERROR;
    }

    if (file_exists(filename)) {
        size = asprintf(&remove, "rm -r -f %s", filename);
        if (size < 0) {
            printf("Out of memory\n");
            return EXIT_ERROR;
        }
        if (system(remove) != 0) {
            printf("Directory %s can't be deleted.\n", filename);
            return EXIT_ERROR;
        }  
    }

    info_file = fopen("./tpm2-info.json","w");
    if (!info_file) {
        printf("create file failed\n");
        return EXIT_ERROR;
    }
    size = fprintf(info_file,"%s\n",info);
    if (size < 0) {
      printf("write to file failed\n");
      return EXIT_ERROR;
    }
    fclose(info_file);

    return EXIT_SUCCESS;
}

static int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
#if defined(TPM_INFO)
  return test_fapi_info(fapi_context);
#elif defined(TPM_WRITE_AND_READ)
  return test_fapi_nvram_read_and_write(fapi_context);
#else
  return test_fapi_data_encrypt_and_decrypt(fapi_context);
#endif
}

int main(void) {
    int ret, size;
    char *config = NULL;
    char *config_path = NULL;
    char *config_env = NULL;
    char *remove_cmd = NULL;
    char *system_dir = NULL;

    char template[] = "/tmp/fapi_tmpdir.XXXXXX";

    tmpdir = mkdtemp(template);

    if (!tmpdir) {
        printf("No temp dir created\n");
        return EXIT_ERROR;
    }

    ret = init_fapi(FAPI_PROFILE,&global_fapi_context);
    if (ret) goto error;

    ret = test_invoke_fapi(global_fapi_context);
    if (ret) goto error;

    size = asprintf(&remove_cmd, "rm -r -f %s", tmpdir);
    if (size < 0) {
      printf("Out of memory\n");
      ret = EXIT_ERROR;
      goto error;
    }
    if (system(remove_cmd) != 0) {
      printf("Directory %s can't be deleted.\n", tmpdir);
      ret = EXIT_ERROR;
      goto error;
    }  


error:
    Fapi_Finalize(&global_fapi_context);

    SAFE_FREE(config);
    SAFE_FREE(config_path);
    SAFE_FREE(config_env);
    SAFE_FREE(remove_cmd);
    SAFE_FREE(system_dir);

    return ret;
}
