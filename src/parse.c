#include <sysrepo.h>

#include <errno.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#include <libubox/md5.h>

#include "common.h"
#include "parse.h"
#include "firmware.h"

const char file_path[FILENAME_MAX] = "/tmp/firmware.bin";

static char *get_username_from_url(char *url)
{
    char *res = malloc(sizeof(char) * strlen(url));
    unsigned int i, counter = 0;
    int bIndex = 0, eIndex = 0;

    for (i = 0; i < strlen(url); i++) {
        if (url[i] == '/') {
            ++counter;
        }
        if (url[i] == '/' && counter == 2) {
            bIndex = i;
        }
        if (url[i] == '@' && counter == 2) {
            eIndex = i;
        }
    }

    if (bIndex > 0 && eIndex > 0) {
        strncpy(res, url + bIndex, eIndex - bIndex);
        free(res);
        res = NULL;
    }

    return res;
}

struct server_data {
    char *address;
    char *password;
    char *certificate;
    char *ssh_key;
};

struct curl_ctx {
    firmware_t *firmware;
    struct server_data *server;
    const char *path;
    size_t n_filesize;
    size_t n_downloaded;
    /* datastore_t *progress; */
    FILE *stream;
};

static size_t firmware_write_cb(void *buffer, size_t size, size_t nmemb, FILE *stream)
{
    return fwrite(buffer, size, nmemb, stream);
}

static CURLcode firmware_download_ssl(CURL *curl, void *sslctx, void *parm)
{
    /* X509_STORE *store; */
    /* X509 *cert=NULL; */
    /* BIO *bio; */
    /* char *mypem = NULL; */

    /* struct curl_data *data = (struct curl_data *)parm; */
    /* mypem = (char *) data->server->certificate; */

    /* bio = BIO_new_mem_buf(mypem, -1); */

    /* PEM_read_bio_X509(bio, &cert, 0, NULL); */
    /* if (NULL == cert) */
    /*	 DEBUG("PEM_read_bio_X509 failed...\n"); */

    /* store=SSL_CTX_get_cert_store((SSL_CTX *) sslctx); */

    /* if (0 == X509_STORE_add_cert(store, cert)) */
    /*	 DEBUG("error adding certificate\n"); */

    /* X509_free(cert); */
    /* BIO_free(bio); */

    return CURLE_OK;
}

static char *get_sha256()
{
    unsigned char buffer[4096];
    char sha256[SHA256_DIGEST_LENGTH * 2 + 1];
    FILE *f;
    SHA256_CTX ctx;
    size_t len;
    f = fopen(file_path, "r");
    if (!f) {
        ERR("Couldn't open firmware %s", file_path);
        return NULL;
    }
    SHA256_Init(&ctx);
    do {
        len = fread(buffer, sizeof(unsigned char), sizeof(buffer), f);
        if (len > 0) {
            SHA256_Update(&ctx, buffer, len);
        }
    } while (len > 0);

    SHA256_Final(buffer, &ctx);
    fclose(f);

    for (len = 0; len < SHA256_DIGEST_LENGTH; len++) {
        sprintf(&sha256[len * 2], "%02x", (unsigned int) buffer[len]);
    }

    return strdup(sha256);
}

static char *get_md5sum()
{
    char md5_str[33];
    uint8_t md5[16];
    int n;

    if (0 >= md5sum((char *) file_path, md5)) {
        return NULL;
    }

    for (n = 0; n < 16; n++) {
        sprintf(&md5_str[n * 2], "%02x", (unsigned int) md5[n]);
    }

    INF("Checksum is %s", md5_str);
    return strdup(md5_str);
}

static bool checksum_check(firmware_t *firmware)
{
    char *cksum = NULL;
    bool match = false;

    switch (firmware->cksum.type) {
        case (CKSUM_MD5):
            cksum = get_md5sum();
            break;
        case (CKSUM_SHA1):
        case (CKSUM_SHA2):
        case (CKSUM_SHA3):
        case (CKSUM_SHA256):
            cksum = get_sha256();
            break;
    }

    if (NULL == cksum || NULL == firmware->cksum.val) {
        goto cleanup;
    }

    if (0 == strcmp(cksum, firmware->cksum.val) && strlen(cksum) == strlen(firmware->cksum.val)) {
        match = true;
    } else {
        ERR_MSG("cheksum does not match");
        INF("calculated checksum is %s", cksum);
        INF("expected checksum is %s", firmware->cksum.val);
    }

cleanup:
    if (cksum) {
        free(cksum);
    }
    return match;
}

int firmware_download(ctx_t *ctx)
{
    CURL *curl;
    CURLcode curl_ret;
    int rc = SR_ERR_OK;
    FILE *fd_data = NULL;
    const char *cert_type = "PEM";
    const char *public_keyfile_path = "";
    uint32_t download_attempts = 0;

    /* open file */
    fd_data = fopen(file_path, "wb");
    if (NULL == fd_data) {
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    curl = curl_easy_init();
    if (!curl) {
        goto cleanup;
    }

    switch (ctx->firmware.credentials.type) {
        case (CRED_PASSWD):;
            char *username = get_username_from_url(ctx->firmware.source.uri);
            char *cred = NULL;
            if (NULL != username && NULL != ctx->firmware.credentials.val) {
                char *cred = malloc(sizeof(char) * strlen(username) + strlen(ctx->firmware.credentials.val) + 2);
                sprintf(cred, "%s:%s", username, ctx->firmware.credentials.val);
                free(username);
                free(cred);
            } else {
                cred = strdup(ctx->firmware.credentials.val ? ctx->firmware.credentials.val : "");
            }
            curl_easy_setopt(curl, CURLOPT_USERPWD, cred);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_write_cb);
            free(cred);
            break;
        case (CRED_CERT):
            curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, cert_type);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, firmware_download_ssl);
            break;
        case (CRED_SSH_KEY):
            curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 0);
            curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PUBLICKEY);
            curl_easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, public_keyfile_path);
            curl_easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, public_keyfile_path);
            curl_easy_setopt(curl, CURLOPT_DIRLISTONLY, 1);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_write_cb);
    }

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, ctx->firmware.source.uri);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fd_data);

    // set libcurl timeout to 10 minuts
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (10 * 60));

    while (0 == ctx->firmware.policy.download_attempts ||
           (0 < ctx->firmware.policy.download_attempts && download_attempts < ctx->firmware.policy.download_attempts)) {
        INF_MSG("downloading");
        SET_MEM_STR(ctx->oper.status, "downloading");
        download_attempts++;
        SET_MEM_STR(ctx->oper.message, "starting download with libcurl");
        curl_ret = curl_easy_perform(curl);
        SET_MEM_STR(ctx->oper.message, "libcurl finished");
        if (CURLE_OK == curl_ret) {
            INF_MSG("download-done");
            SET_MEM_STR(ctx->oper.status, "download-done");
            break;
        }
        INF_MSG("downloading-failed");
        SET_MEM_STR(ctx->oper.status, "download-failed");
        uint32_t time = ctx->firmware.policy.retry_interval + (rand() % ctx->firmware.policy.retry_randomness);
        INF("wait for %d seconds", time);
        char message[120];
        sprintf(message, "download failed, starting new attempt in %d seconds", time);
        SET_MEM_STR(ctx->oper.message, message);
        sleep(time);
    }

    /* close the firmware image file */
    fclose(fd_data);
    fd_data = NULL;

    /* checksum checke */
    if (true == checksum_check(&ctx->firmware)) {
        SET_MEM_STR(ctx->oper.message, "correct checksum");
    } else {
        SET_MEM_STR(ctx->oper.message, "wrong checksum");
        rc = SR_ERR_INTERNAL;
    }

cleanup:
    if (fd_data) {
        fclose(fd_data);
    }
    curl_easy_cleanup(curl);

    return rc;
}

int sysupgrade(ctx_t *ctx)
{
    int rc = SR_ERR_OK;
    pid_t pid;
    char command[128];

    if ((pid = fork()) == 0) {
        signal(SIGHUP, SIG_IGN);
        setsid();
        // run sysupgrade
        SET_MEM_STR(ctx->oper.status, "upgrade-in-progress");
        if (ctx->firmware.preserve_configuration) {
            snprintf(command, 128, "sysupgrade %s", file_path);
        } else {
            snprintf(command, 128, "sysupgrade -n %s", file_path);
        }

        SET_MEM_STR(ctx->oper.message, "calling sysupgrade");
        int ret = system(command);
        SET_MEM_STR(ctx->oper.message, "called sysupgrade");
        // int ret = system("true");
        if (-1 == ret) {
            SET_MEM_STR(ctx->oper.status, "upgrade-failed");
        } else {
            SET_MEM_STR(ctx->oper.status, "upgrade-done");
        }

        exit(EXIT_SUCCESS);
    }

    return rc;
}
