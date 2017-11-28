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
#include <sys/types.h>
#include <sys/stat.h>

#include <json-c/json.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include <libubox/md5.h>

#include "common.h"
#include "parse.h"
#include "firmware.h"

const char file_path[FILENAME_MAX] = "/tmp/sr_firmware.bin";

/* update checksum */
bool compare_checksum(firmware_t *firmware)
{
    const char *filename = "/etc/sysrepo/sysupgrade/cksum";
    bool equal = false;
    size_t max_buf_len = 64;

    char source[max_buf_len + 1];
    FILE *file = fopen(filename, "r");
    if (NULL == file) {
        ERR_MSG("fopen returned NULL");
        goto cleanup;
    }

    size_t newLen = fread(source, sizeof(char), max_buf_len, file);
    if (ferror(file) != 0) {
        ERR_MSG("error reading file");
        goto cleanup;
    }

    source[newLen++] = '\0';
    if (0 == strncmp(firmware->cksum.val, source, strlen(firmware->cksum.val))) {
        equal = true;
    }

cleanup:
    if (NULL != file) {
        fclose(file);
    }

    return equal;
}

/* update checksum */
static int update_checksum(firmware_t *firmware)
{
    FILE *file;
    int rc = SR_ERR_OK;
    const char *filename = "/etc/sysrepo/sysupgrade/cksum";

    file = fopen(filename, "w+b");
    CHECK_NULL_MSG(file, &rc, cleanup, "fopen returned NULL");

    char *cksum = firmware->cksum.val;

    fprintf(file, "%s", cksum);

cleanup:
    if (NULL != file) {
        fclose(file);
    }

    return rc;
}

/* copy startup datatsore file to /etc/sysrepo/sysupgrade */
static int copy_file()
{
	char *src = "/etc/sysrepo/data/ietf-system.startup";
	char *dest = "/etc/sysrepo/sysupgrade/ietf-system.startup";
    int fd_dest, fd_src;
    char buf[4096];
    ssize_t nread;

    fd_src = open(src, O_RDONLY);
    if (fd_src < 0) {
        return -1;
	}

    fd_dest = open(dest, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_dest < 0) {
        goto out_error;
	}

    while (nread = read(fd_src, buf, sizeof buf), nread > 0) {
        char *out_ptr = buf;
        ssize_t nwritten;

        do {
            nwritten = write(fd_dest, out_ptr, nread);

            if (nwritten >= 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else if (errno != EINTR) {
                goto out_error;
            }
        } while (nread > 0);
    }

    if (nread == 0) {
        if (close(fd_dest) < 0) {
            fd_dest = -1;
            goto out_error;
        }
        close(fd_src);

        /* Success! */
        return 0;
    }

out_error:
    close(fd_src);
    if (fd_dest >= 0) {
        close(fd_dest);
	}

    return -1;
}

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
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code == 200 && curl_ret != CURLE_ABORTED_BY_CALLBACK) {
                INF_MSG("download-done");
                SET_MEM_STR(ctx->oper.status, "download-done");
                break;
            } else {
                INF_MSG("dl-verification-failed");
                SET_MEM_STR(ctx->oper.status, "dl-verification-failed");
                char message[30] = {0};
                sprintf(message, "libcurl returned error code %ld", http_code);
                SET_MEM_STR(ctx->oper.message, message);
            }
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
    char result[128] = {0};
    char command[128] = {0};
    size_t pid;
    FILE *file = NULL;

    sprintf(command, "sysupgrade -T %s", file_path);

    /* perform sysupgrade check */
    file = popen(command, "r");
    if (NULL == file) {
        ERR("could not run command %s", command);
    }

    while (fgets(result, sizeof(result) - 1, file) != NULL) {
    }
    result[strlen(result) - 1] = '\0';

    if (0 < strlen(result)) {
        /* image check failed */
        ERR("upgrade faild with message:%s", result);
        SET_MEM_STR(ctx->oper.message, result);
        SET_MEM_STR(ctx->oper.status, "upgrade-failed");
        return rc;
    }

    SET_MEM_STR(ctx->oper.status, "upgrade-in-progress");
    SET_MEM_STR(ctx->oper.message, "starting sysupgrade with ubus call");
    if ((pid = fork()) == 0) {
        signal(SIGHUP, SIG_IGN);
        setsid();
        struct blob_buf buf = {0};
        struct json_object *p;
        uint32_t id = 0;
        int u_rc = 0;

        struct ubus_context *u_ctx = ubus_connect(NULL);
        if (u_ctx == NULL) {
            ERR_MSG("Could not connect to ubus");
            goto cleanup;
        }

        blob_buf_init(&buf, 0);
        u_rc = ubus_lookup_id(u_ctx, "juci.sysupgrade", &id);
        if (UBUS_STATUS_OK != u_rc) {
            SET_MEM_STR(ctx->oper.message, "no object juci.sysupgrade");
            ERR("ubus [%d]: no object juci.sysupgrade", u_rc);
            goto cleanup;
        }

        p = json_object_new_object();
        json_object_object_add(p, "path", json_object_new_string(file_path));

        if (ctx->firmware.preserve_configuration) {
            json_object_object_add(p, "keep", json_object_new_string("1"));
            /* if /etc/sysrepo/sysupgrade does not exist, create it */
            const char *dir = "/etc/sysrepo/sysupgrade";
            struct stat st = {0};

            if (stat(dir, &st) == -1) {
                mkdir(dir, 0700);
            }
            copy_file();
            update_checksum(&ctx->firmware);
        } else {
            json_object_object_add(p, "keep", json_object_new_string("0"));
        }
        const char *json_data = json_object_get_string(p);
        blobmsg_add_json_from_string(&buf, json_data);
        json_object_put(p);

        u_rc = ubus_invoke(u_ctx, id, "start", buf.head, NULL, NULL, 0);
        if (UBUS_STATUS_OK != u_rc) {
            SET_MEM_STR(ctx->oper.message, "no object start");
            ERR("ubus [%d]: no object start", u_rc);
            goto cleanup;
        }

        SET_MEM_STR(ctx->oper.status, "upgrade-done");

    cleanup:
        if (NULL != u_ctx) {
            ubus_free(u_ctx);
            blob_buf_free(&buf);
        }
        exit(EXIT_SUCCESS);
    }

    return rc;
}
