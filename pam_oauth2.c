#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <curl/curl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include "jsmn/jsmn.h"

struct response {
    char *ptr;
    size_t len;
};

struct check_tokens {
    const char *key;
    int key_len;
    const char *value;
    int value_len;
    int match;
};

static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct response *r) {
    size_t data_size = size * nmemb;
    size_t new_len = r->len + data_size;
    char *new_ptr = realloc(r->ptr, new_len + 1);

    if (new_ptr == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: memory allocation failed");
        return 0;
    }

    r->ptr = new_ptr;

    memcpy(r->ptr + r->len, ptr, data_size);
    r->ptr[r->len = new_len] = '\0';

    return data_size;
}

static int skip_object(const jsmntok_t *t, const int count) {
    int i;
    if (count <= 0) return 0; /* should not happen */

    if (t->type == JSMN_PRIMITIVE || t->type == JSMN_STRING) {
        return 1;
    } else if (t->type == JSMN_OBJECT) {
        int ret = 1;
        for (i = 0; i < t->size; ++i) {
            ret += skip_object(t + ret, count - ret);
            ret += skip_object(t + ret, count - ret);
        }
        return ret;
    } else if (t->type == JSMN_ARRAY) {
        int ret = 1;
        for (i = 0; i < t->size; ++i)
            ret += skip_object(t + ret, count - ret);
        return ret;
    } else return 0;
}

static int check_response(const struct response token_info, struct check_tokens *ct) {
    const char * const response_data = token_info.ptr;
    struct check_tokens *cti;
    int r, i = 1;
    jsmn_parser p;
    jsmntok_t t[128]; /* We expect no more than 128 tokens */

    jsmn_init(&p);
    if ((r = jsmn_parse(&p, response_data, token_info.len, t, sizeof(t)/sizeof(t[0]))) < 0) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: Failed to parse tokeninfo JSON response");
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* Assume the top-level element is an object */
    if (r-- < 1 || t[0].type != JSMN_OBJECT) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: tokeninfo response: JSON Object expected");
        return PAM_AUTHINFO_UNAVAIL;
    }

    while (r > 0) {
        if (t[i].type == JSMN_STRING) {
            --r;
            /* try to find "interesting" keys in the top-level element object */
            for (cti = ct; cti->key != NULL; ++cti) {
                if (cti->key_len == t[i].end - t[i].start &&
                        strncmp(response_data + t[i].start, cti->key, cti->key_len) == 0) {
                    ++i;
                    if (t[i].type == JSMN_STRING && cti->value_len == t[i].end - t[i].start &&
                            strncmp(response_data + t[i].start, cti->value, cti->value_len) == 0) {
                        ++i; --r;
                        cti->match = 1;
                        break;
                    } else {
                        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: '%.*s' value doesn't meet expectation: '%.*s' != '%.*s'",
                            cti->key_len, cti->key, t[i].end - t[i].start, response_data + t[i].start, cti->value_len, cti->value);
                        return PAM_AUTH_ERR;
                    }
                }
            }

            /* skip value, because key was not interesting for us */
            if (cti->key == NULL) {
                int skipped = skip_object(t + ++i, r);
                r -= skipped; i += skipped;
            }
        } else {
            int skipped = skip_object(t + i, r);
            r -= skipped; i += skipped;
            skipped = skip_object(t + i, r);
            r -= skipped; i += skipped;
        }
    }

    r = PAM_SUCCESS;
    for (cti = ct; cti->key != NULL; ++cti) {
        if (cti->match == 0) {
            syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't find '%.*s' field in the tokeninfo JSON response object",
                cti->key_len, cti->key);
            if (cti == ct) {  /* login token field always come first */
                r = PAM_USER_UNKNOWN;
            } else if (r != PAM_USER_UNKNOWN) {
                r = PAM_AUTH_ERR;
            }
        }
    }

    if (r == PAM_SUCCESS)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: successfully authenticated '%.*s'", ct->value_len, ct->value);

    return r;
}

static int query_token_info(const char * const tokeninfo_url, const char * const authtok, long *response_code, struct response *token_info) {
    int ret = 1;
    char *url;
    CURL *session = curl_easy_init();

    if (!session) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't initialize curl");
        return ret;
    }

    if ((url = malloc(strlen(tokeninfo_url) + strlen(authtok) + 1))) {
        strcpy(url, tokeninfo_url);
        strcat(url, authtok);

        curl_easy_setopt(session, CURLOPT_URL, url);
        curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(session, CURLOPT_WRITEDATA, token_info);

        if (curl_easy_perform(session) == CURLE_OK &&
                curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, response_code) == CURLE_OK) {
            ret = 0;
        } else {
            syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: failed to perform curl request");
        }

        free(url);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: memory allocation failed");
    }

    curl_easy_cleanup(session);

    return ret;
}

static int oauth2_authenticate(const char * const tokeninfo_url, const char * const authtok, struct check_tokens *ct) {
    struct response token_info;
    long response_code = 0;
    int ret;

    if ((token_info.ptr = malloc(1)) == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: memory allocation failed");
        return PAM_AUTHINFO_UNAVAIL;
    }
    token_info.ptr[token_info.len = 0] = '\0';

    if (query_token_info(tokeninfo_url, authtok, &response_code, &token_info) != 0) {
        ret = PAM_AUTHINFO_UNAVAIL;
    } else if (response_code == 200) {
        ret = check_response(token_info, ct);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: authentication failed with response_code=%li", response_code);
        ret = PAM_AUTH_ERR;
    }

    free(token_info.ptr);

    return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tokeninfo_url = NULL, *authtok = NULL;
    struct check_tokens ct[argc];
    int i, ct_len = 1;
    ct->key = ct->value = NULL;

    if (argc > 0) tokeninfo_url = argv[0];
    if (argc > 1) ct[0].key = argv[1];

    if (tokeninfo_url == NULL || *tokeninfo_url == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: tokeninfo_url is not defined or invalid");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (ct->key == NULL || *ct->key == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: login_field is not defined or empty");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (pam_get_user(pamh, &ct->value, NULL) != PAM_SUCCESS || ct->value == NULL || *ct->value == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get user login");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL) != PAM_SUCCESS || authtok == NULL || *authtok == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get authtok");
        return PAM_AUTHINFO_UNAVAIL;
    }

    ct->key_len = strlen(ct->key);
    ct->value_len = strlen(ct->value);
    ct->match = 0;

    for (i = 2; i < argc; ++i) {
        const char *value = strchr(argv[i], '=');
        if (value != NULL) {
            ct[ct_len].key = argv[i];
            ct[ct_len].key_len = value - argv[i];
            ct[ct_len].value = value + 1;
            ct[ct_len].value_len = strlen(value + 1);
            ct[ct_len++].match = 0;
        }
    }
    ct[ct_len].key = NULL;

    return oauth2_authenticate(tokeninfo_url, authtok, ct);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_CRED_UNAVAIL;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
