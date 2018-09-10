#include "apps.h"
#include <openssl/pkcs12.h>
#include "cm_helper.h"

unsigned long chtype = MBSTRING_ASC;
CONF *req_conf = NULL;

CONF *cm_app_load_config_mem(BIO *in) {
    long errorline = -1;
    CONF *conf;
    int i;
    conf = NCONF_new(NULL);
    i = NCONF_load_bio(conf, in, &errorline);
    if (i > 0)
        return conf;
    if (errorline <= 0)
       printf("Can't load config file\n");
    else
       printf("Error on line %ld of config file \"%s\"\n", errorline);
    NCONF_free(conf);
    return NULL;
}

int dgst_main() {
};

int enc_main() {
};
