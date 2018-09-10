#include <string.h>
#include "apps.h"
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include "cm_helper.h"

static int batch = 0;
static CONF *req_conf;

static int spkac_to_req(X509_REQ *req, const char *spkac) {
   NETSCAPE_SPKI *spki = NULL;
   EVP_PKEY *pktmp = NULL;
   int ok = 0, i, j;

   spki = NETSCAPE_SPKI_b64_decode(spkac, -1);
   if (spki == NULL) {
      printf("unable to load Netscape SPKAC structure\n");
      //ERR_print_errors(bio_err);
      goto end;
   }
   if ((pktmp = NETSCAPE_SPKI_get_pubkey(spki)) == NULL) {
      printf("error unpacking SPKAC public key\n");
      goto end;
   }
   if (NETSCAPE_SPKI_verify(spki, pktmp) <= 0) {
      EVP_PKEY_free(pktmp);
      printf("signature verification failed on SPKAC public key\n");
      goto end;
   }
   printf("Signature ok\n");
   X509_REQ_set_pubkey(req, pktmp);
   EVP_PKEY_free(pktmp);
   ok = 1;
end:
   NETSCAPE_SPKI_free(spki);
   return (ok);
}

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
static int build_subject(X509_REQ *req, const char *subject, unsigned long chtype,
                         int multirdn)
{
    X509_NAME *n;

    if ((n = parse_name(subject, chtype, multirdn)) == NULL)
        return 0;

    if (!X509_REQ_set_subject_name(req, n)) {
        X509_NAME_free(n);
        return 0;
    }
    X509_NAME_free(n);
    return 1;
}

static int req_check_len(int len, int n_min, int n_max)
{
    if ((n_min > 0) && (len < n_min)) {
        printf(
                   "string is too short, it needs to be at least %d bytes long\n",
                   n_min);
        return (0);
    }
    if ((n_max >= 0) && (len > n_max)) {
        printf(
                   "string is too long, it needs to be no more than %d bytes long\n",
                   n_max);
        return (0);
    }
    return (1);
}


static int add_DN_object(X509_NAME *n, char *text, const char *def,
                         char *value, int nid, int n_min, int n_max,
                         unsigned long chtype, int mval)
{
    int i, ret = 0;
    char buf[1024];
 start:
    if (!batch)
        printf("%s [%s]:", text, def);
    //(void) BIO_flush(bio_err);
    if (value != NULL) {
        OPENSSL_strlcpy(buf, value, sizeof(buf));
        OPENSSL_strlcat(buf, "\n", sizeof(buf));
        printf("%s\n", value);
    } else {
        buf[0] = '\0';
        if (!batch) {
            if (!fgets(buf, sizeof(buf), stdin))
                return 0;
        } else {
            buf[0] = '\n';
            buf[1] = '\0';
        }
    }

    if (buf[0] == '\0')
        return (0);
    else if (buf[0] == '\n') {
        if ((def == NULL) || (def[0] == '\0'))
            return (1);
        OPENSSL_strlcpy(buf, def, sizeof(buf));
        OPENSSL_strlcat(buf, "\n", sizeof(buf));
    } else if ((buf[0] == '.') && (buf[1] == '\n'))
        return (1);

    i = strlen(buf);
    if (buf[i - 1] != '\n') {
        printf("weird input :-(\n");
        return (0);
    }
    buf[--i] = '\0';
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, i);
#endif
    if (!req_check_len(i, n_min, n_max)) {
        if (batch || value)
            return 0;
        goto start;
    }

    if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                    (unsigned char *)buf, -1, -1, mval))
        goto err;
    ret = 1;
 err:
    return (ret);
}

/* Check if the end of a string matches 'end' */
static int check_end(const char *str, const char *end)
{
    int elen, slen;
    const char *tmp;
    elen = strlen(end);
    slen = strlen(str);
    if (elen > slen)
        return 1;
    tmp = str + slen - elen;
    return strcmp(tmp, end);
}

static int add_attribute_object(X509_REQ *req, char *text, const char *def,
                                char *value, int nid, int n_min,
                                int n_max, unsigned long chtype)
{
    int i;
    static char buf[1024];

 start:
    if (!batch)
        printf("%s [%s]:", text, def);
    //(void)BIO_flush(bio_err);
    if (value != NULL) {
        OPENSSL_strlcpy(buf, value, sizeof(buf));
        OPENSSL_strlcat(buf, "\n", sizeof(buf));
        printf("%s\n", value);
    } else {
        buf[0] = '\0';
        if (!batch) {
            if (!fgets(buf, sizeof(buf), stdin))
                return 0;
        } else {
            buf[0] = '\n';
            buf[1] = '\0';
        }
    }

    if (buf[0] == '\0')
        return (0);
    else if (buf[0] == '\n') {
        if ((def == NULL) || (def[0] == '\0'))
            return (1);
        OPENSSL_strlcpy(buf, def, sizeof(buf));
        OPENSSL_strlcat(buf, "\n", sizeof(buf));
    } else if ((buf[0] == '.') && (buf[1] == '\n'))
        return (1);

    i = strlen(buf);
    if (buf[i - 1] != '\n') {
        printf("weird input :-(\n");
        return (0);
    }
    buf[--i] = '\0';
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, i);
#endif
    if (!req_check_len(i, n_min, n_max)) {
        if (batch || value)
            return 0;
        goto start;
    }

    if (!X509_REQ_add1_attr_by_NID(req, nid, chtype,
                                   (unsigned char *)buf, -1)) {
        printf("Error adding attribute\n");
        //ERR_print_errors(bio_err);
        goto err;
    }

    return (1);
 err:
    return (0);
}


static int prompt_info(X509_REQ *req,
                       STACK_OF(CONF_VALUE) *dn_sk, const char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, const char *attr_sect,
                       int attribs, unsigned long chtype)
{
    int i;
    char *p, *q;
    char buf[100];
    int nid, mval;
    long n_min, n_max;
    char *type, *value;
    const char *def;
    CONF_VALUE *v;
    X509_NAME *subj;
    subj = X509_REQ_get_subject_name(req);

    if (!batch) {
        printf(
                   "You are about to be asked to enter information that will be incorporated\n");
        printf("into your certificate request.\n");
        printf(
                   "What you are about to enter is what is called a Distinguished Name or a DN.\n");
        printf(
                   "There are quite a few fields but you can leave some blank\n");
        printf(
                   "For some fields there will be a default value,\n");
        printf(
                   "If you enter '.', the field will be left blank.\n");
        printf("-----\n");
    }

    if (sk_CONF_VALUE_num(dn_sk)) {
        i = -1;
 start:for (;;) {
            i++;
            if (sk_CONF_VALUE_num(dn_sk) <= i)
                break;

            v = sk_CONF_VALUE_value(dn_sk, i);
            p = q = NULL;
            type = v->name;
            if (!check_end(type, "_min") || !check_end(type, "_max") ||
                !check_end(type, "_default") || !check_end(type, "_value"))
                continue;
            /*
             * Skip past any leading X. X: X, etc to allow for multiple
             * instances
             */
            for (p = v->name; *p; p++)
                if ((*p == ':') || (*p == ',') || (*p == '.')) {
                    p++;
                    if (*p)
                        type = p;
                    break;
                }
            if (*type == '+') {
                mval = -1;
                type++;
            } else
                mval = 0;
            /* If OBJ not recognised ignore it */
            if ((nid = OBJ_txt2nid(type)) == NID_undef)
                goto start;
            if (BIO_snprintf(buf, sizeof(buf), "%s_default", v->name)
                >= (int)sizeof(buf)) {
                printf("Name '%s' too long\n", v->name);
                return 0;
            }

            if ((def = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                def = "";
            }

            BIO_snprintf(buf, sizeof(buf), "%s_value", v->name);
            if ((value = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                value = NULL;
            }

            BIO_snprintf(buf, sizeof(buf), "%s_min", v->name);
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_min)) {
                ERR_clear_error();
                n_min = -1;
            }

            BIO_snprintf(buf, sizeof(buf), "%s_max", v->name);
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_max)) {
                ERR_clear_error();
                n_max = -1;
            }

            if (!add_DN_object(subj, v->value, def, value, nid,
                               n_min, n_max, chtype, mval))
                return 0;
        }
        if (X509_NAME_entry_count(subj) == 0) {
            printf(
                       "error, no objects specified in config file\n");
            return 0;
        }

        if (attribs) {
            if ((attr_sk != NULL) && (sk_CONF_VALUE_num(attr_sk) > 0)
                && (!batch)) {
                printf(
                           "\nPlease enter the following 'extra' attributes\n");
                printf(
                           "to be sent with your certificate request\n");
            }

            i = -1;
 start2:   for (;;) {
                i++;
                if ((attr_sk == NULL) || (sk_CONF_VALUE_num(attr_sk) <= i))
                    break;

                v = sk_CONF_VALUE_value(attr_sk, i);
                type = v->name;
                if ((nid = OBJ_txt2nid(type)) == NID_undef)
                    goto start2;

                if (BIO_snprintf(buf, sizeof(buf), "%s_default", type)
                    >= (int)sizeof(buf)) {
                    printf("Name '%s' too long\n", v->name);
                    return 0;
                }

                if ((def = NCONF_get_string(req_conf, attr_sect, buf))
                    == NULL) {
                    ERR_clear_error();
                    def = "";
                }

                BIO_snprintf(buf, sizeof(buf), "%s_value", type);
                if ((value = NCONF_get_string(req_conf, attr_sect, buf))
                    == NULL) {
                    ERR_clear_error();
                    value = NULL;
                }

                BIO_snprintf(buf, sizeof(buf), "%s_min", type);
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_min)) {
                    ERR_clear_error();
                    n_min = -1;
                }

                BIO_snprintf(buf, sizeof(buf), "%s_max", type);
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_max)) {
                    ERR_clear_error();
                    n_max = -1;
                }

                if (!add_attribute_object(req,
                                          v->value, def, value, nid, n_min,
                                          n_max, chtype))
                    return 0;
            }
        }
    } else {
        printf("No template, please set one up.\n");
        return 0;
    }

    return 1;

}

static int auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *dn_sk,
                     STACK_OF(CONF_VALUE) *attr_sk, int attribs,
                     unsigned long chtype)
{
    int i, spec_char, plus_char;
    char *p, *q;
    char *type;
    CONF_VALUE *v;
    X509_NAME *subj;

    subj = X509_REQ_get_subject_name(req);

    for (i = 0; i < sk_CONF_VALUE_num(dn_sk); i++) {
        int mval;
        v = sk_CONF_VALUE_value(dn_sk, i);
        p = q = NULL;
        type = v->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (p = v->name; *p; p++) {
#ifndef CHARSET_EBCDIC
            spec_char = ((*p == ':') || (*p == ',') || (*p == '.'));
#else
            spec_char = ((*p == os_toascii[':']) || (*p == os_toascii[','])
                    || (*p == os_toascii['.']));
#endif
            if (spec_char) {
                p++;
                if (*p)
                    type = p;
                break;
            }
        }
#ifndef CHARSET_EBCDIC
        plus_char = (*type == '+');
#else
        plus_char = (*type == os_toascii['+']);
#endif
        if (plus_char) {
            type++;
            mval = -1;
        } else
            mval = 0;
        if (!X509_NAME_add_entry_by_txt(subj, type, chtype,
                                        (unsigned char *)v->value, -1, -1,
                                        mval))
            return 0;

    }

    if (!X509_NAME_entry_count(subj)) {
        printf("error, no objects specified in config file\n");
        return 0;
    }
    if (attribs) {
        for (i = 0; i < sk_CONF_VALUE_num(attr_sk); i++) {
            v = sk_CONF_VALUE_value(attr_sk, i);
            if (!X509_REQ_add1_attr_by_txt(req, v->name, chtype,
                                           (unsigned char *)v->value, -1))
                return 0;
        }
    }
    return 1;
}



static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *subj, int multirdn, int attribs, unsigned long chtype) {
    int ret = 0, i;
    char no_prompt = 0;
    STACK_OF(CONF_VALUE) *dn_sk, *attr_sk = NULL;
    char *tmp, *dn_sect, *attr_sect;

    tmp = NCONF_get_string(req_conf, SECTION, PROMPT);
    if (tmp == NULL)
        ERR_clear_error();
    if ((tmp != NULL) && strcmp(tmp, "no") == 0)
        no_prompt = 1;

    dn_sect = NCONF_get_string(req_conf, SECTION, DISTINGUISHED_NAME);
    if (dn_sect == NULL) {
        printf("unable to find '%s' in config\n",
                   DISTINGUISHED_NAME);
        goto err;
    }
    dn_sk = NCONF_get_section(req_conf, dn_sect);
    if (dn_sk == NULL) {
        printf("unable to get '%s' section\n", dn_sect);
        goto err;
    }

    attr_sect = NCONF_get_string(req_conf, SECTION, ATTRIBUTES);
    if (attr_sect == NULL) {
        ERR_clear_error();
        attr_sk = NULL;
    } else {
        attr_sk = NCONF_get_section(req_conf, attr_sect);
        if (attr_sk == NULL) {
            printf("unable to get '%s' section\n", attr_sect);
            goto err;
        }
    }

    /* setup version number */
    if (!X509_REQ_set_version(req, 0L))
        goto err;               /* version 1 */

    if (subj)
        i = build_subject(req, subj, chtype, multirdn);
    else if (no_prompt)
        i = auto_info(req, dn_sk, attr_sk, attribs, chtype);
    else
        i = prompt_info(req, dn_sk, dn_sect, attr_sk, attr_sect, attribs,
                        chtype);
    if (!i)
        goto err;

    if (pkey && !X509_REQ_set_pubkey(req, pkey))
       goto err;

    ret = 1;
 err:
    return (ret);
}

static int genpkey_cb(EVP_PKEY_CTX *ctx)
{
    char c = '*';
    //uuu
    //BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
    int p;
    p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    //BIO_write(b, &c, 1);
    //(void)BIO_flush(b);
    //printf("%d", p);
    return 1;
}

static EVP_PKEY_CTX *set_keygen_ctx(const char *gstr,
                                    int *pkey_type, long *pkeylen,
                                    char **palgnam, ENGINE *keygen_engine)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *param = NULL;
    long keylen = -1;
    BIO *pbio = NULL;
    const char *paramfile = NULL;

    if (gstr == NULL) {
        *pkey_type = EVP_PKEY_RSA;
        keylen = *pkeylen;
    } else if (gstr[0] >= '0' && gstr[0] <= '9') {
        *pkey_type = EVP_PKEY_RSA;
        keylen = atol(gstr);
        *pkeylen = keylen;
    } else if (strncmp(gstr, "param:", 6) == 0)
        paramfile = gstr + 6;
    else {
        const char *p = strchr(gstr, ':');
        int len;
        ENGINE *tmpeng;
        const EVP_PKEY_ASN1_METHOD *ameth;

        if (p)
            len = p - gstr;
        else
            len = strlen(gstr);
        /*
         * The lookup of a the string will cover all engines so keep a note
         * of the implementation.
         */

        ameth = EVP_PKEY_asn1_find_str(&tmpeng, gstr, len);

        if (!ameth) {
            printf("Unknown algorithm %.*s\n", len, gstr);
            return NULL;
        }

        EVP_PKEY_asn1_get0_info(NULL, pkey_type, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(tmpeng);
#endif
        if (*pkey_type == EVP_PKEY_RSA) {
            if (p) {
                keylen = atol(p + 1);
                *pkeylen = keylen;
            } else
                keylen = *pkeylen;
        } else if (p)
            paramfile = p + 1;
    }

    if (paramfile) {
        pbio = BIO_new_file(paramfile, "r");
        if (!pbio) {
            printf("Can't open parameter file %s\n", paramfile);
            return NULL;
        }
        param = PEM_read_bio_Parameters(pbio, NULL);

        if (!param) {
            X509 *x;
            (void)BIO_reset(pbio);
            x = PEM_read_bio_X509(pbio, NULL, NULL, NULL);
            if (x) {
                param = X509_get_pubkey(x);
                X509_free(x);
            }
        }

        BIO_free(pbio);

        if (!param) {
            printf("Error reading parameter file %s\n", paramfile);
            return NULL;
        }
        if (*pkey_type == -1)
            *pkey_type = EVP_PKEY_id(param);
        else if (*pkey_type != EVP_PKEY_base_id(param)) {
            printf("Key Type does not match parameters\n");
            EVP_PKEY_free(param);
            return NULL;
        }
    }

    if (palgnam) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        ENGINE *tmpeng;
        const char *anam;
        ameth = EVP_PKEY_asn1_find(&tmpeng, *pkey_type);
        if (!ameth) {
            printf("Internal error: can't find key algorithm\n");
            return NULL;
        }
        EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, &anam, ameth);
        *palgnam = OPENSSL_strdup(anam);
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(tmpeng);
#endif
    }

    if (param) {
        gctx = EVP_PKEY_CTX_new(param, keygen_engine);
        *pkeylen = EVP_PKEY_bits(param);
        EVP_PKEY_free(param);
    } else
        gctx = EVP_PKEY_CTX_new_id(*pkey_type, keygen_engine);

    if (gctx == NULL) {
        printf("Error allocating keygen context\n");
        //ERR_print_errors(bio_err);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(gctx) <= 0) {
        printf("Error initializing keygen context\n");
        //ERR_print_errors(bio_err);
        EVP_PKEY_CTX_free(gctx);
        return NULL;
    }
#ifndef OPENSSL_NO_RSA
    if ((*pkey_type == EVP_PKEY_RSA) && (keylen != -1)) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, keylen) <= 0) {
            printf("Error setting RSA keysize\n");
            //ERR_print_errors(bio_err);
            EVP_PKEY_CTX_free(gctx);
            return NULL;
        }
    }
#endif

    return gctx;
}

void * X509_OpenSSL_doreq(EVP_PKEY ** ppkey, int x509, unsigned char * config, unsigned char * serialt, unsigned char * md, unsigned char * keytype, int days, unsigned char * pkeyt, unsigned char * spkac) {
   ASN1_INTEGER *serial = s2i_ASN1_INTEGER(NULL, serialt);

   char *p;
   ENGINE *e = NULL, *gen_eng = NULL;
   int i = 0;
   const EVP_MD *md_alg = NULL, *digest = NULL;
   char *extensions = NULL;
   //char *passin = NULL, *passout = NULL;
   char *req_exts = NULL;
   long newkey = -1;
   char *keyalgstr = NULL;
   EVP_PKEY_CTX *genctx = NULL;
   int pkey_type = -1;
   const EVP_CIPHER *cipher = NULL;
   int multirdn = 0;
   STACK_OF(OPENSSL_STRING) *sigopts = NULL;
   X509_REQ *req = NULL;
   X509 *x509ss = NULL;
   void * ret = NULL;

   // Config laden
   req_conf = cm_app_load_config_mem(BIO_new_mem_buf(config, strlen(config)));
   if (!app_load_modules(req_conf))
      goto end;

   // Signature
   if (!opt_md(md, &md_alg))
      goto end;
   digest = md_alg;

   p = NCONF_get_string(req_conf, SECTION, STRING_MASK);
   if (!p)
      ERR_clear_error();

   if (p && !ASN1_STRING_set_default_mask_asc(p)) {
      printf("Invalid global string mask setting %s\n", p);
      goto end;
   }

   // Optional: UTF8 erlauben
   //chtype = MBSTRING_UTF8;

   // Extensions
   if (!req_exts) {
      req_exts = NCONF_get_string(req_conf, SECTION, REQ_EXTENSIONS);
      if (!req_exts)
         ERR_clear_error();
   }
   if (req_exts) {
      /* Check syntax of file */
      X509V3_CTX ctx;
      X509V3_set_ctx_test(&ctx);
      X509V3_set_nconf(&ctx, req_conf);
      if (!X509V3_EXT_add_nconf(req_conf, &ctx, req_exts, NULL)) {
         printf("Error Loading request extension section %s\n", req_exts);
         goto end;
      }
   }

   if (pkeyt && (strlen(pkeyt) > 0))
      *ppkey = PEM_read_bio_PrivateKey(BIO_new_mem_buf(pkeyt, strlen(pkeyt)), NULL, NULL, "");

   // Key erzeugen
   if (!(spkac && (strlen(spkac))) && (*ppkey == NULL)) {
      char *randfile = NCONF_get_string(req_conf, SECTION, "RANDFILE");
      if (randfile == NULL)
         ERR_clear_error();
      app_RAND_load_file(randfile, 0);
      genctx = set_keygen_ctx(keytype, &pkey_type, &newkey, &keyalgstr, gen_eng);
      if (!genctx)
         goto end;
      if (pkey_type == EVP_PKEY_EC) {
         printf("Generating an EC private key\n");
      } else {
         printf("Generating a %ld bit %s private key\n", newkey, keyalgstr);
      }
      EVP_PKEY_CTX_set_cb(genctx, genpkey_cb);
      if (EVP_PKEY_keygen(genctx, ppkey) <= 0) {
         printf("Error Generating Key\n");
         goto end;
      }
      EVP_PKEY_CTX_free(genctx);
      genctx = NULL;
      app_RAND_write_file(randfile);
      if (*ppkey == NULL) {
         printf("you need to specify a private key\n");
         goto end;
      }
   }

   if (req == NULL) {
      req = X509_REQ_new();
      if (req == NULL) {
         printf("Req undefined\n");
         goto end;
      }
      i = make_REQ(req, *ppkey, NULL, multirdn, !x509, chtype);
      if (!i) {
         printf("problems making Certificate Request\n");
         goto end;
      }
      if (spkac && (strlen(spkac))) {
         printf("Using SPKAC public key\n");
         spkac_to_req(req, spkac);
      }
   } else {
      printf("Req already defined\n");
   }
   if (x509) {
      EVP_PKEY *tmppkey;
      X509V3_CTX ext_ctx;
      if ((x509ss = X509_new()) == NULL) {
         printf("X509_new\n");
         goto end;
      }
      /* Set version to V3 */
      if (extensions && !X509_set_version(x509ss, 2)) {
         printf("X509_set_version\n");
         goto end;
      }
      if (serial) {
         if (!X509_set_serialNumber(x509ss, serial)) {
            printf("rand_serial\n");
            goto end;
         }
      } else {
         if (!rand_serial(NULL, X509_get_serialNumber(x509ss))) {
            printf("X509_get_serialNumber\n");
            goto end;
         }
      }
      if (!X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req))) {
         printf("X509_set_issuer_name\n");
         goto end;
      }
      if (!set_cert_times(x509ss, NULL, NULL, days)) {
         printf("set_cert_times\n");
         goto end;
      }
      if (!X509_set_subject_name(x509ss, X509_REQ_get_subject_name(req))) {
         printf("X509_set_subject_name\n");
         goto end;
      }
      tmppkey = X509_REQ_get0_pubkey(req);
      if (!tmppkey || !X509_set_pubkey(x509ss, tmppkey)) {
         printf("X509_REQ_get0_pubkey\n");
         goto end;
      }
      /* Set up V3 context struct */
      X509V3_set_ctx(&ext_ctx, x509ss, x509ss, NULL, NULL, 0);
      X509V3_set_nconf(&ext_ctx, req_conf);
      /* Add extensions */
      if (extensions && !X509V3_EXT_add_nconf(req_conf, &ext_ctx, extensions, x509ss)) {
         printf("Error Loading extension section %s\n", extensions);
         goto end;
      }
      if (*ppkey) {
         i = do_X509_sign(x509ss, *ppkey, digest, sigopts);
         if (!i) {
            // TODO:XXX:FIXME: ERR_print_errors(bio_err);
            printf("do_X509_sign\n", extensions);
            goto end;
         }
      }
   } else {
      X509V3_CTX ext_ctx;
      /* Set up V3 context struct */
      X509V3_set_ctx(&ext_ctx, NULL, NULL, req, NULL, 0);
      X509V3_set_nconf(&ext_ctx, req_conf);
      /* Add extensions */
      if (req_exts && !X509V3_EXT_REQ_add_nconf(req_conf, &ext_ctx, req_exts, req)) {
          printf("Error Loading extension section %s\n", req_exts);
          goto end;
      }
      if (*ppkey) {
         i = do_X509_REQ_sign(req, *ppkey, digest, sigopts);
         if (!i) {
            // TODO:XXX:FIXME: ERR_print_errors(bio_err);
            printf("do_X509_REQ_sign\n", extensions);
            goto end;
         }
      }
   }

   if (x509) {
      ret = (void *) x509ss;
   } else {
      ret = (void *) req;
   }
   end:

   //if (ret) {
   // TODO:XXX:FIXME: ERR_print_errors(bio_err);
   //}
   NCONF_free(req_conf);
   EVP_PKEY_CTX_free(genctx);
   sk_OPENSSL_STRING_free(sigopts);
   ENGINE_free(gen_eng);
   OPENSSL_free(keyalgstr);
   ASN1_INTEGER_free(serial);
   release_engine(e);
   return ret;
}
