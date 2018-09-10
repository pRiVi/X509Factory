#include <string.h>
#include "apps.h"
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include "cm_helper.h"

static int batch = 0;
static CONF *req_conf;

static int cm_pem_password_cb(char *buf, int size, int rwflag, void *u) {
   strncpy(buf, (unsigned char *) u, size);
   buf[size - 1] = '\0';
   return strlen((unsigned char *) u);
}

static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts) {
    EVP_PKEY_CTX *pkctx = NULL;
    int i;
    if (ctx == NULL)
        return 0;
    if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
        return 0;
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            printf("parameter error \"%s\"\n", sigopt);
            // ERR_print_errors(bio_err);
            return 0;
        }
    }
    return 1;
}

int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts) {
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}

int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts) {
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_REQ_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}

static int x509_certify(X509_STORE *ctx, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        const char *serialfile, int create,
                        int days, int clrext, CONF *conf, const char *section,
                        ASN1_INTEGER *sno, int reqfile) {
    int ret = 0;
    ASN1_INTEGER *bs = NULL;
    X509_STORE_CTX *xsc = NULL;
    EVP_PKEY *upkey;
    upkey = X509_get0_pubkey(xca);
    if (upkey == NULL) {
        printf("Error obtaining CA X509 public key\n");
        goto end;
    }
    EVP_PKEY_copy_parameters(upkey, pkey);

    xsc = X509_STORE_CTX_new();
    if (xsc == NULL || !X509_STORE_CTX_init(xsc, ctx, x, NULL)) {
        printf("Error initialising X509 store\n");
        goto end;
    }
    if (sno)
        bs = sno;
    else {
        printf("No serial\n");
        goto end;
    }

    /*
     * NOTE: this certificate can/should be self signed, unless it was a
     * certificate request in which case it is not.
     */
    X509_STORE_CTX_set_cert(xsc, x);
    X509_STORE_CTX_set_flags(xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!reqfile && X509_verify_cert(xsc) <= 0) {
        printf("X509_verify_cert\n");
        goto end;
    }

    if (!X509_check_private_key(xca, pkey)) {
        printf("CA certificate and CA private key do not match\n");
        goto end;
    }

    if (!X509_set_issuer_name(x, X509_get_subject_name(xca))) {
       printf("X509_set_issuer_name\n");
       goto end;
    }
    if (!X509_set_serialNumber(x, bs)) {
        printf("X509_set_serialNumber\n");
        goto end;
    }

    if (!set_cert_times(x, NULL, NULL, days)) {
       printf("set_cert_times\n");
       goto end;
    }

    if (clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }

    if (conf) {
        X509V3_CTX ctx2;
        X509_set_version(x, 2); /* version 3 certificate */
        X509V3_set_ctx(&ctx2, xca, x, NULL, NULL, 0);
        X509V3_set_nconf(&ctx2, conf);
        if (!X509V3_EXT_add_nconf(conf, &ctx2, section, x)) {
           printf("X509V3_EXT_add_nconf\n");
           goto end;
        }
    }

    if (!do_X509_sign(x, pkey, digest, sigopts)){
      printf("do_X509_sign\n");
      goto end;
    }
    ret = 1;
 end:
    X509_STORE_CTX_free(xsc);
    if (!ret)
        //ERR_print_errors(bio_err);
        printf("x509_certify error\n");
    if (!sno)
        ASN1_INTEGER_free(bs);
    return ret;
}

X509* X509_OpenSSL_dosign(unsigned char * cafile, unsigned char * cakeyfile, unsigned char * capassword, unsigned char * reqfiletext, unsigned char * serialt, unsigned char * md, int days, unsigned char * extconftext, X509_REQ * req) {
   int reqfile = 1;

   ASN1_INTEGER *sno = s2i_ASN1_INTEGER(NULL, serialt);
   X509_STORE *ctx = NULL;
   EVP_PKEY * CApkey = NULL, *fkey = 0;
   int need_rand = 1;
   X509 *x = NULL;
   unsigned long nmflag = 0;
   int i = 0;
   ctx = X509_STORE_new();
   if (ctx == NULL)
      goto end;

   if (cakeyfile && (strlen(cakeyfile) > 0)) {
      CApkey = PEM_read_bio_PrivateKey(BIO_new_mem_buf(cakeyfile, strlen(cakeyfile)), NULL, &cm_pem_password_cb, capassword);
      if (CApkey == NULL)
         printf("Error loading CA private key!\n");
   }

   if (!X509_STORE_set_default_paths(ctx)) {
      //ERR_print_errors(bio_err);
      printf("X509_STORE_set_default_paths\n");
      goto end;
   }

   CONF *extconf = NULL;
   char *extsect = NULL;
   X509V3_CTX ctx2;

   if (extconftext && strlen(extconftext)) {
      extconf = cm_app_load_config_mem(BIO_new_mem_buf(extconftext, strlen(extconftext)));
      if (!extsect) {
         extsect = NCONF_get_string(extconf, "default", "extensions");
         if (!extsect) {
            ERR_clear_error();
            extsect = "default";
         }
      }
      X509V3_set_ctx_test(&ctx2);
      X509V3_set_nconf(&ctx2, extconf);
      if (!X509V3_EXT_add_nconf(extconf, &ctx2, extsect, NULL)) {
         printf("Error Loading extension section %s\n", extsect);
         //ERR_print_errors(bio_err);
         goto end;
      }
   }

   EVP_PKEY *pkey;
   if (req == NULL) {
      BIO *in;
      /* if (!sign_flag && !CA_flag) {
         printf("We need a private key to sign with\n");
         goto end;
      } */
      in = BIO_new_mem_buf(reqfiletext, strlen(reqfiletext)); //bio_open_default(infile, 'r', informat);
      if (in == NULL) {
         printf("BIO failed\n");
         goto end;
      }
      req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
      BIO_free(in);

      if (req == NULL) {
         //ERR_print_errors(bio_err);
         printf("Failed to parse request with length of %d bytes\n", strlen(reqfiletext));
         goto end;
      }
      if ((pkey = X509_REQ_get0_pubkey(req)) == NULL) {
         printf("error unpacking public key\n");
         goto end;
      }
      i = X509_REQ_verify(req, pkey);
      if (i < 0) {
         printf("Signature verification error\n");
         //ERR_print_errors(bio_err);
         goto end;
      }
      if (i == 0) {
         printf("Signature did not match the certificate request\n");
         goto end;
      } else
         //printf("Signature ok\n")
      ;
    }


      printf("subject=", X509_REQ_get_subject_name(req));
      if ((x = X509_new()) == NULL) {
         printf("Failed to create new cert\n");
         goto end;
      }

      if (sno == NULL) {
         sno = ASN1_INTEGER_new();
         if (sno == NULL || !rand_serial(NULL, sno)) {
            printf("Failed to generate serial\n");
            goto end;
         }
         if (!X509_set_serialNumber(x, sno)) {
            printf("Failed to set generated serial\n");
            goto end;
         }
         ASN1_INTEGER_free(sno);
         sno = NULL;
      } else if (!X509_set_serialNumber(x, sno)) {
         printf("Failed to set serial\n");
         goto end;
      }

      if (!X509_set_issuer_name(x, X509_REQ_get_subject_name(req))) {
         printf("Failed to set issuer name\n");
         goto end;
      }

      if (!X509_set_subject_name(x, X509_REQ_get_subject_name(req))) {
         printf("Failed to set subject name\n");
         goto end;
      }

      if (!set_cert_times(x, NULL, NULL, days)) {
         printf("Failed to set cert times\n");
         goto end;
      }

      if (fkey)
         X509_set_pubkey(x, fkey);
      else {
         pkey = X509_REQ_get0_pubkey(req);
         X509_set_pubkey(x, pkey);
      }
   //} else
   //      x = load_cert(infile, informat, "Certificate");

   X509 *xca = PEM_read_bio_X509(BIO_new_mem_buf(cafile, strlen(cafile)), NULL, 0, NULL);
   if (xca == NULL) {
      printf("Failed to read ca\n");
      goto end;
   }
   //printf("Getting CA Private Key: %s %p\n", cakeyfile, CApkey);
   if (CApkey == NULL) {
      printf("No CA private key\n");
      goto end;
   }

   const EVP_MD *digest = NULL;
   if (!opt_md(md, &digest)) {
      printf("Invalid digest\n");
      goto end;
   }
   int CA_createserial = 1;
   int clrext = 0;
   STACK_OF(OPENSSL_STRING) *sigopts = NULL;
   assert(need_rand);
   if (!x509_certify(ctx,  digest, x, xca, CApkey, sigopts,
      NULL, CA_createserial, days, clrext,
      extconf, extsect, sno, reqfile))
      goto end;

   end:
   if (need_rand)
      app_RAND_write_file(NULL);
   NCONF_free(extconf);
   X509_STORE_free(ctx);
   X509_REQ_free(req);
   X509_free(xca);
   EVP_PKEY_free(CApkey);
   EVP_PKEY_free(fkey);
   sk_OPENSSL_STRING_free(sigopts);
   ASN1_INTEGER_free(sno);
   return x;
}
