#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "openssl/objects.h"
#include "openssl/rsa.h"

#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/sha.h"

#include "apps.h"
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include "cm_helper.h"

MODULE = X509::Factory      PACKAGE = X509::Factory

SV *
X509_OpenSSL_req(config, serialt, md, keytype, days, pkeyt, spkac)
   unsigned char * config
   unsigned char * serialt
   unsigned char * md
   unsigned char * keytype
   int days
   unsigned char * pkeyt
   unsigned char * spkac
   CODE:
      AV * results = (AV *) sv_2mortal ((SV *) newAV ());

      EVP_PKEY ** ppkey = malloc(sizeof(void *));
      *ppkey = NULL;
      int x509 = 0;
      void * ret = X509_OpenSSL_doreq(ppkey, x509, config, serialt, md, keytype, days, pkeyt, spkac);

       BIO* out = BIO_new(BIO_s_mem());
       unsigned long nmflag = 0, reqflag = 0;
       if (out == NULL)
           goto end;

        char buf[65550] = "";
        int read = 0;
        if (*ppkey) {
           PEM_write_bio_PrivateKey(out, *ppkey, NULL, NULL, 0, NULL, NULL);
           read = BIO_read(out, buf, sizeof(buf));
        }
        av_push (results, newSVpvn(buf, read));
        read = 0;
        if (x509) {
           if (ret) {
              PEM_write_bio_X509(out, (X509*) ret);
              read = BIO_read(out, buf, sizeof(buf));
           }
           av_push (results, newSVpvn(buf, read));
           if (ret) {
              X509_print_ex(out, (X509*) ret, nmflag, reqflag);
              read = BIO_read(out, buf, sizeof(buf));
           }
           av_push (results, newSVpvn(buf, read));
           X509_free((X509*) ret);
        } else {
           if (ret) {
              PEM_write_bio_X509_REQ(out, (X509_REQ*) ret);
              read = BIO_read(out, buf, sizeof(buf));
           }
           av_push (results, newSVpvn(buf, read));
           if (ret) {
              X509_REQ_print_ex(out, (X509_REQ*) ret, nmflag, reqflag);
              read = BIO_read(out, buf, sizeof(buf));
           }
           av_push (results, newSVpvn(buf, read));
           av_push (results, newSViv((IV) ret));
           // Muss vom Aufrufer selbst gefreed werden, weil man das fuer SPKAC
           // weiter nutzen muss.
           //X509_REQ_free((X509_REQ *) ret);
        }
        BIO_free_all(out);

       end:
          EVP_PKEY_free(*ppkey);
          free(ppkey);
          RETVAL = newRV((SV *)results);
       OUTPUT:
           RETVAL

void
X509_OpenSSL_freereq(req)
   X509_REQ * req
   CODE:
      X509_REQ_free(req);

SV *
X509_OpenSSL_sign(cafile, cakeyfile, capassword, reqfiletext, serialt, md, days, extconftext, req)
   char * cafile
   char * cakeyfile
   char * capassword
   char * reqfiletext
   char * serialt
   char * md
   int days
   char * extconftext
   X509_REQ * req
   CODE:
      AV * results = (AV *) sv_2mortal ((SV *) newAV ());

      X509 *x = X509_OpenSSL_dosign(cafile, cakeyfile, capassword, reqfiletext, serialt, md, days, extconftext, req);
      if (x == NULL)
         goto end;

      BIO* out = BIO_new(BIO_s_mem());
      if (out == NULL)
         goto end;

      char mybuf[65550] = "";
      PEM_write_bio_X509(out, x);
      int read = BIO_read(out, mybuf, sizeof(mybuf));
      av_push (results, newSVpvn(mybuf, read));

      X509_print_ex(out, x, 0, 0);
      read = BIO_read(out, mybuf, sizeof(mybuf));
      av_push (results, newSVpvn(mybuf, read));

      end:
      if (out != NULL)
         BIO_free_all(out);
      X509_free(x);
      RETVAL = newRV((SV *)results);
   OUTPUT:
        RETVAL

SV *
X509_OpenSSL_pkcs12(passin, passout, certsfile, keyfile, macalg)
   unsigned char * passin
   unsigned char * passout
   unsigned char * certsfile
   unsigned char * keyfile
   unsigned char * macalg
   CODE:
      ST(0) = sv_newmortal();
      PKCS12* p12 = X509_OpenSSL_dopkcs12(passin, passout, certsfile, keyfile, macalg);
      BIO* out = NULL;
      if (p12) {
        out = BIO_new(BIO_s_mem());
        if (out == NULL)
           goto end;
        char mybuf[65550] = "";
        i2d_PKCS12_bio(out, p12);
        int read = BIO_read(out, mybuf, sizeof(mybuf));
        //printf("RESULT:%d\n", read);
        sv_setpvn(ST(0), mybuf, read);
      } else {
        printf("Failed to run dopkcs12\n");
      }
      end:
      if (out != NULL)
         BIO_free_all(out);
      PKCS12_free(p12);
