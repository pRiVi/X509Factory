#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include "cm_helper.h"

static int batch = 0;
static CONF *req_conf;

static int cm_pem_password_cb(char *buf, int size, int rwflag, void *u) {
   strncpy(buf, (unsigned char *) u, size);
   buf[size - 1] = '\0';
   return strlen((unsigned char *) u);
}

static int cm_load_certs(const char *certs, char *pass, const char *desc, STACK_OF(X509) **pcerts) {
   int i;
   BIO *bio;
   STACK_OF(X509_INFO) *xis = NULL;
   X509_INFO *xi;
   PW_CB_DATA cb_data;
   int rv = 0;

   xis = PEM_X509_INFO_read_bio(BIO_new_mem_buf(certs, strlen(certs)), NULL, &cm_pem_password_cb, pass);
   if (pcerts && *pcerts == NULL) {
      *pcerts = sk_X509_new_null();
      if (!*pcerts)
         goto end;
   }
   for (i = 0; i < sk_X509_INFO_num(xis); i++) {
      xi = sk_X509_INFO_value(xis, i);
      if (xi->x509 && pcerts) {
         if (!sk_X509_push(*pcerts, xi->x509))
            goto end;
         xi->x509 = NULL;
      }
   }
   if (pcerts && sk_X509_num(*pcerts) > 0)
      rv = 1;
end:
   sk_X509_INFO_pop_free(xis, X509_INFO_free);
   if (rv == 0) {
      if (pcerts) {
         sk_X509_pop_free(*pcerts, X509_free);
         *pcerts = NULL;
       }
       printf("unable to load %s\n", pcerts ? "certificates" : "CRLs");
       //ERR_print_errors(bio_err);
   }
   return rv;
}

PKCS12* X509_OpenSSL_dopkcs12(unsigned char * passin, unsigned char * passout, unsigned char * certsfile, unsigned char * keyfile, unsigned char * macalg) {
   char *cpass = NULL;
   //char pass[2048] = "";
   int maciter = PKCS12_DEFAULT_ITER;

   app_RAND_load_file(NULL, 0);
   /* if (inrand != NULL)
      printf("%ld semi-random bytes loaded\n", app_RAND_load_files(inrand)); */

   int keytype = 0;
   PKCS12 *p12 = NULL;
   PKCS12 *p12return = NULL;
   EVP_PKEY *key = NULL;
   char *name = NULL;
   X509 *ucert = NULL, *x = NULL;
   STACK_OF(X509) *certs = NULL;
   const EVP_MD *macmd = NULL;
   unsigned char *catmp = NULL;
   int key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
   int cert_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC; // NID_pbe_WithSHA1And40BitRC2_CBC;
   int iter = PKCS12_DEFAULT_ITER;
   int i;
   //if (keyfile && (strlen(keyfile) > 0)) {
      key = PEM_read_bio_PrivateKey(BIO_new_mem_buf(keyfile, strlen(keyfile)), NULL, &cm_pem_password_cb, passin);
      if (key == NULL) {
         printf("Error loading private key!\n");
         goto export_end;
      }
   //}
   /* Load in all certs in input file */
      if (!cm_load_certs(certsfile, passin, "certificates", &certs)) {
         printf("Error loading certs!\n");
         goto export_end;
      }
      //if (key) {
         /* Look for matching private key */
         for (i = 0; i < sk_X509_num(certs); i++) {
             x = sk_X509_value(certs, i);
             if (X509_check_private_key(x, key)) {
                ucert = x;
                /* Zero keyid and alias */
                 X509_keyid_set1(ucert, NULL, 0);
                 X509_alias_set1(ucert, NULL, 0);
                    /* Remove from list */
                    (void)sk_X509_delete(certs, i);
                    break;
                }
            }
            if (!ucert) {
                printf("No certificate matches private key\n");
                goto export_end;
            }
      //  }

      /* // Add any more certificates asked for
      if (certfile) {
          if (!load_certs(certfile, &certs, FORMAT_PEM, NULL, "certificates from certfile"))
             goto export_end;
      }

      // If chaining get chain from user cert
      if (chain) {
          int vret;
          STACK_OF(X509) *chain2;
          X509_STORE *store;
          if ((store = setup_verify(CAfile, CApath, noCAfile, noCApath)) == NULL)
             goto export_end;
          vret = get_cert_chain(ucert, store, &chain2);
          X509_STORE_free(store);
          if (vret == X509_V_OK) {
              // Exclude verified certificate
              for (i = 1; i < sk_X509_num(chain2); i++)
                  sk_X509_push(certs, sk_X509_value(chain2, i));
              // Free first certificate
              X509_free(sk_X509_value(chain2, 0));
              sk_X509_free(chain2);
          } else {
              if (vret != X509_V_ERR_UNSPECIFIED)
                  BIO_printf(bio_err, "Error %s getting chain.\n", X509_verify_cert_error_string(vret));
              else
                  ERR_print_errors(bio_err);
              goto export_end;
          }
      } */

   p12 = PKCS12_create(passout, name, key, ucert, certs, key_pbe, cert_pbe, iter, -1, keytype);
   if (!p12) {
      //ERR_print_errors(bio_err);
      printf("Unable to create pkcs12\n");
      goto export_end;
   }
   if (macalg) {
      if (!opt_md(macalg, &macmd))
         goto export_end;
   }
   if (maciter != -1)
      PKCS12_set_mac(p12, passout, -1, NULL, 0, maciter, macmd);
   p12return = p12;

export_end:
   EVP_PKEY_free(key);
   sk_X509_pop_free(certs, X509_free);
   X509_free(ucert);
   goto end;

end:
  app_RAND_write_file(NULL);
  return p12return;
}
