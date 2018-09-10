#define ATTRIBUTES      "attributes"
#define PROMPT          "prompt"
#define DISTINGUISHED_NAME      "distinguished_name"
#define BITS            "default_bits"
#define V3_EXTENSIONS   "x509_extensions"
#define UTF8_IN         "utf8"
#define DEFAULT_KEY_LENGTH      2048
#define MIN_KEY_LENGTH          512

extern unsigned long chtype;

#define SECTION "req"
#define STRING_MASK     "string_mask"
#define REQ_EXTENSIONS  "req_extensions"
CONF *cm_app_load_config_mem(BIO *in);

X509* X509_OpenSSL_dosign(unsigned char * cafile, unsigned char * cakeyfile, unsigned char * capassword, unsigned char * reqfiletext, unsigned char * serialt, unsigned char * md, int days, unsigned char * extconftext, X509_REQ * req);
void * X509_OpenSSL_doreq(EVP_PKEY ** ppkey, int x509, unsigned char * config, unsigned char * serialt, unsigned char * md, unsigned char * keytype, int days, unsigned char * pkeyt, unsigned char * spkac);
PKCS12* X509_OpenSSL_dopkcs12(unsigned char * passin, unsigned char * passout, unsigned char * certsfile, unsigned char * keyfile, unsigned char * macalg);
