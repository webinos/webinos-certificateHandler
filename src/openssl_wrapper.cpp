/*******************************************************************************
*  Code contributed to the webinos project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Copyright 2011 University of Oxford
* Copyright 2011 Habib Virji, Samsung Electronics (UK) Ltd
* Copyright 2012 Ziran Sun, Samsung Electronics (UK) Ltd
*******************************************************************************/

#include <node.h>
#include "openssl_wrapper.h"
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

using namespace v8;
/*
 * Note: you CANT use STL in this module - it breaks the Android build.
 */

int genRsaKey(const int bits, char * privkey)
{
  BIO * out = BIO_new(BIO_s_mem());
  RSA * rsa = 0;
  BIGNUM * bn = 0;
  int err = 0;
  if (!(rsa = RSA_new()))  goto error;
  if (!(bn = BN_new()))    goto error;
  if (!(err = BN_set_word(bn,RSA_F4)))  goto error;
  if (!(err = RSA_generate_key_ex(rsa,bits,bn,NULL)))  goto error;
  if (!(err = PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL)))  goto error;
  if (!(err = BIO_read(out,privkey,bits) <= 0))  goto error;
  err = 0;

  error:
    if (bn != NULL)  BN_free(bn);
    if (rsa != NULL) RSA_free(rsa);
    if (out != NULL) BIO_free(out);
    return err;
}

int createCertificateRequest(char* result, char* keyToCertify, char * country, char* state, char* loc,
char* org, char *orgUnit, char* cname, char* email){
  BIO *mem = NULL, *bmem = NULL;
  EVP_PKEY* privkey = NULL;
  X509_REQ *req = NULL;
  X509_NAME *nm=NULL;
  BUF_MEM *bptr=NULL;
  int err=0;
  if(!(mem = BIO_new(BIO_s_mem()))) goto error;
  if(!(req = X509_REQ_new()))       goto error;
  if(!(nm  = X509_NAME_new()))      goto error;
  //fill in details
  if (strlen(country) > 0 && !(err = X509_NAME_add_entry_by_txt(nm,"C", MBSTRING_UTF8, (unsigned char*)country, -1, -1, 0))) goto error;
  if (strlen(state)   > 0 && !(err = X509_NAME_add_entry_by_txt(nm,"ST",MBSTRING_UTF8, (unsigned char*)state,   -1, -1, 0))) goto error;
  if (strlen(loc)     > 0 && !(err = X509_NAME_add_entry_by_txt(nm,"L", MBSTRING_UTF8, (unsigned char*)loc,     -1, -1, 0))) goto error;
  if (strlen(org)     > 0 && !(err = X509_NAME_add_entry_by_txt(nm,"O", MBSTRING_UTF8, (unsigned char*)org,     -1, -1, 0))) goto error;
  if (strlen(orgUnit) > 0 && !(err = X509_NAME_add_entry_by_txt(nm,"OU",MBSTRING_UTF8, (unsigned char*)orgUnit, -1, -1, 0))) goto error;
   // This is mandatory to have, rest are optional
  if (strlen(cname)   > 0 && !(err = X509_NAME_add_entry_by_txt(nm,"CN", MBSTRING_UTF8, (unsigned char*) cname, -1, -1, 0))) goto error;
  if (strlen(email)   > 0 && !(err = X509_NAME_add_entry_by_txt(nm,"emailAddress",MBSTRING_UTF8,(unsigned char*)email, -1, -1, 0))) goto error;
  if (!(X509_REQ_set_subject_name(req, nm))) goto error;
  if (!(bmem = BIO_new_mem_buf(keyToCertify, -1))) goto error;//Set the public key,convert PEM private key into a BIO
  if (!(privkey = PEM_read_bio_PrivateKey(bmem, NULL, NULL, NULL))) goto error;// read the private key into an EVP_PKEY structure
  if (!(err = X509_REQ_set_pubkey(req, privkey))) goto error;
  if (!(err = X509_REQ_set_version(req,3))) goto error;
  if (!(err = PEM_write_bio_X509_REQ(mem, req))) goto error;  //write it to PEM format

  BIO_get_mem_ptr(mem, &bptr);
  BIO_read(mem, result, bptr->length);
  err = 0;
  error:
    if(bmem    != NULL) BIO_free(bmem);
    if(mem     != NULL) BIO_free(mem);
    if(privkey != NULL) EVP_PKEY_free(privkey);
    if(req     != NULL) X509_REQ_free(req);
    if(nm      != NULL) X509_NAME_free(nm);
    return err;
}

int getHash(char* filename, char *pointer){
  struct stat           sb;
  char                * buff;
  FILE                * fd;
  size_t                len;
  BIO                 * bio;
  X509                * x;
  unsigned              err;
  char                  errmsg[1024];
  const EVP_MD        * digest;
  unsigned char         md[EVP_MAX_MD_SIZE];
  unsigned int          n;
  int j;

  // checks file
  if ((stat(filename, &sb)) == -1)
  {
    perror("getHash: stat()");
    return(1);
  };
  len = (sb.st_size * 2);

  // allocates memory
  if (!(buff = (char*)malloc(len)))
  {
    fprintf(stderr, "getHash: out of virtual memory\n");
    return(1);
  };

  // opens file for reading
  if ((fd = fopen(filename, "r")) == NULL)
  {
    perror("getHash: open()");
    free(buff);
    return(1);
  };

  // reads file
  if (!fread(buff, 1, len, fd))
  {
    perror("getHash: read()");
    free(buff);
    return(1);
  };

  // closes file
  fclose(fd);

  // initialize OpenSSL

  // creates BIO buffer
  bio = BIO_new_mem_buf(buff, len);

  // decodes buffer
  if (!(x = PEM_read_bio_X509(bio, NULL, 0L, NULL)))
  {
    while((err = ERR_get_error()))
    {
      errmsg[1023] = '\0';
      ERR_error_string_n(err, errmsg, 1023);
      fprintf(stderr, "peminfo: %s\n", errmsg);
    };
    BIO_free(bio);
    free(buff);
    return(1);
  };
  
  OpenSSL_add_all_digests();
  digest = EVP_get_digestbyname("sha1");
  if(X509_digest(x, digest, md, &n) && n > 0) {
    static const char hexcodes[] = "0123456789ABCDEF";
    for (j = 0; j < (int) n; j++) {
      pointer[j * 3] = hexcodes[(md[j] & 0xf0) >> 4U];
      pointer[(j * 3) + 1] = hexcodes[(md[j] & 0x0f)];
      if (j + 1 != (int) n) {
        pointer[(j * 3) + 2] = ':';
      } 
      else {
        pointer[(j * 3) + 2] = '\0';
      }
    }
  }
  X509_free(x);
  BIO_free(bio);
  free(buff);

  return(0);
}

ASN1_INTEGER* getRandomSN(ASN1_INTEGER *res) {
  BIGNUM *btmp = BN_new();
  BN_pseudo_rand(btmp, 64, 0, 0);//64 bits of randomness?
  BN_to_ASN1_INTEGER(btmp, res);
  BN_free(btmp);
  return res;
}

ASN1_INTEGER* setTimeStart(ASN1_UTCTIME *s) {
  ASN1_UTCTIME_set_string(s, "700101000000Z");
  return s;
}

ASN1_INTEGER* setTimeEnd(ASN1_UTCTIME *s){
  struct tm *t = NULL,valgrind={0};
  t = (struct tm*) malloc(sizeof(struct tm));
  *t= valgrind;
  t->tm_hour = 0;
  t->tm_min = 0;
  t->tm_sec = 0;
  t->tm_year = 120;
  t->tm_mon = 0;
  t->tm_mday = 1;
  ASN1_UTCTIME_set(s, mktime(t));
  free(t);
  return s;

}
int selfSignRequest(char* pemRequest, int days, char* pemCAKey, int certType, char *url, char* result)  {
  BIO *bioReq=NULL, *bioCAKey=NULL, *mem=NULL;
  X509_REQ *req=NULL;
  EVP_PKEY *caKey=NULL, *reqPub=NULL;
  X509 *cert = X509_new();
  BUF_MEM *bptr=NULL;
  int err = 0;
  ASN1_UTCTIME *s=ASN1_UTCTIME_new();
  ASN1_INTEGER* res = ASN1_INTEGER_new();
  X509_EXTENSION *ex=NULL;  // V3 extensions
  X509V3_CTX ctx;

  if(!(bioReq= BIO_new_mem_buf(pemRequest, -1))) goto error;
  if(!(bioCAKey = BIO_new_mem_buf(pemCAKey, -1))) goto error;
  if(!(req=PEM_read_bio_X509_REQ(bioReq, NULL, NULL, NULL))) goto error;
  if(!(caKey = PEM_read_bio_PrivateKey(bioCAKey, NULL, NULL, NULL))) goto error;

//redo all the certificate details, because OpenSSL wants us to work hard
  if(!(err = X509_set_version(cert, 2))) goto error;
  if(!(err = X509_set_issuer_name(cert, X509_REQ_get_subject_name(req)))) goto error;
  if(!(err = X509_set_notBefore(cert, setTimeStart(s)))) goto error;
  if(!(err = X509_set_notAfter(cert, setTimeEnd(s)))) goto error;
  if(!(err = X509_set_subject_name(cert, X509_REQ_get_subject_name(req)))) goto error;
  if (!(reqPub = X509_REQ_get_pubkey(req))) goto error;
  if (!(err = X509_set_pubkey(cert,reqPub))) goto error;
  if (!(err =X509_set_serialNumber(cert, getRandomSN(res)))) goto error;

  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

  if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, (char*)url)))  goto error;
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, (char*)"hash"))) goto error;
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  if( certType == 0) {
    if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, (char*)"critical, CA:TRUE"))) goto error;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    if(!(ex = X509V3_EXT_conf_nid(NULL,  &ctx, NID_key_usage, (char*)"critical, keyCertSign, digitalSignature, cRLSign"))) goto error; /* critical, keyCertSign,cRLSign, nonRepudiation,*/
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    if(!(ex = X509V3_EXT_conf_nid(NULL,  &ctx, NID_ext_key_usage, (char*)"critical, serverAuth"))) goto error;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    if(!(ex = X509V3_EXT_conf_nid(NULL,  &ctx, NID_inhibit_any_policy, (char*)"0"))) goto error;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_crl_distribution_points, (char*)url))) goto error;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
  }

  if (!(err = X509_sign(cert,caKey,EVP_sha1())))  goto error;

  mem = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(mem,cert);
  BIO_get_mem_ptr(mem, &bptr);
  BIO_read(mem, result, bptr->length);
  err = 0;
  error:
    if (res!=NULL)        ASN1_INTEGER_free(res);
    if (s != NULL)        ASN1_UTCTIME_free(s);
    if (caKey != NULL)    EVP_PKEY_free(caKey);
    if (reqPub != NULL)   EVP_PKEY_free(reqPub);
    if (cert != NULL)     X509_free(cert);
    if (req != NULL)      X509_REQ_free(req);
    if (mem != NULL)      BIO_free_all(mem);
    if (bioReq != NULL)   BIO_free_all(bioReq);
    if (bioCAKey != NULL) BIO_free_all(bioCAKey);

  return err;

}

int signRequest(char* pemRequest, int days, char* pemCAKey, char* pemCaCert,  int certType, char *url, char* result)  {
  BIO *bioReq=NULL,*bioCAKey=NULL, *bioCert=NULL, *mem=NULL;
  X509* caCert = NULL, *cert=NULL;
  X509_REQ *req=NULL;
  EVP_PKEY* caKey=NULL, *reqPub=NULL;
  ASN1_UTCTIME *s = ASN1_UTCTIME_new(), *s1 = ASN1_UTCTIME_new();
  ASN1_INTEGER* res = ASN1_INTEGER_new();
  X509_EXTENSION *ex=NULL;
  X509V3_CTX ctx;
  char *str = NULL;
  BUF_MEM *bptr;
  int err = 0;

  if (!(bioReq= BIO_new_mem_buf(pemRequest, -1))) goto error;
  if (!(bioCAKey= BIO_new_mem_buf(pemCAKey, -1))) goto error;
  if (!(bioCert= BIO_new_mem_buf(pemCaCert, -1))) goto error;
  if (!(caCert = PEM_read_bio_X509(bioCert, NULL, NULL, NULL))) goto error;
  if (!(req=PEM_read_bio_X509_REQ(bioReq, NULL, NULL, NULL))) goto error;
  if (!(caKey = PEM_read_bio_PrivateKey(bioCAKey, NULL, NULL, NULL))) goto error;
  if (!(cert = X509_new())) goto error;
  if (!(err =  X509_set_version(cert, 2)))goto error;
  //redo all the certificate details, because OpenSSL wants us to work hard
  if (!(X509_set_issuer_name(cert, X509_get_subject_name(caCert)))) goto error;
  if (!(X509_set_notBefore(cert, setTimeStart(s)))) goto error;
  if (!(X509_set_notAfter(cert, setTimeEnd(s1)))) goto error;

  if (!(X509_set_subject_name(cert, X509_REQ_get_subject_name(req)))) goto error;
  if (!(reqPub = X509_REQ_get_pubkey(req))) goto error;
  if (!(X509_set_pubkey(cert,reqPub))) goto error;
  if (!(X509_set_serialNumber(cert, getRandomSN(res)))) goto error;//create a serial number at random

  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

  if(!(str =(char*)malloc(strlen("caIssuers;") + strlen(url) + 1))) goto error;
  strcpy(str, "caIssuers;");
  strcat(str, url);

  if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_info_access, (char*)str))) goto error;
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, (char*)url))) goto error;
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_issuer_alt_name, (char*)"issuer:copy"))) goto error;
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  if(!(ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, (char*)"hash"))) goto error;
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  if( certType == 1) {
    if(!(ex = X509V3_EXT_conf_nid(NULL,  &ctx, NID_basic_constraints, (char*)"critical, CA:FALSE"))) goto error;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    if(!(ex = X509V3_EXT_conf_nid(NULL,  &ctx, NID_ext_key_usage, (char*)"critical, clientAuth, serverAuth"))) goto error;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
  }
  if (!(err = X509_sign(cert,caKey,EVP_sha1()))) goto error;

  mem = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(mem,cert);
  BIO_get_mem_ptr(mem, &bptr);
  BIO_read(mem, result, bptr->length);
  err =0;
error:
  if(req)      X509_REQ_free(req);
  if(caKey)    EVP_PKEY_free(caKey);
  if(reqPub)   EVP_PKEY_free(reqPub);
  if(s)        ASN1_UTCTIME_free(s);
  if(s1)       ASN1_UTCTIME_free(s1);
  if(res)      ASN1_INTEGER_free(res);
  if(str)      free(str);
  if(cert)     X509_free(cert);
  if(cert)     X509_free(caCert);
  if(mem)      BIO_free_all(mem);
  if(bioReq)   BIO_free_all(bioReq);
  if(bioCert)  BIO_free_all(bioCert);
  if(bioCAKey) BIO_free_all(bioCAKey);

  return err;
}

int createEmptyCRL(char* pemSigningKey, char* pemCaCert, int crldays, int crlhours, char* result) {
  int err = 0;
  BIO *bioCert=NULL, *bioSigningKey=NULL, *mem =NULL;
  X509 *caCert=NULL;
  EVP_PKEY* caKey = NULL;
  X509_CRL* crl=NULL;
  ASN1_UTCTIME *s=NULL;
  BUF_MEM *bptr;
  //convert to BIOs and then keys and x509 structures
  if (!(bioCert= BIO_new_mem_buf(pemCaCert, -1))) goto error;
  if (!(bioSigningKey = BIO_new_mem_buf(pemSigningKey, -1))) goto error;
  if (!(caCert = PEM_read_bio_X509(bioCert, NULL, NULL, NULL))) goto error;
  if (!(caKey = PEM_read_bio_PrivateKey(bioSigningKey, NULL, NULL, NULL))) goto error;
  if (!(crl = X509_CRL_new())) goto error;
  if (!(X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert)))) goto error;
  if (!(s=ASN1_UTCTIME_new())) goto error;//set update times (probably not essential, but why not.
  if (!(X509_CRL_set_lastUpdate(crl, setTimeStart(s)))) goto error;
  if (!(X509_CRL_set_nextUpdate(crl, setTimeEnd(s)))) goto error;
  if (!(X509_CRL_sort(crl))) goto error;
  //extensions would go here.
  if (!(err = X509_CRL_sign(crl,caKey,EVP_sha1()))) goto error;
  mem = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_CRL(mem,crl);
  BIO_get_mem_ptr(mem, &bptr);
  BIO_read(mem, result, bptr->length);
  err = 0;
error:
  if (s) ASN1_UTCTIME_free(s);
  if (bioCert) BIO_free(bioCert);
  if (bioSigningKey) BIO_free(bioSigningKey);
  if (mem) BIO_free(mem);
  if (caCert) X509_free(caCert);
  if (caKey) EVP_PKEY_free(caKey);
  if (crl) X509_CRL_free(crl);
  return err;
}

int addToCRL(char* pemSigningKey, char* pemOldCrl, char* pemRevokedCert, char* result) {
  int err = 0;
  BIO* bioSigningKey, *bioRevCert=NULL, *bioOldCRL=NULL, *mem=NULL;
  X509* badCert=NULL;
  EVP_PKEY* caKey=NULL;
  X509_CRL* crl=NULL;
  X509_REVOKED* revoked=NULL;
  ASN1_TIME* tmptm=NULL;
  BUF_MEM *bptr;

  if (!(bioSigningKey= BIO_new_mem_buf(pemSigningKey, -1)))  goto error;
  if (!(bioOldCRL = BIO_new_mem_buf(pemOldCrl, -1))) goto error;
  if (!(bioRevCert = BIO_new_mem_buf(pemRevokedCert, -1))) goto error;
  if (!(badCert = PEM_read_bio_X509(bioRevCert, NULL, NULL, NULL))) goto error;
  if (!(caKey = PEM_read_bio_PrivateKey(bioSigningKey, NULL, NULL, NULL))) goto error;
  if (!(crl = PEM_read_bio_X509_CRL(bioOldCRL, NULL, NULL, NULL))) goto error;
  if( !(revoked = X509_REVOKED_new())) goto error;
  if (!X509_REVOKED_set_serialNumber(revoked, X509_get_serialNumber(badCert))) goto error;
  if (!(tmptm = ASN1_TIME_new())) goto error;
  if (!(X509_REVOKED_set_revocationDate(revoked, X509_gmtime_adj(tmptm, long(0))))) goto error;

  //set the reason?  Not yet.
  //    ASN1_ENUMERATED* rtmp = ASN1_ENUMERATED_new();
  //  ASN1_ENUMERATED_set(rtmp, reasonCode);
  //    goto err;
  //  if (!X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
  //    goto err;
  //  }
  if(!(err = X509_CRL_add0_revoked(crl,revoked))) goto error;
  if (!X509_CRL_sort(crl)) goto error;
  if(!(err=X509_CRL_sign(crl,caKey,EVP_sha1()))) goto error;
  mem = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_CRL(mem,crl);
  BIO_get_mem_ptr(mem, &bptr);
  BIO_read(mem, result, bptr->length);
  err = 0;
  error:
    if (crl != NULL) X509_CRL_free(crl);
    if (badCert != NULL)       X509_free(badCert);
    if (caKey != NULL)         EVP_PKEY_free(caKey);
    //if (revoked != NULL)       X509_REVOKED_free(revoked);
    if (tmptm != NULL)         ASN1_TIME_free(tmptm);
    if (bioRevCert != NULL)    BIO_free_all(bioRevCert);
    if (bioSigningKey != NULL) BIO_free_all(bioSigningKey);
    if (bioOldCRL != NULL)     BIO_free_all(bioOldCRL);
    if (mem != NULL)           BIO_free_all(mem);
   return err;
}

int parseCertificate(char *certData, int format, v8::Local<v8::Object> parseCert){
  BIO* bioCert=NULL, *bio=NULL, *b64=NULL;
  X509* cert=NULL;
  char buf[256];
  X509_CINF *ci=NULL;
  char *details=NULL, *serialNum = NULL, *details1=NULL, *bufff = NULL, *signatureBuf=NULL, *fp =NULL;
  ASN1_INTEGER *asn=NULL;
  ASN1_STRING  *asn1=NULL;
  BIGNUM *bignum=NULL;
  EVP_PKEY *publicKey=NULL;
  RSA *rsa=NULL;
  const EVP_MD *digest=NULL;
  STACK_OF(ASN1_OBJECT) *eku=NULL;
  int len;
  unsigned char *buff = NULL, *md = NULL;
  unsigned int n;
  if(!(bio = BIO_new(BIO_s_mem()))) goto error;
  if(!(bioCert= BIO_new_mem_buf(certData, -1))) goto error;
  if (format == 1){
    if(!(cert = PEM_read_bio_X509_AUX(bioCert, NULL, NULL, NULL)))  goto error;
  } else if (format == 2){
     if(!(b64 = BIO_new(BIO_f_base64()))) goto error;
     bioCert = BIO_push(b64, bioCert);
     cert = d2i_X509_bio(bioCert, NULL);
  }
  ci = cert->cert_info;

  //Version
  parseCert->Set(String::New("version"), Integer::New(X509_get_version(cert)+1));

  //subject name
  details = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  parseCert->Set(String::New("subject"), String::New(details));

  //issuer name
  details1 = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
  parseCert->Set(String::New("issuer"), String::New(details1));

  //serial number
  asn = X509_get_serialNumber(cert);
  bignum = ASN1_INTEGER_to_BN(asn, NULL);
  serialNum = BN_bn2hex(bignum);
  parseCert->Set(String::New("serial"), String::New(serialNum));

  //valid from
  ASN1_TIME_print(bio, X509_get_notBefore(cert));
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  parseCert->Set(String::New("validFrom"), String::New(buf));

  //Not before
  ASN1_TIME_print(bio, X509_get_notAfter(cert));
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  parseCert->Set(String::New("validTo"), String::New(buf));

  //Public key information
  i2a_ASN1_OBJECT(bio, ci->key->algor->algorithm);
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  parseCert->Set(String::New("publicKeyAlgorithm"), String::New(buf));

  // Public Key
  publicKey = X509_get_pubkey(cert);
  if (publicKey->type == EVP_PKEY_RSA) {
    rsa = EVP_PKEY_get1_RSA(publicKey);
    buff = new unsigned char[BN_num_bytes(rsa->n)];
    int n = BN_bn2bin(rsa->n, buff); // rsa->n (modulus) is in big number format
    bufff = new char[n*3];
    for (int i = 0; i < n ; i = i + 1){
      sprintf(bufff+(i*3), "%02x%s", buff[i],((i+1) == n) ? "":":");
    }
    parseCert->Set(String::New("publicKey"), String::New((char*)bufff));
  }

  //Signature Alg
  len = i2a_ASN1_OBJECT(bio, ci->signature->algorithm);
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  buf[len] = '\0';
  parseCert->Set(String::New("signatureAlgorithm"), String::New(buf));

   //Signature
  asn1 =  cert->signature;
  signatureBuf = new char[(asn1->length)*3];
  for(int i = 0; i < (asn1->length); i = i + 1){
    sprintf(signatureBuf+(i*3), "%02x%s", asn1->data[i],((i+1) == asn1->length) ? "":":");
  }
  parseCert->Set(String::New("signature"), String::New((char*)signatureBuf));

  // fingerPrint
  digest = EVP_sha1();//EVP_sha1();
  md = new unsigned char[EVP_MAX_MD_SIZE];
  if(X509_digest(cert, digest, md, &n) && n > 0) {
    fp = new char[EVP_MAX_MD_SIZE*3];
    for (int j = 0; j < (int) n; j++) {
      sprintf(fp+(j*3), "%02x%s", md[j],((j+1) == n) ? "":":");
    }
    parseCert->Set(String::New("fingerPrint"), String::New((char *)fp));
  }

  //Extensions
  eku = (STACK_OF(ASN1_OBJECT) *)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
  if (eku != NULL) {
    Local<Array> extKey = Array::New();
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
      memset(buf, 0, sizeof(buf));
      OBJ_obj2txt(buf, sizeof(buf) - 1, sk_ASN1_OBJECT_value(eku, i), 1);
      extKey->Set(Integer::New(i), String::New(buf));
    }
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    parseCert->Set(String::New("extendedKey"), extKey);
  }
  error:
    if (bioCert != NULL) BIO_free_all(bioCert);
    if (bio != NULL) BIO_free_all(bio);
    if (details != NULL) OPENSSL_free(details);
    if (details1 != NULL) OPENSSL_free(details1);
    if (serialNum != NULL) OPENSSL_free(serialNum);
    if (publicKey != NULL) EVP_PKEY_free(publicKey);
    if (rsa != NULL) RSA_free(rsa);
    if (cert != NULL) X509_free(cert);
    if (bignum != NULL) BN_free(bignum);
    if (buff) delete [] buff;
    if (bufff) delete [] bufff;
    if (fp) delete [] fp;
    if (md) delete [] md;
    if (signatureBuf) delete [] signatureBuf;
    return 0;
}

int parseCrl(char *crl, int format, v8::Local<v8::Object> newCrl) {
  BIO *bp=NULL, *bio= NULL, *b64 = NULL;
  X509_CRL* x=NULL;
  char *details=NULL, *signatureBuf=NULL;
  char buf [256];
  ASN1_STRING  *asn1=NULL;
  ASN1_TIME *lastUpdate=NULL, *nextUpdate=NULL;
  int len;

  if(!(bp = BIO_new_mem_buf(crl, -1))) goto error;
  if(!(bio = BIO_new(BIO_s_mem()))) goto error;

  if (format == 1){
    if(!(x = PEM_read_bio_X509_CRL(bp, NULL, NULL, NULL))) goto error;
  } else if (format == 2){
       if(!(b64 = BIO_new(BIO_f_base64()))) goto error;
       bp = BIO_push(b64, bp);
       x = d2i_X509_CRL_bio(bp, NULL);
  }
   // Issuer
  if(!(details = X509_NAME_oneline(X509_CRL_get_issuer(x), 0, 0))) goto error;
  newCrl->Set(String::New("issuer"), String::New(details));
  // Version
  newCrl->Set(String::New("version"), Integer::New(X509_CRL_get_version(x)+1));
  // lastUpdate
  if (!(lastUpdate = X509_CRL_get_lastUpdate(x))) goto error; // lastUpdate
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  newCrl->Set(String::New("lastUpdate"), String::New(buf));
  // nextUpdate
  if (!(nextUpdate = X509_CRL_get_nextUpdate(x))) goto error;  //next update
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  newCrl->Set(String::New("nextUpdate"), String::New(buf));
  //SignatureAlg
  if(!(len = i2a_ASN1_OBJECT(bio, x->crl->sig_alg->algorithm))) goto error;//Signature Algorithm
  memset(buf, 0, sizeof(buf));
  BIO_read(bio, buf, sizeof(buf)-1);
  buf[len] = '\0';
  newCrl->Set(String::New("signatureAlg"), String::New(buf));
 //Signature
  asn1 =  x->signature;
  signatureBuf = new char[(asn1->length)*3];
  for(int i = 0; i < (asn1->length); i = i + 1){
    sprintf(signatureBuf+(i*3), "%02x%s", asn1->data[i],((i+1) == asn1->length) ? "":":");
  }
  newCrl->Set(String::New("signature"), String::New((char *)signatureBuf));
error:
 if (details != NULL) OPENSSL_free(details);
  //if (lastUpdate != NULL) ASN1_TIME_free(lastUpdate);
  //if (nextUpdate != NULL) ASN1_TIME_free(nextUpdate);
  if (bio != NULL) BIO_free_all(bio);
  if (b64 != NULL) BIO_free_all(b64);
  if (bp != NULL) BIO_free_all(bp);
  if (x != NULL) X509_CRL_free(x);
  if (signatureBuf) delete [] signatureBuf;
  //if (asn1 != NULL) ASN1_STRING_free(asn1);
  return 0;
}

int verifyCertificate(char *validateCert,  v8::Handle<v8::Array>masterCertificate){
  int ret=0;
  X509_STORE *cert_ctx=NULL;
  X509_LOOKUP *lookup=NULL;
  X509 *x=NULL, *tmp=NULL;
  BIO *bioCert = NULL, *tmpBIO=NULL;
  X509_STORE_CTX *csc=NULL;

  // x=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
  // i=X509_STORE_add_crl(ctx->store_ctx,x);
  if(!(cert_ctx=X509_STORE_new())) goto error;
  for (int i = 0; i < (int)masterCertificate->Length(); i++) {
    String::Utf8Value certFile((masterCertificate->Get(i))->ToString());
    if(!(tmpBIO= BIO_new_mem_buf(certFile.operator*(), -1))) goto error;
    if(!(tmp=PEM_read_bio_X509_AUX(tmpBIO,NULL,NULL,NULL))) goto error;
    X509_STORE_add_cert(cert_ctx,tmp);
    X509_free(tmp);
    BIO_free(tmpBIO);

  }
 // if (!(lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_hash_dir()))) goto error;
//  X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);

  if(!(bioCert= BIO_new_mem_buf(validateCert, -1))) goto error;
  if(!(x = PEM_read_bio_X509_AUX(bioCert, NULL, NULL, NULL)))  goto error;
  if(!(csc = X509_STORE_CTX_new())) goto error;
  X509_STORE_set_flags(cert_ctx, 0);
  if(!X509_STORE_CTX_init(csc,cert_ctx,x,0)) goto error;
  ret =X509_verify_cert(csc);

error:
  if (lookup) X509_LOOKUP_free(lookup);
  if (csc) X509_STORE_CTX_free(csc);
  if (x != NULL) X509_free(x);
  if (bioCert != NULL) BIO_free(bioCert);
  if (cert_ctx != NULL) X509_STORE_free(cert_ctx);
  return ret;
}


