#include "sodium_glue.h"
#include <idris_rts.h>

int secretbox_keyLength() {
    return crypto_secretbox_KEYBYTES;
}

int secretbox_nonceLength() {
    return crypto_secretbox_NONCEBYTES;
}

int box_publicKeyLength() {
    return crypto_box_PUBLICKEYBYTES;
}

int box_secretKeyLength() {
    return crypto_box_SECRETKEYBYTES;
}

int box_nonceLength() {
    return crypto_box_NONCEBYTES;
}

KeyPair* newKeyPair() {
    Key* pub = mkKey(box_publicKeyLength());
    Key* secret = mkKey(box_secretKeyLength());

    KeyPair* kpair = malloc(sizeof(KeyPair));
    crypto_box_keypair(pub->key, secret->key);

    kpair->pub = pub;
    kpair->secret = secret;
    return kpair;
}

Key* getPublic(KeyPair* k) {
    return (k->pub);
}

Key* getSecret(KeyPair* k) {
    return (k->secret);
}

int keyLen(Key* k) {
    return k->klen;
}

int keyIdx(Key* k, int i) {
    return (int)(k->key[i]);
}

Key* mkKey(int len) {
    Key* k = malloc(sizeof(Key)+len);
    k->key = (unsigned char*)k + sizeof(Key);
    k->klen = len;

    return k;
}

void setKeyIdx(Key* k, int i, int v) {
    k->key[i] = (char)v;
}

Nonce* mkNonce(int len) {
    Nonce* n = malloc(sizeof(Nonce)+len);
    n->nonce = (unsigned char*)n + sizeof(Nonce);
    n->nlen = len;

    return n;
}

Nonce* mkNonceFromString(char* nstr) {
    int len = strlen(nstr);

    Nonce* n = malloc(sizeof(Nonce)+len);
    n->nonce = (unsigned char*)n + sizeof(Nonce);
    memcpy(n->nonce, nstr, len+1);
    n->nlen = len;

    return n;
}

void setNonceIdx(Nonce* n, int i, int v) {
    n->nonce[i] = (unsigned char)v;
}

void freeKeyPair(KeyPair* k) {
    free(k);
}

void dumpKey(Key* k) {
    int i;
    for (i=0; i<k->klen; ++i) {
        printf("%d ", (int)(k->key[i]));
    }
    printf("\n");
}

Encrypted* do_crypto_secretbox(char* m, Nonce* n, Key* key) {
    int mlen = strlen(m) + crypto_secretbox_ZEROBYTES;

    Encrypted* e = malloc(sizeof(Encrypted) + mlen + 1);

    char* inmsg = malloc(mlen + 1); 
    char* res = (char*)e + sizeof(Encrypted);

    memset(inmsg, 0, crypto_secretbox_ZEROBYTES);
    strcpy(inmsg + crypto_secretbox_ZEROBYTES, m);

    int r = crypto_secretbox((unsigned char*)res, (unsigned char*)inmsg, mlen, 
                     n->nonce, (unsigned char*)key->key);

    if (r == 0) {
        e->msg = res;
        e->mlen = mlen;
        e->padding = crypto_secretbox_BOXZEROBYTES;
        return e;
    } else {
        free(e);
        return NULL;
    }
}

Decrypted* do_crypto_secretbox_open(Encrypted* cin, Nonce* n, Key* key) {
    int mlen = cin->mlen;

    Decrypted* d = malloc(sizeof(Decrypted) + mlen+1);
    char* res = (char*)d + sizeof(Decrypted);

    memset(cin->msg, 0, crypto_secretbox_BOXZEROBYTES);

    int r = crypto_secretbox_open(
                         (unsigned char*)res, (unsigned char*)cin->msg, mlen, 
                         n->nonce, (unsigned char*)key->key);

    if (r == 0) {
        d->msg = res;
        d->mlen = mlen;
        d->padding = crypto_secretbox_ZEROBYTES;
        return d;
    } else {
        free(d);
        return NULL;
    }
}

Encrypted* do_crypto_box(char* m, Nonce* n, Key* pkey, Key* skey) {
    int mlen = strlen(m) + crypto_box_ZEROBYTES;

    Encrypted* e = malloc(sizeof(Encrypted) + mlen+1);

    char* inmsg = malloc(mlen + 1); 
    char* res = (char*)e + sizeof(Encrypted);

    memset(inmsg, 0, crypto_box_ZEROBYTES);
    strcpy(inmsg + crypto_box_ZEROBYTES, m);

    int r = crypto_box((unsigned char*)res, (unsigned char*)inmsg, mlen, 
                     n->nonce, 
                     (unsigned char*)pkey->key, (unsigned char*)skey->key);

    if (r == 0) {
        e->msg = res;
        e->mlen = mlen;
        e->padding = crypto_box_BOXZEROBYTES;
        return e;
    } else {
        free(e);
        return NULL;
    }
}

Decrypted* do_crypto_box_open(Encrypted* cin, Nonce* n, Key* pkey, Key* skey) {
    int mlen = cin->mlen;
    Decrypted* d = malloc(sizeof(Decrypted) + mlen+1);
    char* res = (char*)d + sizeof(Decrypted);

    memset(cin->msg, 0, crypto_box_BOXZEROBYTES);

    int r = crypto_box_open((unsigned char*)res, 
                     (unsigned char*)cin->msg, 
                     cin->mlen, 
                     n->nonce, 
                     (unsigned char*)pkey->key, (unsigned char*)skey->key);

    if (r == 0) {
        d->msg = res;
        d->padding = crypto_box_ZEROBYTES;
        int i;
        return d;
    } else {
        free(d);
        return NULL;
    }
}

char* getEnc(Encrypted* enc) {
    return (enc->msg + enc->padding);
}

char* getDec(Decrypted* dec) {
    return (dec->msg + dec->padding);
}

Encrypted* newBox(int len) {
    Encrypted* e = malloc(sizeof(Encrypted) + len + crypto_box_ZEROBYTES);
    e->msg = (char*)e + sizeof(Encrypted);
    e->padding = crypto_box_BOXZEROBYTES;
    e->mlen = len + e->padding;
    return e;
}

Encrypted* newSecretBox(int len) {
    Encrypted* e = malloc(sizeof(Encrypted) + len + crypto_secretbox_BOXZEROBYTES);
    e->msg = (char*)e + sizeof(Encrypted); 
    e->padding = crypto_secretbox_BOXZEROBYTES;
    e->mlen = len + e->padding;
    return e;
}

int getEncLen(Encrypted *enc) {
    return enc->mlen - enc->padding;
}

int getEncSize(Encrypted *enc) {
    return enc->mlen;
}

int getDecSize(Decrypted *dec) {
    return dec->mlen;
}

int getEncByte(Encrypted *enc, int b) {
    return (int)(enc->msg[b + enc->padding]);
}

void setEncByte(Encrypted *enc, int i, int b) {
    enc->msg[b + enc->padding] = (char)i;
}

void* getEncData(Encrypted *enc) {
    return enc->msg - enc->padding;
}

void setEncData(Encrypted *enc, void* data) {
    memcpy(enc->msg + enc->padding, data, enc->mlen - enc->padding);
}



