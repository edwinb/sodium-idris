#ifndef _SODIUM_GLUE_H
#define _SODIUM_GLUE_H

#include <sodium.h>

typedef struct {
    unsigned char* key;
    int klen;
} Key;

typedef struct {
    Key* secret;
    Key* pub;
} KeyPair;

typedef struct {
    char* msg; // padded with zeros
    int mlen;
    int padding;
} Encrypted;

typedef struct {
    char* msg; // padded with zeros
    int mlen;
    int padding;
} Decrypted;

int box_publicKeyLength();
int box_secretKeyLength();
int box_nonceLength();
int secretbox_keyLength();
int secretbox_nonceLength();

// Invent a new public/private key pair
// Caller responsible for freeing
KeyPair* newKeyPair();

// Return individual components
Key *getPublic(KeyPair* k);
Key *getSecret(KeyPair* k);

int keyLen(Key* k);
int keyIdx(Key* k, int i);

Key* mkKey(int len);
void setKeyIdx(Key* k, int i, int v);

// Free a key/value pair (but not the individual keys)
void freeKeyPair(KeyPair* k);

// Free memory allocated for a key
void freeKey(Key* k);

// Public/private key encryption
Encrypted* do_crypto_box(char* m, char* n, Key* pkey, Key* skey);
Decrypted* do_crypto_box_open(Encrypted* c, char* n, Key* pkey, Key* skey);

// Symmetric key encryption
Encrypted* do_crypto_secretbox(char* m, char* n, Key* key);
Decrypted* do_crypto_secretbox_open(Encrypted* c, char* n, Key* key);

// Get the string from a decrypted object
char* getDec(Decrypted* dec);
int getDecSize(Decrypted *enc);

// Read/write encrypted values

Encrypted* newBox(int len);
Encrypted* newSecretBox(int len);

int getEncLen(Encrypted *enc);
int getEncSize(Encrypted *enc);
int getEncByte(Encrypted *enc, int b);
void setEncByte(Encrypted *enc, int i, int b);
void* getEncData(Encrypted *enc);
void setEncData(Encrypted *enc, void* buf);

// Free encryption/decryption objects
void freeEnc(Encrypted* enc);
void freeDec(Decrypted* enc);

#endif
