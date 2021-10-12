#pragma once
#include "sodium.h"

void writeKeyPairToFile(unsigned char publickey[crypto_box_PUBLICKEYBYTES], unsigned char privatekey[crypto_box_SECRETKEYBYTES], char* keyName);

void writeEncryptSecretKeyToFile(const char* targetFile, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], char* members[]);

void readSecretKeyFromFile(FILE* sourceFile, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], const char* pubkeyPath, const char* prikeyPath);