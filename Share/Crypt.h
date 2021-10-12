#pragma once

void genKeyPair(char* keyName);

void encryptFile(const char* sourceFile, const char* targetFile, char* members[]);

void decryptFile(const char* sourceFile, const char* targetFile, const char* pubPath, const char* priPath);