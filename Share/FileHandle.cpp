
#include "FileHandle.h"
#include "sodium.h"
#include <fstream>
#include <iostream>

/** write public key and private key
 *  
 * @param keyName	-	path to folder of key and key name
 */
void writeKeyPairToFile(unsigned char publickey[crypto_box_PUBLICKEYBYTES], unsigned char privatekey[crypto_box_SECRETKEYBYTES], char* keyName )
{
	FILE* file;
	// path của 2 key
	char* pubKeyPath = (char*) malloc((strlen(keyName) + 5) * sizeof(char));
	char* priKeyPath = (char*) malloc((strlen(keyName) + 5) * sizeof(char));
	// build path 
	sprintf(pubKeyPath, "%s.pub", keyName);
	sprintf(priKeyPath, "%s.ppk", keyName);
	// ghi public key vào file
	file = fopen(pubKeyPath, "w+b");
	fwrite(publickey, crypto_box_PUBLICKEYBYTES, 1, file);
	fclose(file);
	// ghi private key vào file
	file = fopen(pubKeyPath, "w+b");
	fwrite(publickey, crypto_box_SECRETKEYBYTES, 1, file);
	fclose(file);
}

/**
 * Ghi số người tham gia chia sẻ file và secret key được encrypt lần lượt bằng public key của những người tham gia vào file
 * 
 * @param targetFile	-	file đích khi encrypt
 * @param key			-	secret key để encrypt/decrypt file
 * @param members		-	mảng các file public key của người tham gia chia sẻ file
 * 
 */

void writeEncryptSecretKeyToFile(const char* targetFile, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], char* members[])
{
	FILE* fp_t, * fp_k;
	fp_t = fopen(targetFile, "wb"); /* mở file target */
	
	size_t len = 0;
	while (members[len] != NULL)
	{
		++len;
	}

	// ghi số người tham dự chia sẻ file vào file target
	fwrite(&len, sizeof(int), 1, fp_t);
	
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char cipherkey[crypto_secretstream_xchacha20poly1305_KEYBYTES + crypto_box_SEALBYTES];

	// encrypt secret key bằng public key của những người tham gia chia sẻ file và ghi vào file encrypt
	for (size_t i = 0; i < len; i++)
	{
		// đọc public key từ file members
		fp_k = fopen(members[i], "rb");
		fread(pubkey, sizeof pubkey, 1, fp_k);

		// ghi public key vào file target để nhận dạng lúc decrypt
		fwrite(pubkey, sizeof pubkey, 1, fp_t);

		// encrypt secret key bằng public key trên
		crypto_box_seal(cipherkey, key, sizeof key, pubkey);
		
		// ghi cipher key vào file encrypt
		fwrite(cipherkey, sizeof cipherkey, 1, fp_t);

		// đóng file
		fclose(fp_k);
	}
}

/**
 * Read secret key from source file 
 *
 * @param key			-	secret key to write in
 * @param pubkeyPath	-	path of public key
 * @param prikeyPath	-	path of private key to decrypt secret key
 */

void readSecretKeyFromFile(FILE* fp_s, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], const char* pubkeyPath, const char* prikeyPath)
{
	size_t len;
	fread(&len, sizeof(size_t), 1, fp_s);

	unsigned char publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char privatekey[crypto_box_SECRETKEYBYTES];

	FILE* keyFile;

	keyFile = fopen(pubkeyPath, "rb");
	fread(publickey, crypto_box_PUBLICKEYBYTES, 1, keyFile);
	fclose(keyFile);

	keyFile = fopen(prikeyPath, "rb");
	fread(privatekey, crypto_box_SECRETKEYBYTES, 1, keyFile);
	fclose(keyFile);

	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char cipherkey[crypto_secretstream_xchacha20poly1305_KEYBYTES + crypto_box_SEALBYTES];
	
	for (size_t i = 0; i < len; i++) {
		fread(pubkey, sizeof pubkey, 1, fp_s);
		fread(cipherkey, sizeof cipherkey, 1, fp_s);
		if (strcmp((char*)publickey, (char*)pubkey)) {
			crypto_box_seal_open(key, cipherkey, sizeof cipherkey, publickey, privatekey);
		}
	}
}
