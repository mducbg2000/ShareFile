#include "Crypt.h"
#include "sodium.h"
#include "FileHandle.h"

#define CHUNK_SIZE 4096

void genKeyPair(char* keyName)
{
    unsigned char publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char privatekey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(publickey, privatekey);
    writeKeyPairToFile(publickey, privatekey, keyName);
}

void encryptFile(const char* sourceFile, const char* targetFile, char* members[])
{
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(key);

    //write quantity of member and encypt secret keys to target file
    writeEncryptSecretKeyToFile(targetFile, key, members);

    unsigned char buf_in[CHUNK_SIZE];
    unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;

    FILE* fp_t, * fp_s;

    unsigned long long out_len;
    size_t rlen;
    int eof;
    unsigned char tag;

    fp_s = fopen(sourceFile, "rb");

    // mở file target bằng append mode
    fp_t = fopen(targetFile, "ab");

    // khởi tạo encrypt stream
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    
    // ghi header vào file target
    fwrite(header, sizeof header, 1, fp_t);
    
    // chia file source thành từng chunk, encrypt và ghi lần lượt các chunk vào file target
    do
    {
        // đọc chunk tính từ con trỏ fp_s
        rlen = fread(buf_in, sizeof buf_in, 1, fp_s);
        
        // check xem đã hết file chưa
        eof = feof(fp_s);

        // nếu hết đánh dấu tag final
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        // ghi encrypt buf vào stream
        crypto_secretstream_xchacha20poly1305_push(&state, buf_out, &out_len, buf_in, rlen, NULL, 0, tag);

        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    
    fclose(fp_t);
    fclose(fp_s);
}

void decryptFile(const char* sourceFile, const char* targetFile, const char* pubPath, const char* priPath)
{

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    FILE* fp_s = fopen(sourceFile, "rb");
    readSecretKeyFromFile(fp_s, key, pubPath, priPath);

    // read chunk from sourceFile to buf_in
    unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    // read chunk to targetFile from buf_out
    unsigned char buf_out[CHUNK_SIZE];
    //header
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    //state
    crypto_secretstream_xchacha20poly1305_state state;

    // pointer to open files
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    int ret = -1;
    unsigned char tag;

    fp_s = fopen(sourceFile, "rb");
    fp_t = fopen(targetFile, "wb");

    // read header from source file
    fread(header, sizeof header, 1, fp_s);
    
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0)
    {
        goto ret; /* incomplete header */
    }
    do
    {
        // read chunk from source file
        rlen = fread(buf_in, sizeof buf_in, 1, fp_s);
        // is end of file?
        eof = feof(fp_s);


        if (crypto_secretstream_xchacha20poly1305_pull(&state, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0)
        {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof)
        {
            goto ret; /* premature end (end of file reached before the end of the stream) */
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
}
