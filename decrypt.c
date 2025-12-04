#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdio.h>

#define BUFFER_SIZE 4096

int decrypt_file(const char *input, const char *output, unsigned char *key, unsigned char *iv) {
    FILE *in = fopen(input, "rb");
    FILE *out = fopen(output, "wb");
    if (!in || !out) return 1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int outlen;

    while (1) {
        int bytes = fread(buffer, 1, BUFFER_SIZE, in);
        if (bytes <= 0) break;

        EVP_DecryptUpdate(ctx, outbuf, &outlen, buffer, bytes);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    return 0;
}
