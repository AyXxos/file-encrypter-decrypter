#include <openssl/evp.h>
#include <openssl/aes.h>
#include <windows.h> 
#include <string.h>  
#include <stdio.h>

#define BUFFER_SIZE 4096

typedef void (*file_processed_callback)(const char *filepath);

int decrypt_file_cb(const char *input, const char *output, unsigned char *key, unsigned char *iv,
                    file_processed_callback callback) {
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

    if (callback) callback(input);
    return 0;
}

void decrypt_directory_recursive_cb(const char *folder, unsigned char *key, unsigned char *iv,
                                    file_processed_callback callback) {
    char search_path[4096];
    snprintf(search_path, sizeof(search_path), "%s\\*", folder);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", folder, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            decrypt_directory_recursive_cb(fullpath, key, iv, callback);
        } else {
            size_t len = strlen(fullpath);
            if (len > 4 && strcmp(fullpath + len - 4, ".enc") == 0) {
                char outfile[4096];
                snprintf(outfile, sizeof(outfile), "%.*s", (int)(len - 4), fullpath);
                decrypt_file_cb(fullpath, outfile, key, iv, callback);
                DeleteFile(fullpath);
            }
        }
    } while (FindNextFile(hFind, &fd));
    FindClose(hFind);
}
