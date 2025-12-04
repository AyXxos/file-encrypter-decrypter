#ifndef ENCRYPT_H
#define ENCRYPT_H

typedef void (*file_processed_callback)(const char *filepath);

int encrypt_file_cb(const char *input, const char *output, unsigned char *key, unsigned char *iv,
                    file_processed_callback callback);

void encrypt_directory_recursive_cb(const char *folder, unsigned char *key, unsigned char *iv,
                                    file_processed_callback callback);

#endif
