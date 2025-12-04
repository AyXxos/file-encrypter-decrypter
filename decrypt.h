#ifndef DECRYPT_H
#define DECRYPT_H

typedef void (*file_processed_callback)(const char *filepath);

int decrypt_file_cb(const char *input, const char *output, unsigned char *key, unsigned char *iv,
                    file_processed_callback callback);

void decrypt_directory_recursive_cb(const char *folder, unsigned char *key, unsigned char *iv,
                                    file_processed_callback callback);

#endif
