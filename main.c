#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shlobj.h>

// gcc main.c encrypt.c decrypt.c -I"C:\vcpkg\installed\x64-windows\include" -L"C:\vcpkg\installed\x64-windows\lib" -lcrypto -lssl -o aescrypt.exe

int encrypt_file(const char *input, const char *output, unsigned char *key, unsigned char *iv);
int decrypt_file(const char *input, const char *output, unsigned char *key, unsigned char *iv);

char* getFolder() {
    BROWSEINFO bi = {0};
    bi.lpszTitle = "Sélectionnez un dossier";
    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);

    if (pidl != NULL) {
        static char path[MAX_PATH];
        if (SHGetPathFromIDList(pidl, path)) {
            path[MAX_PATH - 1] = '\0';  // Assure la terminaison nulle
            printf("Dossier sélectionné : %s\n", path);
            return path;
        }
        CoTaskMemFree(pidl);
    } else {
        printf("Aucun dossier sélectionné.\n");
    }

    return NULL;
}

void encrypt_directory_recursive(const char *folder, unsigned char *key, unsigned char *iv) {
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", folder);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char fullpath[MAX_PATH];
        snprintf(fullpath, MAX_PATH, "%s\\%s", folder, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            encrypt_directory_recursive(fullpath, key, iv);
        } else {
            char outfile[MAX_PATH];
            snprintf(outfile, MAX_PATH, "%s.enc", fullpath);
            printf("Chiffrement : %s -> %s\n", fullpath, outfile);
            encrypt_file(fullpath, outfile, key, iv);
            DeleteFile(fullpath);  // supprime le fichier original
        }

    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
}

void decrypt_directory_recursive(const char *folder, unsigned char *key, unsigned char *iv) {
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", folder);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char fullpath[MAX_PATH];
        snprintf(fullpath, MAX_PATH, "%s\\%s", folder, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            decrypt_directory_recursive(fullpath, key, iv);
        } else {
            size_t len = strlen(fullpath);
            if (len > 4 && strcmp(fullpath + len - 4, ".enc") == 0) {
                char outfile[MAX_PATH];
                snprintf(outfile, MAX_PATH, "%.*s", (int)(len - 4), fullpath); // retire .enc
                printf("Déchiffrement : %s -> %s\n", fullpath, outfile);
                decrypt_file(fullpath, outfile, key, iv);
                DeleteFile(fullpath);  // supprime le fichier chiffré
            }
        }

    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
}

int main() {
    unsigned char key[32] = "01234567890123456789012345678901"; // 32 bytes
    unsigned char iv[16]  = "1234567890123456";                 // 16 bytes

    int choix;
    char folder[MAX_PATH];

    printf("Que voulez-vous faire ?\n");
    printf("1 - Chiffrer un dossier\n");
    printf("2 - Déchiffrer un dossier\n");
    printf("Choix : ");
    scanf("%d", &choix);
    getchar(); // consomme le '\n' restant

    char *selected_folder = getFolder();
    if (selected_folder == NULL) {
        printf("Aucun dossier sélectionné, sortie.\n");
        return 1;
    }
    strncpy(folder, selected_folder, MAX_PATH);
folder[MAX_PATH - 1] = '\0'; // assure terminaison nulle

if (choix == 1) {
    encrypt_directory_recursive(folder, key, iv);
    printf("Chiffrement terminé.\n");
} else if (choix == 2) {
    decrypt_directory_recursive(folder, key, iv);
    printf("Déchiffrement terminé.\n");
} else {
    printf("Choix invalide.\n");
}

    return 0;
}
