#include <windows.h>
#include <shlobj.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>
#include "encrypt.h"
#include "decrypt.h"

#pragma comment(lib, "comctl32.lib")

#define MAX_KEY_LEN 32

HWND hwndPath, hwndKey, hwndJournal, hwndProgress;

typedef struct {
    char folder[4096];
    int mode; // 1=encrypt, 2=decrypt
    unsigned char key[32];
    unsigned char iv[16];
} THREAD_PARAMS;

int count_files(const char *folder, int encrypt_mode) {
    int count = 0;
    char search_path[4096];
    snprintf(search_path, sizeof(search_path), "%s\\*", folder);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", folder, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            count += count_files(fullpath, encrypt_mode);
        else {
            if (encrypt_mode || (!encrypt_mode && strlen(fullpath) > 4 && strcmp(fullpath + strlen(fullpath)-4, ".enc") == 0))
                count++;
        }
    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
    return count;
}

DWORD WINAPI process_thread(LPVOID lpParam) {
    THREAD_PARAMS *params = (THREAD_PARAMS*)lpParam;

    void callback(const char *filepath) {
        SendMessage(hwndJournal, LB_INSERTSTRING, 0, (LPARAM)filepath);
        SendMessage(hwndJournal, LB_SETTOPINDEX, 0, 0);
        SendMessage(hwndProgress, PBM_STEPIT, 0, 0);
    }

    int total_files = count_files(params->folder, params->mode);
    SendMessage(hwndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, total_files));
    SendMessage(hwndProgress, PBM_SETSTEP, 1, 0);
    SendMessage(hwndProgress, PBM_SETPOS, 0, 0);

    if (params->mode == 1)
        encrypt_directory_recursive_cb(params->folder, params->key, params->iv, callback);
    else
        decrypt_directory_recursive_cb(params->folder, params->key, params->iv, callback);

    MessageBox(NULL, "Operation terminee !", "Info", MB_OK);
    free(params);
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            INITCOMMONCONTROLSEX icex = {0};
            icex.dwSize = sizeof(icex);
            icex.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
            InitCommonControlsEx(&icex);

            CreateWindow("STATIC", "Dossier :", WS_VISIBLE|WS_CHILD, 10, 10, 120, 20, hwnd, NULL, NULL, NULL);
            hwndPath = CreateWindow("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER, 130, 10, 300, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("BUTTON","Parcourir...", WS_VISIBLE|WS_CHILD, 440, 10, 100, 20, hwnd, (HMENU)1, NULL, NULL);

            CreateWindow("STATIC", "Cle AES (32 octets) :", WS_VISIBLE|WS_CHILD, 10, 40, 120, 20, hwnd, NULL, NULL, NULL);
            hwndKey = CreateWindow("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 130, 40, 300, 20, hwnd, NULL, NULL, NULL);

            CreateWindow("BUTTON","Chiffrer", WS_VISIBLE|WS_CHILD, 10, 70, 100, 30, hwnd, (HMENU)2, NULL, NULL);
            CreateWindow("BUTTON","Dechiffrer", WS_VISIBLE|WS_CHILD, 120, 70, 100, 30, hwnd, (HMENU)3, NULL, NULL);

            hwndJournal = CreateWindow("LISTBOX","", WS_VISIBLE|WS_CHILD|WS_BORDER|WS_VSCROLL|LBS_NOTIFY, 10,110,530,200, hwnd,NULL,NULL,NULL);
            hwndProgress = CreateWindowEx(0, PROGRESS_CLASS, NULL, WS_CHILD|WS_VISIBLE, 10,320,530,20, hwnd,NULL,NULL,NULL);
        } break;

        case WM_COMMAND: {
            if (LOWORD(wParam) == 1) { // Parcourir
                BROWSEINFO bi = {0};
                bi.lpszTitle = "Selectionnez un dossier";
                LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
                if (pidl) {
                    char path[4096];
                    if (SHGetPathFromIDList(pidl, path))
                        SetWindowText(hwndPath, path);
                    CoTaskMemFree(pidl);
                }
            } else if (LOWORD(wParam) == 2 || LOWORD(wParam) == 3) { // Chiffrer / Dechiffrer
                char folder[4096];
                GetWindowText(hwndPath, folder, 4096);
                if (folder[0] == '\0') break;

                char keyText[33] = {0};
                GetWindowText(hwndKey, keyText, 33);
                if (strlen(keyText) == 0) {
                    MessageBox(hwnd, "Veuillez entrer une cle AES de 32 octets.", "Erreur", MB_OK|MB_ICONERROR);
                    break;
                }

                THREAD_PARAMS *params = (THREAD_PARAMS*)malloc(sizeof(THREAD_PARAMS));
                strcpy(params->folder, folder);
                params->mode = (LOWORD(wParam) == 2) ? 1 : 2;
                memset(params->key, 0, sizeof(params->key));
                strncpy((char*)params->key, keyText, 32);
                memcpy(params->iv, "1234567890123456", 16);

                CreateThread(NULL, 0, process_thread, params, 0, NULL);
            }
        } break;

        case WM_DESTROY: PostQuitMessage(0); break;
    }
    return DefWindowProc(hwnd,msg,wParam,lParam);
}

int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "AESGuiClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    HWND hwnd = CreateWindow("AESGuiClass", "Encryptor/Decryptor AES",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                             CW_USEDEFAULT, CW_USEDEFAULT, 560, 380,
                             NULL, NULL, hInstance, NULL);
    ShowWindow(hwnd, nCmdShow);

    MSG msg = {0};
    while(GetMessage(&msg,NULL,0,0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
