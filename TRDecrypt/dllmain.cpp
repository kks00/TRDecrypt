#include <Windows.h>
#include <stdio.h>
#include <io.h>

#include <vector>
#include <iterator>
#include <string>
#include <queue>

using namespace std;

#define DIR_NAME "script"
#define OUT_DIR_NAME "script_decrypted"

HMODULE hCurrentModule  = NULL;

int DecryptScript(const char* input_filename, const char* output_filename) {
    int result = 0;

    FILE* f_encrypted = fopen(input_filename, "rb");
    if (f_encrypted) {
        fseek(f_encrypted, 0, SEEK_END);
        long file_size = ftell(f_encrypted);
        fseek(f_encrypted, 0, SEEK_SET);

        char* pBuffer = (char*)malloc(file_size);
        if (pBuffer) {
            fread(pBuffer, sizeof(char), file_size, f_encrypted);

            void* pKeyTable = (void*)0x02288660;
            void* pDecryptFunction = (void*)0x015A7040; // E8 ?? ?? ?? ?? FF 75 EC 8D 56 08 52 8D 88 ?? ?? ?? ?? 52

            __asm {
                pushad
                pushfd

                mov ecx, [pKeyTable]
                lea ecx, [ecx+0x10B8]
                push[file_size]
                mov eax, pBuffer
                push eax
                mov eax, pBuffer
                push eax
                call[pDecryptFunction]

                popfd
                popad
            }

            FILE* f_decrypted = fopen(output_filename, "wb");
            if (f_decrypted) {
                fwrite(pBuffer, sizeof(char), file_size, f_decrypted);
                fclose(f_decrypted);
                result = 1;
            }
        }
        free(pBuffer);
        fclose(f_encrypted);

        return result;
    }

    return 0;
}

typedef struct script_file {
    string DirectoryName, FileName;
} script_file;

vector<script_file> vScriptFiles;

string make_file_name(string Directory, string FileName) {
    return Directory.erase(Directory.length() - 1) + FileName;
}

string make_out_file_name(string Directory, string FileName) {
    string result = make_file_name(Directory, FileName);
    return string(OUT_DIR_NAME) + "\\" + result.substr(result.find("\\") + 1, result.length() - result.find("\\"));
}

void make_directory(string Directory) {
    if (_access(Directory.c_str(), 02) == -1) {
        CreateDirectoryA(Directory.c_str(), NULL);
    }
}

void MainProcedure() {
    vScriptFiles.clear();

    make_directory(OUT_DIR_NAME);

    queue<string> directoryQueue;
    directoryQueue.push(string(DIR_NAME) + "\\*");

    while (!directoryQueue.empty()) {
        string current_directory = directoryQueue.front();
        directoryQueue.pop();

        WIN32_FIND_DATAA fd;
        HANDLE hFindFile = FindFirstFileA(current_directory.c_str(), &fd);
        current_directory.erase(current_directory.length() - 1);
        if (hFindFile != INVALID_HANDLE_VALUE) {
            while (FindNextFileA(hFindFile, &fd)) {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    string dir_name = string(fd.cFileName);
                    if (dir_name == "." || dir_name == "..")
                        continue;
                    string new_dir_name = string(OUT_DIR_NAME) + "\\" + current_directory.substr(current_directory.find("\\") + 1, current_directory.length() - current_directory.find("\\")) + string(fd.cFileName);
                    make_directory(new_dir_name);
                    directoryQueue.push(current_directory + string(fd.cFileName) + "\\*");
                }
                else if (fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) {
                    vScriptFiles.push_back({ current_directory + "\\", fd.cFileName });
                }
            }
        }
        FindClose(hFindFile);
    }

    for (vector<script_file>::iterator curr_file = vScriptFiles.begin(); curr_file != vScriptFiles.end(); ++curr_file) {
        DecryptScript(make_file_name(curr_file->DirectoryName, curr_file->FileName).c_str(), make_out_file_name(curr_file->DirectoryName, curr_file->FileName).c_str());
    }

    FreeLibraryAndExitThread(hCurrentModule, 0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hCurrentModule = hModule;
        DWORD ThreadId;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainProcedure, NULL, 0, &ThreadId);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

