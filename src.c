#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROCESS_ALL_ACCESS (0x1F0FFF)
#define MAX_LOG_LENGTH 256
#define MAX_DLL_PATH_LENGTH 512
#define MAX_DLL_COUNT 10

typedef enum {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_DEBUG
} LogLevel;

typedef struct {
    FILE *log_file;
    char log_file_name[MAX_LOG_LENGTH];
} Logger;

void start_logging(Logger *logger);
void log_message(Logger *logger, LogLevel level, const char *message);
DWORD find_process_id(const char *process_name);
HANDLE open_process(DWORD target_pid);
LPVOID allocate_memory(HANDLE process_handle, SIZE_T size);
void write_memory(HANDLE process_handle, LPVOID base_address, const char *dll_path);
LPVOID get_load_library_address();
void create_remote_thread(HANDLE process_handle, LPVOID load_library, LPVOID alloc_mem);
void free_memory(HANDLE process_handle, LPVOID base_address);
void cleanup(HANDLE process_handle, LPVOID alloc_mem, Logger *logger);
void handle_error(const char *message);
void log_dll_injection_details(Logger *logger, const char *dll_path, DWORD target_pid);
void handle_command_line_arguments(int argc, char *argv[], char **target_process_name, char **dll_paths[], int *dll_count);
void print_usage(const char *program_name);

int main(int argc, char *argv[]) {
    char *target_process_name;
    char *dll_paths[MAX_DLL_COUNT];
    int dll_count = 0;

    handle_command_line_arguments(argc, argv, &target_process_name, dll_paths, &dll_count);
    
    Logger logger;
    start_logging(&logger);
    log_message(&logger, LOG_LEVEL_INFO, "Starting DLL injection process...");

    DWORD target_pid = find_process_id(target_process_name);
    if (target_pid == 0) {
        log_message(&logger, LOG_LEVEL_ERROR, "Could not find target process");
        cleanup(NULL, NULL, &logger);
        return EXIT_FAILURE;
    }

    log_message(&logger, LOG_LEVEL_INFO, "Target PID found. Proceeding with injection...");

    HANDLE process_handle = open_process(target_pid);

    for (int i = 0; i < dll_count; ++i) {
        const char *dll_path = dll_paths[i];
        if (strlen(dll_path) > MAX_DLL_PATH_LENGTH) {
            log_message(&logger, LOG_LEVEL_WARNING, "DLL path exceeds maximum length");
            continue; // Skip this DLL but continue with others
        }

        LPVOID alloc_mem = allocate_memory(process_handle, strlen(dll_path) + 1);
        write_memory(process_handle, alloc_mem, dll_path);
        LPVOID load_library = get_load_library_address();
        create_remote_thread(process_handle, load_library, alloc_mem);
        log_dll_injection_details(&logger, dll_path, target_pid);
    }

    log_message(&logger, LOG_LEVEL_INFO, "DLL injection process completed!");
    cleanup(process_handle, NULL, &logger);
    return EXIT_SUCCESS;
}

void start_logging(Logger *logger) {
    SYSTEMTIME time;
    GetLocalTime(&time);
    
    snprintf(logger->log_file_name, MAX_LOG_LENGTH, "injection_log_%04d-%02d-%02d_%02d-%02d-%02d.txt",
            time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

    logger->log_file = fopen(logger->log_file_name, "w");
    if (logger->log_file == NULL) {
        handle_error("Failed to create log file");
    }
}

void log_message(Logger *logger, LogLevel level, const char *message) {
    const char *level_str;
    switch (level) {
        case LOG_LEVEL_INFO: level_str = "[INFO]"; break;
        case LOG_LEVEL_WARNING: level_str = "[WARNING]"; break;
        case LOG_LEVEL_ERROR: level_str = "[ERROR]"; break;
        case LOG_LEVEL_DEBUG: level_str = "[DEBUG]"; break;
        default: level_str = "[LOG]"; break;
    }
    fprintf(logger->log_file, "%s %s\n", level_str, message);
    fflush(logger->log_file);
}

DWORD find_process_id(const char *process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_PROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        handle_error("Failed to create process snapshot");
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process_entry)) {
        do {
            if (strcmp(process_entry.szExeFile, process_name) == 0) {
                CloseHandle(snapshot);
                return process_entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &process_entry));
    }

    CloseHandle(snapshot);
    return 0;
}

HANDLE open_process(DWORD target_pid) {
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (process_handle == NULL) {
        handle_error("Failed to open process");
    }
    return process_handle;
}

LPVOID allocate_memory(HANDLE process_handle, SIZE_T size) {
    LPVOID base_address = VirtualAllocEx(process_handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (base_address == NULL) {
        handle_error("Failed to allocate memory in target process");
    }
    return base_address;
}

void write_memory(HANDLE process_handle, LPVOID base_address, const char *dll_path) {
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_handle, base_address, dll_path, strlen(dll_path) + 1, &bytes_written) || bytes_written != strlen(dll_path) + 1) {
        handle_error("Failed to write memory in target process");
    }
}

LPVOID get_load_library_address() {
    HMODULE kernel32_handle = GetModuleHandleA("kernel32.dll");
    if (kernel32_handle == NULL) {
        handle_error("Failed to get handle for kernel32.dll");
    }

    LPVOID load_library_address = GetProcAddress(kernel32_handle, "LoadLibraryA");
    if (load_library_address == NULL) {
        handle_error("Failed to get address of LoadLibraryA");
    }

    return load_library_address;
}

void create_remote_thread(HANDLE process_handle, LPVOID load_library, LPVOID alloc_mem) {
    HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)load_library, alloc_mem, 0, NULL);
    if (thread_handle == NULL) {
        handle_error("Failed to create remote thread");
    }

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
}

void free_memory(HANDLE process_handle, LPVOID base_address) {
    if (!VirtualFreeEx(process_handle, base_address, 0, MEM_RELEASE)) {
        handle_error("Failed to free memory in target process");
    }
}

void cleanup(HANDLE process_handle, LPVOID alloc_mem, Logger *logger) {
    if (alloc_mem) {
        free_memory(process_handle, alloc_mem);
    }
    if (process_handle) {
        CloseHandle(process_handle);
    }
    if (logger->log_file) {
        fclose(logger->log_file);
    }
}

void handle_error(const char *message) {
    fprintf(stderr, "[ERROR] %s\n", message);
    exit(EXIT_FAILURE);
}

void log_dll_injection_details(Logger *logger, const char *dll_path, DWORD target_pid) {
    char log_msg[MAX_LOG_LENGTH];
    snprintf(log_msg, MAX_LOG_LENGTH, "Injected DLL: %s into PID: %u", dll_path, target_pid);
    log_message(logger, LOG_LEVEL_INFO, log_msg);
}

void handle_command_line_arguments(int argc, char *argv[], char **target_process_name, char **dll_paths[], int *dll_count) {
    if (argc < 3 || argc > MAX_DLL_COUNT + 2) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    *target_process_name = argv[1];
    *dll_count = argc - 2;

    for (int i = 0; i < *dll_count; i++) {
        (*dll_paths)[i] = argv[i + 2];
    }
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s <target_process_name> <path_to_dll1> [<path_to_dll2> ... <path_to_dllN>]\n", program_name);
}

void sleep_and_retry(HANDLE process_handle, int retries) {
    for (int i = 0; i < retries; i++) {
        Sleep(1000); // Wait for 1 second before retrying
        if (WaitForSingleObject(process_handle, 0) == WAIT_OBJECT_0) {
            log_message(&logger, LOG_LEVEL_INFO, "Process has exited, retrying...");
            return;
        }
    }
}

void handle_memory_allocation_failure(HANDLE process_handle, LPVOID alloc_mem, Logger *logger) {
    log_message(logger, LOG_LEVEL_ERROR, "Memory allocation failed, attempting to free allocated memory...");
    if (alloc_mem) {
        free_memory(process_handle, alloc_mem);
    }
    cleanup(process_handle, alloc_mem, logger);
}

