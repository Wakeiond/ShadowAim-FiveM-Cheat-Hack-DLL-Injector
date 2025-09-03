

#include <chrono>
#include <mutex>
#include <thread>
#include <windows.h>
#include <winternl.h>
#include <iostream>

int main()
{

    DWORD OldProtect;
    VirtualProtect((PVOID)&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
    *(BYTE*)&FreeConsole = 0xC3;

    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout)
        ;
    SetWindowPos(GetConsoleWindow(), HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_DRAWFRAME);

    SetConsoleTitleA("A WE KNOW");
    std::cout << "Hello World!\n";

    std::cin.get();
}



BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "test", "test", MB_OK);
    break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
