
#include <windows.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <print>
#include <ranges>
#include <filesystem>

#include <minhook/MinHook.h>

#pragma comment(lib, "minhook/libMinHook.x86.lib")

using CreateProcessW_t = BOOL(__stdcall*) (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
CreateProcessW_t o_CreateProcessW = nullptr;

void open_binary(std::string m_sSource, std::vector< std::uint8_t >& m_aData)
{
    std::ifstream m_strFile(m_sSource, std::ios::binary);
    m_strFile.unsetf(std::ios::skipws);
    m_strFile.seekg(0, std::ios::end);

    const auto m_iSize = m_strFile.tellg();

    m_strFile.seekg(0, std::ios::beg);
    m_aData.reserve(static_cast<uint32_t>(m_iSize));
    m_aData.insert(m_aData.begin(), std::istream_iterator< std::uint8_t >(m_strFile), std::istream_iterator< std::uint8_t >());
    m_strFile.close();
}

void wstring2string(const std::wstring& sSource, std::string& sDest)
{
    std::string tmp;
    tmp.resize(sSource.size());
    std::transform(sSource.begin(), sSource.end(), tmp.begin(), wctob);
    tmp.swap(sDest);
}

BOOL __stdcall hooked_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcAttr,
    LPSECURITY_ATTRIBUTES lpThreadAttr, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDir, LPSTARTUPINFOW pStartupInfo, LPPROCESS_INFORMATION pProcessInfo)
{
    std::wstring wsApplicationName = std::wstring(lpCommandLine);

    std::string sApplicationName;
    wstring2string(wsApplicationName, sApplicationName);

    if (!strstr(sApplicationName.data(), "csgo.exe")) {
        return o_CreateProcessW(lpApplicationName, lpCommandLine, lpProcAttr, lpThreadAttr, bInheritHandles,
            dwCreationFlags, lpEnvironment, lpCurrentDir, pStartupInfo, pProcessInfo);
    }

    BOOL result = o_CreateProcessW(lpApplicationName, lpCommandLine, lpProcAttr, lpThreadAttr, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDir, pStartupInfo, pProcessInfo);

    if (!result) {
        return result;
    }

    if (HANDLE handle = pProcessInfo->hProcess; handle) {
        const std::filesystem::path path{ "C:\\moneybot" };

        int allocated_count{ 0 };

        for (const auto& file : std::filesystem::directory_iterator{ path }) {

            std::vector<std::string> split_string = file.path().string() | std::ranges::views::split('_') | std::ranges::views::transform(std::ranges::to<std::string>()) | std::ranges::to<std::vector>();

            const int base_address = std::stoi(split_string.at(1), 0, 16);
            const int size = std::stoi(split_string.at(2).substr(0, split_string.at(2).find('.')), 0, 16);

            //std::println("base: {:x} -> size : {:x}", base_address, size);

            void* allocated = VirtualAllocEx(handle, reinterpret_cast<void*>(base_address), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!allocated) {
                std::println("Failed to allocate memory for cheat -- closing csgo and retry.");
                TerminateProcess(handle, 0);
                return result;
            }

            allocated_count++;
        }

        std::println("Allocated {} pages of memory", allocated_count);

        for (const auto& file : std::filesystem::directory_iterator{ path }) {
            std::vector<std::string> split_string = file.path().string() | std::ranges::views::split('_') | std::ranges::views::transform(std::ranges::to<std::string>()) | std::ranges::to<std::vector>();

            const int base_address = std::stoi(split_string.at(1), 0, 16);
            const int size = std::stoi(split_string.at(2).substr(0, split_string.at(2).find('.')), 0, 16);

            std::vector<uint8_t> hack{};
            open_binary(file.path().string(), hack);

            if (!hack.size()) {
                std::println("Failed to read file {} -- missing permission? try running steam as admin.", file.path().string());
                TerminateProcess(handle, 0);
                return result;
            }

            if (!WriteProcessMemory(handle, reinterpret_cast<void*>(base_address), hack.data(), hack.size(), nullptr)) {
                std::println("Failed to write memory -- did csgo close?????");
                TerminateProcess(handle, 0);
                return result;
            }
        }
    }

    return result;
}

void init()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    SetConsoleTitleA("god i wish i had moneybot");

    if (!std::filesystem::exists("C:\\moneybot")) {
        MessageBoxA(0, "Please put the folder moneybot into C: -- Exiting", "Failure", 0);
        TerminateProcess(reinterpret_cast<HANDLE>(-1), 0);
        return;
    }

    if (MH_Initialize() != MH_OK)
    {
        MessageBoxA(NULL, "Failed to initialize hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

    if (MH_CreateHookApi(L"kernelbase.dll", "CreateProcessW", hooked_CreateProcessW, reinterpret_cast<void**>(&o_CreateProcessW)) != MH_OK)
    {
        MessageBoxA(NULL, "Failed to create hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        MessageBoxA(NULL, "Failed to enable hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

    std::println("Waiting on game launch...");
}

BOOL __stdcall DllMain([[maybe_unused]] HMODULE hModule, DWORD ulReason, [[maybe_unused]] LPVOID lpReserved)
{
    if (ulReason != DLL_PROCESS_ATTACH)
        return 0;


    CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr);
    return 1;
}