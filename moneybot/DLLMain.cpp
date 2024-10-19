#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <print>
#include <format>
#include <ranges>
#include <filesystem>
#include <unordered_map>

#pragma comment(lib, "Ws2_32.lib")

#include <minhook/MinHook.h>
#pragma comment(lib, "minhook/libMinHook.x86.lib")

#include "modules/advapi32.h"
#include "modules/D3DX9_43.h"
#include "modules/gdi32.h"
#include "modules/kernel32.h"
#include "modules/msvcp140.h"
#include "modules/ntdll.h"
#include "modules/shell32.h"
#include "modules/ucrtbase.h"
#include "modules/user32.h"
#include "modules/VCRUNTIME140.h"
#include "modules/winmm.h"
#include "modules/ws2_32.h"

#include "obfuscated_calls.h"
#include "obfuscated_jmps.h"

struct dmp_symbol
{
	const char* module;
	const char* proc;
	uintptr_t   address;
};

std::unordered_map<uintptr_t, dmp_symbol> dmp_symbols;

uintptr_t __stdcall get_target(uintptr_t old_address)
{
	if (auto it = dmp_symbols.find(old_address); it != dmp_symbols.end()) {
		return it->second.address;
	}
	return -1;
}

uintptr_t get_target_impl = reinterpret_cast<uintptr_t>(&get_target);

std::array<uint8_t, 19> obfuscation_redirect_shellcode =
{
	0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0x60, 0x50, 0xFF, 0x15, reinterpret_cast<uintptr_t>(&get_target_impl), 0x89, 0x44, 0x24, 0x20, 0x61, 0x58
};

#pragma pack(1)
struct obfuscation_hook
{
	uint8_t original_bytes[8];
	uint8_t shellcode0[9];
	uint32_t get_target_impl_address;
	uint8_t shellcode1[6];
	uint8_t push;
	uint32_t return_address;
	uint8_t shellcode2[3];
};
#pragma pack()

obfuscation_hook* obfuscated_call_hooks;
obfuscation_hook* obfuscated_jmp_hooks;

bool init_obfuscation_hooks(auto& calls, auto& jmps)
{
	size_t calls_size = sizeof(obfuscation_hook) * (calls.size() + 1);
	size_t jmps_size = sizeof(obfuscation_hook) * (jmps.size() + 1);

	obfuscated_call_hooks = (obfuscation_hook*)VirtualAlloc(nullptr, calls_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	obfuscated_jmp_hooks = (obfuscation_hook*)VirtualAlloc(nullptr, jmps_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!obfuscated_call_hooks || !obfuscated_jmp_hooks)
		return false;

	static auto init_hook = [&](obfuscation_hook* hook, uintptr_t start, size_t size, bool is_call = false)
		{
			static std::array<uint8_t, 9> shellcode0 = { 0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0x60, 0x50, 0xFF, 0x15 };
			static std::array<uint8_t, 6> shellcode1 = { 0x89, 0x44, 0x24, 0x20, 0x61, 0x58 };
			static std::array<uint8_t, 3> shellcode2 = { 0xFF, 0xE0, 0xCC };

			memset(hook, 0x90, sizeof(obfuscation_hook));
			// copy old bytes
			memcpy(hook, reinterpret_cast<void*>(start), size);
			// set up shellcodes...
			memcpy(hook->shellcode0, shellcode0.data(), shellcode0.size());
			memcpy(hook->shellcode1, shellcode1.data(), shellcode1.size());
			memcpy(hook->shellcode2, shellcode2.data(), shellcode2.size());

			hook->get_target_impl_address = reinterpret_cast<uint32_t>(&get_target_impl);
			
			// set up return address
			if (is_call)
			{
				hook->push = 0x68;
				hook->return_address = start + size + 2;
			}

			// set up hook
			// fill with int3
			memset(reinterpret_cast<void*>(start), 0xCC, size + 2);
			*reinterpret_cast<uint8_t*>(start) = 0xE9;
			*reinterpret_cast<uint32_t*>(start + 1) = reinterpret_cast<uintptr_t>(hook) - start - 5;

		};

	// calls
	for (size_t i = 0; i < calls.size(); i++)
	{
		obfuscated_call_t& call = calls[i];
		obfuscation_hook* hook = &obfuscated_call_hooks[i];
		init_hook(hook, call.start_address, call.size2call, true);
	}

	// jmps
	for (size_t i = 0; i < jmps.size(); i++)
	{
		obfuscated_jmp_t& jmp = jmps[i];
		obfuscation_hook* hook = &obfuscated_jmp_hooks[i];
		init_hook(hook, jmp.start_address, jmp.size2jmp);
	}

	return true;
}

void load_modules()
{
	auto load_symbols = [&](const moneybot::module& module)
		{
			for (auto& symbol : module.export_symbols)
			{
				dmp_symbols[symbol.address] = { module.name,symbol.name, reinterpret_cast<uintptr_t>(GetProcAddress(LoadLibraryA(module.name),symbol.name)) };
			}
		};
	load_symbols(advapi32);
	load_symbols(D3DX9_43);
	load_symbols(gdi32);
	load_symbols(kernel32);
	load_symbols(msvcp140);
	load_symbols(ntdll);
	load_symbols(shell32);
	load_symbols(ucrtbase);
	load_symbols(user32);
	load_symbols(VCRUNTIME140);
	load_symbols(winmm);
	load_symbols(ws2_32);
}

void fix_iat()
{
	uintptr_t start = 0x7fff0000 + 0x762000;
	uintptr_t end = 0x7fff0000 + 0x762650;

	for (uintptr_t* cur = reinterpret_cast<uintptr_t*>(start); cur <= reinterpret_cast<uintptr_t*>(end); cur++)
	{
		uintptr_t address = *cur;

		if (!address)
		{
			continue;
		}

		if (auto it = dmp_symbols.find(address); it != dmp_symbols.end()) {
			*cur = it->second.address;
		}

	}
}

decltype(&connect) oConnect;

int WSAAPI hooked_connect(
	_In_ SOCKET s,
	_In_reads_bytes_(namelen) const struct sockaddr FAR * name,
	_In_ int namelen
)
{
	std::println("Connect called");
	return true;
	//return oConnect(s, name, namelen);
}

decltype(&GetCurrentProcessId) oGetCurrentProcessId;

DWORD
WINAPI
hooked_GetCurrentProcessId(
	VOID
)
{
	return 18344;
}


void init()
{
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	SetConsoleTitleA("god i wish i had moneybot");

	std::println("Welcome");

	std::println("Waiting for serverbrowser.dll ...");
	while (!GetModuleHandleA("serverbrowser.dll")) {
		Sleep(1000);
	}
	std::println("Found serverbrowser.dll !");

	std::println("Loading symbols...");
	load_modules();
	std::println("Loaded {} symbols!", dmp_symbols.size());

	std::println("Fixing iat...");
	fix_iat();
	std::println("Fixed iat!");

	std::println("Patching...");

	if (!init_obfuscation_hooks(obfuscated_calls, obfuscated_jmps))
	{
		std::println("Failed to create obfuscation hooks!");
		std::println("Exiting...");
		return;
	}

	std::println("Patched {} obfuscated calls at {}!", obfuscated_calls.size(), (void*)obfuscated_call_hooks);
	std::println("Patched {} obfuscated jmps at {}!", obfuscated_jmps.size(), (void*)obfuscated_jmp_hooks);

	std::array<uint8_t, 9> remove_server_connection = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
		};

	memcpy(reinterpret_cast<void*>(0x804E39C4), remove_server_connection.data(), remove_server_connection.size());

	std::println("Patched server connection!");

	std::println("Patched!");

	std::println("Enabling hooks...");

    if (MH_Initialize() != MH_OK)
    {
        MessageBoxA(NULL, "Failed to initialize hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

	if (MH_CreateHook(&connect, hooked_connect, reinterpret_cast<void**>(&oConnect)) != MH_OK)
	{
		std::println("Failed to create hook at connect");
		return;
	}

	if (MH_CreateHook(&GetCurrentProcessId, hooked_GetCurrentProcessId, reinterpret_cast<void**>(&oGetCurrentProcessId)) != MH_OK)
	{
		std::println("Failed to create hook at GetCurrentProcessId");
		return;
	}

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        MessageBoxA(NULL, "Failed to enable hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

	std::println("Enabled hooks!");
    std::println("Calling OEP @ 0x1380000");

	CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(0x1380000), nullptr, 0, nullptr);

	std::println("Cracked by PinkKing and MOxXiE1337 <3"); 
}

BOOL __stdcall DllMain([[maybe_unused]] HMODULE hModule, DWORD ulReason, [[maybe_unused]] LPVOID lpReserved)
{
	if (ulReason != DLL_PROCESS_ATTACH) {
		return 0;
	}

    CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr);
    return 1;
}