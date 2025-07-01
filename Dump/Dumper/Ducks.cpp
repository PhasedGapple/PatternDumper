#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
// made by ducks
struct PatternInfo {
    std::string pattern;
    std::string name;
};

bool PatternToBytes(const std::string& pattern, std::vector<BYTE>& bytes, std::string& mask) {
    bytes.clear();
    mask.clear();

    size_t i = 0;
    while (i < pattern.size()) {
        if (pattern[i] == ' ') {
            i++;
            continue;
        }
        if (pattern[i] == '?') {
            bytes.push_back(0x00);
            mask += '?';
            i++;
            if (i < pattern.size() && pattern[i] == '?') i++;
        }
        else {
            if (i + 1 >= pattern.size()) return false;
            auto hexCharToInt = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                else if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
                };
            int high = hexCharToInt(pattern[i]);
            int low = hexCharToInt(pattern[i + 1]);
            if (high == -1 || low == -1) return false;
            bytes.push_back((BYTE)((high << 4) | low));
            mask += 'x';
            i += 2;
        }
    }
    return true;
}

bool DataCompare(const BYTE* data, const BYTE* pattern, const std::string& mask, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (mask[i] == 'x' && data[i] != pattern[i])
            return false;
    }
    return true;
}

uintptr_t ScanRegion(HANDLE hProcess, uintptr_t base, size_t size, const std::vector<BYTE>& pattern, const std::string& mask) {
    std::vector<BYTE> buffer(size);
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, (LPCVOID)base, buffer.data(), size, &bytesRead) || bytesRead < pattern.size()) {
        return 0;
    }

    for (size_t i = 0; i <= bytesRead - pattern.size(); i++) {
        if (DataCompare(buffer.data() + i, pattern.data(), mask, pattern.size())) {
            return base + i;
        }
    }
    return 0;
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                processId = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return processId;
}

uintptr_t GetModuleBaseAddress(DWORD pid, const std::wstring& moduleName) {
    uintptr_t baseAddress = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &moduleEntry)) {
        do {
            if (moduleName == moduleEntry.szModule) {
                baseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                break;
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }
    CloseHandle(snapshot);
    return baseAddress;
}

SIZE_T GetModuleSize(DWORD pid, const std::wstring& moduleName) {
    SIZE_T moduleSize = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &moduleEntry)) {
        do {
            if (moduleName == moduleEntry.szModule) {
                moduleSize = moduleEntry.modBaseSize;
                break;
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }
    CloseHandle(snapshot);
    return moduleSize;
}

int main() {
    std::ofstream ofs("offsets.txt");

    std::streambuf* coutbuf = std::cout.rdbuf();   // Save old buffer
    std::cout.rdbuf(ofs.rdbuf());                   // Redirect std::cout to file

    std::wstring targetProcessName = L"RobloxPlayerBeta.exe";
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (!pid) {
        std::cerr << "Roblox process not found." << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "Roblox PID: " << pid << std::endl;

    uintptr_t moduleBase = GetModuleBaseAddress(pid, targetProcessName);
    if (!moduleBase) {
        std::cerr << "Failed to get module base address." << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "Module Base Address: 0x" << std::hex << moduleBase << std::dec << std::endl;

    SIZE_T moduleSize = GetModuleSize(pid, targetProcessName);
    if (moduleSize == 0) {
        std::cerr << "Failed to get module size." << std::endl;
        system("pause");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open Roblox process." << std::endl;
        system("pause");
        return 1;
    }

    std::vector<PatternInfo> patterns = {
        {"48 8D 05 ? ? ? ? 48 83 C4 ? C3 48 8D 0D ? ? ? ? E8 ? ? ? ? 90 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C4 ? C3 48 8D 0D ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 75 ? 48 8D 4C 24", "AppDataInfo"},
        {"8B C1 33 01 33 49 ? 89 4C 24 ? 89 44 24 ? 48 8B 44 24 ? C3", "DecryptLuaState"},
        {"4C 8D 05 ? ? ? ? 41 B9 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 33 FF", "EnableLoadModule"},
        {"48 89 5C 24 ? 55 56 57 48 83 EC ? 49 8B F8 48 8B F1 33 ED 89 AC 24 ? ? ? ? F3 0F 10 81 ? ? ? ? 0F 2F C1 0F 86", "FireClickDetector"},
        {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 79 ? 41 0F B6 F1", "FireMouseClick"},
        {"48 83 EC ? 48 81 F9 ? ? ? ? 72", "FireProximityPrompt"},
        {"48 89 5C 24 ? 55 56 57 48 83 EC ? 49 8B F8 48 8B F1 33 ED 89 AC 24 ? ? ? ? F3 0F 10 81 ? ? ? ? 0F 2F C1 CC", "FireRightMouseClick"},
        {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 79 ? 41 0F B6 F1", "FireTouchInterest"},
        {"48 89 5C 24 ? 57 48 83 EC ? 48 8B 41 ? 48 85 C0", "GetAssemblyPrimitive"},
        {"48 89 54 24 ? 48 83 EC ? 4C 8B D1 44 0F B6 CA", "GetContextObject"},
        {"48 89 5C 24 ? 48 89 74 24 ? 48 89 4C 24 ? 55 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 4C 8B 35", "GetFFlag"},
        {"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B FA 48 8B D9 49 8B 08", "GetGlobalState"},
        {"40 57 48 8B 39 4C 8B 41 ? 49 3B F8 75 ? 45 33 C9 41 8B C9", "GetProperty"},
        {"48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 45 0F B6 D1", "GetValue"},
        {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 E8 ? ? ? ? 90", "IdentityStruct"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 49 8B E9", "Impersonator"},
        {"48 8d 0d ? ? ? ? 48 8d 54 24 ? 48 8b 04 c1", "KTable"},
        {"48 8D 0D ? ? ? ? E8 ? ? ? ? 0F B6 C0 85 C0 74 ? 4C 8B 84 24 ? ? ? ? 48 8B 94 24 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 89 44 24 ? 48 8B 44 24 ? 48 89 44 24 ? 48 8B 4C 24 ? E8 ? ? ? ? 48 8B D0 48 8D 0D ? ? ? ? E8 ? ? ? ? 90 48 8D 4C 24 ? E8 ? ? ? ? EB", "LockViolationInstanceCrash"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B 59 ? B8", "LuaC_step"},
        {"48 83 EC ? 44 8B C2 48 8B D1 48 8D 4C 24", "LuaD_throw"},
        {"48 8d 3d ? ? ? ? 48 8B D9 48 39", "LuaH_Dummynode"},
        {"48 89 5C 24 ? 4C 89 44 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 4D 8B E8 4C 8B E2", "LuaL_register"},
        {"48 8d 3d ? ? ? ? 48 3b d7", "LuaO_NilObject"},
        {"4C 89 44 24 ? 48 89 4C 24 ? 53 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 41 8B F9", "LuaVM_Load"},
        {"80 79 06 00 0F 85 ? ? ? ? E9 ? ? ? ?", "Luau_Execute"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B FA 48 8B F1 33 ED 89 AC 24 ? ? ? ? 48 85 D2", "MouseHoverEnter"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B FA 48 8B F1 33 ED 89 AC 24 ? ? ? ? 48 8B 01", "MouseHoverLeave"},
        {"48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 55 53 56 57 41 54 41 55", "Pseudo2addr"},
        {"48 89 5C 24 08 57 48 83 EC ? 48 8B FA 48 8B D9 E8 ? ? ? ? 84 C0 74 ? 48 8B D7 48 8B CB 48 8B 5C 24 30", "PushInstance"},
        {"48 89 5C 24 ? 55 56 57 48 83 EC ? 49 8B F1 49 8B E8 48 8B FA 48 8B D9 48 83 79", "RaiseEventInvocation"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B EA 48 8B F9 48 85 D2", "RequestCode"},
        {"0F B6 86 ? ? ? ? 48 89 2F", "require"},
        {"48 8B C4 44 89 48 ? 4C 89 40 ? 48 89 50 ? 48 89 48 ? 53", "ScriptContextResume"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 56 48 83 EC ? 33 DB", "SetProtoCapabilities"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 48 8B F9 80 3D", "Task.Defer"},
        {"48 89 5C 24 ? 55 56 57 48 81 EC ? ? ? ? 48 8B D9 80 3D", "Task.Spawn"},
        {"48 83 EC ? 4C 8D 15 ? ? ? ? 85 D2", "LuaA_toobject"},
        {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 63 FA 49 8B F0", "luaL_checklstring"},
        {"40 56 41 54 41 55 48 83 EC", "luaM_visitgco"},
        {"48 89 05 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 3D ? ? ? ? EB ? 48 8B 08 8B 04 0B", "RawScheduler"}
        // {"15 ?? ?? ?? ?? 89 C2 45 89", "YaraResult"} doesnt work - i didnt add this one yet because its in the dll
    };

    uintptr_t startAddress = moduleBase;
    uintptr_t endAddress = moduleBase + moduleSize;

    MEMORY_BASIC_INFORMATION memInfo;
    bool foundAny = false;

    for (const auto& patternInfo : patterns) {
        std::vector<BYTE> patternBytes;
        std::string mask;
        if (!PatternToBytes(patternInfo.pattern, patternBytes, mask)) {
            std::cerr << "Failed to parse pattern for " << patternInfo.name << std::endl;
            continue;
        }

        uintptr_t currentAddress = startAddress;
        bool foundPattern = false;
        size_t regionsScanned = 0;

        while (currentAddress < endAddress) {
            if (VirtualQueryEx(hProcess, (LPCVOID)currentAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
                regionsScanned++;

                if ((memInfo.State == MEM_COMMIT) &&
                    !(memInfo.Protect & PAGE_GUARD) &&
                    !(memInfo.Protect & PAGE_NOACCESS) &&
                    memInfo.BaseAddress >= (LPCVOID)startAddress &&
                    (uintptr_t)memInfo.BaseAddress < endAddress) {

                    uintptr_t regionStart = (uintptr_t)memInfo.BaseAddress;
                    SIZE_T regionSize = memInfo.RegionSize;

                    if (regionStart + regionSize > endAddress) {
                        regionSize = endAddress - regionStart;
                    }

                    uintptr_t found = ScanRegion(hProcess, regionStart, regionSize, patternBytes, mask);
                    if (found) {
                        uintptr_t offset = found - moduleBase;
                        std::cout << "[" << patternInfo.name << "] Pattern found at address: 0x"
                            << std::hex << found << " (offset: 0x" << offset << ")" << std::dec << std::endl;
                        foundPattern = true;
                        foundAny = true;
                        break;
                    }
                }
                currentAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
            }
            else {
                break;
            }
        }

        if (!foundPattern) {
            std::cout << "[" << patternInfo.name << "] Pattern not found after scanning " << regionsScanned << " regions." << std::endl;
        }
    }

    CloseHandle(hProcess);
    system("pause");
    return 0;
}