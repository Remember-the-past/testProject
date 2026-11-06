#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <wchar.h>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winmm.lib")


#include "driver_blob.h"
#include "msdk_blob.h"


#if defined(_WIN64)
#error "xx.exe 是 32 位；msdk.dll 也是 PE32。请用 vcvars32（cl 默认 x86 目标）编译本文件。"
#endif


// ===== 驱动 / 设备相关名字（已替换为 Xxx） =====
static const wchar_t* kDevicePath  = L"\\\\.\\XxxDevice";
static const wchar_t* kServiceName = L"Xxx_Service";
static const wchar_t* kServiceDisp = L"Xxx physical memory driver";
static const wchar_t* kDriverFile  = L"\\System32\\drivers\\Xxx.sys";

static const wchar_t* kSoundInsert = L"C:\\Windows\\Media\\Windows Hardware Insert.wav";
static const wchar_t* kSoundRemove = L"C:\\Windows\\Media\\Windows Hardware Remove.wav";
static const wchar_t* kConfigPath  = L"D:\\config11.ini";


#define IOCTL_VERSION       0x9C406400u
#define IOCTL_PORT_READ     0x9C406404u
#define IOCTL_PORT_WRITE    0x9C406408u
#define IOCTL_PCI_READ      0x9C40640Cu
#define IOCTL_PCI_WRITE     0x9C406410u
#define IOCTL_MAP_PHYS      0x9C40644Cu
#define IOCTL_UNMAP_PHYS    0x9C406450u

#define CACHE_WB 2u

#define PAGE_SZ   0x1000ull
#define PAGE_MSK  0xFFFFFFFFFFFFF000ull


#define PA_MASK   0x000FFFFFFFFFF000ull
#define PS_BIT    0x80ull
#define KR_PML4   496
#define LOW_BEGIN 0x1000ull
#define LOW_END   0x4000000ull
#define LOW_MAX   0x20000000ull

static uint64_t g_lowEnd = 0;
static uint64_t g_ramTop = 0;
static uint64_t g_forceDtb = 0;
static uint64_t g_dumpDtb = 0;
static int g_noGate = -1;
static int g_vtDiag = 0;
static int g_autoDumped = 0;
#define LOW_CAP   0x4000000ull


static bool PaInRam(uint64_t pa, uint64_t size = 0x1000)
{
    if (!g_ramTop) return false;
    if (pa < 0x1000) return false;
    if (pa + size > g_ramTop) return false;
    if (pa < 0x100000 && pa + size > 0xA0000) return false;
    if (pa < 0x100000000ull)
    {
        if (pa >= 0xC0000000ull) return false;
        if (pa + size > 0xC0000000ull) return false;
    }
    return true;
}


// ===== 游戏窗口 / 进程名（已替换为 Xxx / xxx.exe / XxxWindowClass） =====
static const uint16_t kObfWindowClass[] = {
    0xD880, 0xD8A0, 0xD8A0, 0xD88F, 0xD8B1, 0xD8B6, 0xD8BC, 0xD8B7, 0xD8AF,
    0xD89B, 0xD8B4, 0xD8B9, 0xD8AB, 0xD8AB,
};
static const uint16_t kObfProcess[] = {
    0xD8A0, 0xD8A0, 0xD8A0, 0xD8F6, 0xD8BD, 0xD8A0, 0xD8BD,
};
static const uint16_t kObfWindowTitle[] = {0xD880, 0xD8A0, 0xD8A0};

static std::wstring Deobf(const uint16_t* p, size_t n)
{
    std::wstring s;
    s.resize(n);
    for (size_t i = 0; i < n; ++i) s[i] = (wchar_t)(p[i] ^ 0xD8D8);
    return s;
}


static bool g_msgbox = false;
static bool g_hidDebug = false;

static void Out(const char* fmt, ...)
{
    char b[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    printf("%s\n", b);
    fflush(stdout);
}

static void OutW(const wchar_t* fmt, ...)
{
    wchar_t b[1024];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(b, 1024, fmt, ap);
    va_end(ap);

    char u8[3072] = {};
    WideCharToMultiByte(CP_UTF8, 0, b, -1, u8, sizeof(u8), nullptr, nullptr);
    printf("%s\n", u8);
    fflush(stdout);
}

static void Fatal(bool msgbox, const wchar_t* text)
{
    OutW(L"[失败] %ls", text);
    if (msgbox || g_msgbox) MessageBoxW(nullptr, text, L"Xxx", MB_ICONERROR | MB_OK);
}


static bool IsElevated()
{
    BOOL admin = FALSE;
    PSID g = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &g))
    {
        CheckTokenMembership(nullptr, g, &admin);
        FreeSid(g);
    }
    return admin != FALSE;
}

struct WinVer
{
    uint32_t major = 0, minor = 0, build = 0;
};

static WinVer QueryWinVer()
{
    WinVer v;
    typedef LONG (WINAPI
    *PFN
    )
    (POSVERSIONINFOEXW);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    PFN f = nt ? (PFN)GetProcAddress(nt, "RtlGetVersion") : nullptr;
    if (f)
    {
        OSVERSIONINFOEXW os = {};
        os.dwOSVersionInfoSize = sizeof(os);
        if (f(&os) == 0)
        {
            v.major = os.dwMajorVersion;
            v.minor = os.dwMinorVersion;
            v.build = os.dwBuildNumber;
        }
    }
    return v;
}


static bool WriteDriverFile(std::wstring* pathOut)
{
    wchar_t winDir[MAX_PATH] = {};
    if (!GetWindowsDirectoryW(winDir, MAX_PATH))
    {
        Out("[驱动] GetWindowsDirectoryW 失败");
        return false;
    }
    std::wstring path = std::wstring(winDir) + kDriverFile;

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        Out("[驱动] 创建 %ls 失败 err=%lu", path.c_str(), GetLastError());
        return false;
    }
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, kDriverBlob, kDriverBlobSize, &wrote, nullptr);
    CloseHandle(h);
    if (!ok || wrote != kDriverBlobSize)
    {
        Out("[驱动] 写驱动失败 err=%lu（写入 %lu/%u）", GetLastError(), wrote, kDriverBlobSize);
        DeleteFileW(path.c_str());
        return false;
    }
    OutW(L"[驱动] 已释放 %ls（%u 字节）", path.c_str(), kDriverBlobSize);
    *pathOut = path;
    return true;
}

static bool WaitServiceRunning(SC_HANDLE svc, DWORD timeoutMs)
{
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs)
    {
        SERVICE_STATUS_PROCESS ssp = {};
        DWORD need = 0;
        if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof(ssp), &need)) return false;
        if (ssp.dwCurrentState == SERVICE_RUNNING) return true;
        if (ssp.dwCurrentState == SERVICE_STOPPED) return false;
        Sleep(50);
    }
    return false;
}

static bool InstallAndStartDriver(const std::wstring& drvPath)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        Out("[驱动] OpenSCManagerW 失败 err=%lu", GetLastError());
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, kServiceName,
                                 SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
    if (!svc)
    {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_DOES_NOT_EXIST)
        {
            Out("[驱动] OpenServiceW 失败 err=%lu", e);
            CloseServiceHandle(scm);
            return false;
        }
        svc = CreateServiceW(scm, kServiceName, kServiceDisp,
                             SERVICE_START | SERVICE_QUERY_STATUS,
                             SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                             drvPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc)
        {
            Out("[驱动] CreateServiceW 失败 err=%lu", GetLastError());
            CloseServiceHandle(scm);
            return false;
        }
        Out("[驱动] 服务已创建 Xxx_Service");
    }
    else
    {
        if (ChangeServiceConfigW(svc, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                 drvPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, kServiceDisp))
            Out("[驱动] 服务配置已刷新");
        else
            Out("[驱动] ChangeServiceConfigW err=%lu（继续）", GetLastError());
    }

    bool ok = true;
    if (!StartServiceW(svc, 0, nullptr))
    {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING)
        {
            Out("[驱动] 服务已在运行");
        }
        else if (e == ERROR_FILE_NOT_FOUND)
        {
            Out("[驱动] StartServiceW: 驱动文件不存在 err=%lu", e);
            ok = false;
        }
        else
        {
            Out("[驱动] StartServiceW 失败 err=%lu（签名/策略可能拒绝）", e);
            ok = false;
        }
    }
    if (ok)
    {
        if (!WaitServiceRunning(svc, 3000))
        {
            Out("[驱动] 服务未进入 RUNNING");
            ok = false;
        }
        else Out("[驱动] 服务已 RUNNING");
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

static void RemoveDriver()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm)
    {
        SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (svc)
        {
            SERVICE_STATUS st = {};
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            if (DeleteService(svc)) Out("[驱动] 服务已删除");
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    wchar_t winDir[MAX_PATH] = {};
    if (GetWindowsDirectoryW(winDir, MAX_PATH))
    {
        std::wstring p = std::wstring(winDir) + kDriverFile;
        if (DeleteFileW(p.c_str())) OutW(L"[驱动] 已删除 %ls", p.c_str());
    }
}


class Device
{
public:
    HANDLE h = INVALID_HANDLE_VALUE;

    bool Open()
    {
        h = CreateFileW(kDevicePath, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return h != INVALID_HANDLE_VALUE;
    }

    void Close()
    {
        if (h != INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    }

    uint32_t Version()
    {
        uint32_t v = 0;
        DWORD ret = 0;
        if (h == INVALID_HANDLE_VALUE) return 0;
        if (!DeviceIoControl(h, IOCTL_VERSION, nullptr, 0, &v, sizeof(v), &ret, nullptr) || ret != 4) return 0;
        return v;
    }


    uint64_t Map(uint64_t pa, uint32_t size, uint32_t cache)
    {
        struct
        {
            uint64_t pa;
            uint32_t size;
            uint32_t cache;
        } in = {pa, size, cache};
        uint64_t va = 0;
        DWORD ret = 0;
        if (h == INVALID_HANDLE_VALUE) return 0;
        if (!DeviceIoControl(h, IOCTL_MAP_PHYS, &in, (DWORD)sizeof(in), &va, (DWORD)sizeof(va), &ret, nullptr)) return
            0;
        if (ret != sizeof(va)) return 0;
        return va;
    }

    void Unmap(uint64_t va)
    {
        if (h == INVALID_HANDLE_VALUE || !va) return;
        DWORD ret = 0;
        DeviceIoControl(h, IOCTL_UNMAP_PHYS, &va, (DWORD)sizeof(va), nullptr, 0, &ret, nullptr);
    }

    bool MapForPart(uint64_t page, uint32_t off, uint32_t n, uint32_t cache, uint64_t* va, uint32_t* skip)
    {
        if (off + n > PAGE_SZ) return false;
        uint64_t v = Map(page, (uint32_t)PAGE_SZ, cache);
        if (v)
        {
            *va = v;
            *skip = off;
            return true;
        }

        uint64_t blk = page & ~0xFFFFull;
        uint32_t delta = (uint32_t)(page - blk);
        if (delta + off + n > 0x10000) return false;
        v = Map(blk, 0x10000, cache);
        if (!v) return false;
        *va = v;
        *skip = delta + off;
        return true;
    }

    bool ReadPa(uint64_t pa, void* dst, uint32_t size)
    {
        uint8_t* d = (uint8_t*)dst;
        while (size)
        {
            uint64_t page = pa & PAGE_MSK;
            uint32_t off = (uint32_t)(pa - page);
            uint32_t n = (uint32_t)std::min<uint64_t>(size, PAGE_SZ - off);
            uint64_t va = 0;
            uint32_t skip = 0;
            if (!MapForPart(page, off, n, CACHE_WB, &va, &skip)) return false;
            bool ok = false;
            __try
            {
                memcpy(d, (const uint8_t*)va + skip, n);
                ok = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
            Unmap(va);
            if (!ok) return false;
            pa += n;
            d += n;
            size -= n;
        }
        return true;
    }


    bool ReadPaBulk(uint64_t pa, void* dst, uint32_t size)
    {
        if ((pa & 0xFFF) || (size & 0xFFF) || size == 0) return false;
        uint64_t va = Map(pa, size, CACHE_WB);
        if (!va) return false;
        bool ok = false;
        __try
        {
            memcpy(dst, (const uint8_t*)va, size);
            ok = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
        Unmap(va);
        return ok;
    }

    bool WritePa(uint64_t pa, const void* src, uint32_t size)
    {
        const uint8_t* s = (const uint8_t*)src;
        while (size)
        {
            uint64_t page = pa & PAGE_MSK;
            uint32_t off = (uint32_t)(pa - page);
            uint32_t n = (uint32_t)std::min<uint64_t>(size, PAGE_SZ - off);
            uint64_t va = 0;
            uint32_t skip = 0;
            if (!MapForPart(page, off, n, CACHE_WB, &va, &skip)) return false;
            bool ok = false;
            __try
            {
                memcpy((uint8_t*)va + skip, s, n);
                ok = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
            Unmap(va);
            if (!ok) return false;
            pa += n;
            s += n;
            size -= n;
        }
        return true;
    }
};


static HMODULE ManualMapImage(const uint8_t* raw, size_t rawSize, std::string* err)
{
    if (rawSize < 0x400)
    {
        *err = "blob too small";
        return nullptr;
    }
    auto dos = (const IMAGE_DOS_HEADER*)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        *err = "bad MZ";
        return nullptr;
    }
    auto nt = (const IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        *err = "bad PE";
        return nullptr;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        *err = "not PE32";
        return nullptr;
    }


    if (sizeof(void*) != 4)
    {
        *err = "msdk.dll is PE32 (x86); 需要 32 位编译（vcvars32）才能加载执行";
        return nullptr;
    }

    const SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE* image = (BYTE*)VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        *err = "VirtualAlloc(image)";
        return nullptr;
    }
    memcpy(image, raw, nt->OptionalHeader.SizeOfHeaders);

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        if (!sec->SizeOfRawData) continue;
        if ((size_t)sec->PointerToRawData + sec->SizeOfRawData > rawSize)
        {
            *err = "section oob";
            return nullptr;
        }
        memcpy(image + sec->VirtualAddress, raw + sec->PointerToRawData, sec->SizeOfRawData);
    }

    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress)
    {
        auto imp = (const IMAGE_IMPORT_DESCRIPTOR*)(image + impDir.VirtualAddress);
        for (; imp->Name; ++imp)
        {
            const char* dllName = (const char*)(image + imp->Name);
            HMODULE hDep = LoadLibraryA(dllName);
            if (!hDep)
            {
                *err = std::string("LoadLibrary ") + dllName;
                return nullptr;
            }


            std::vector<uint32_t> thunkCopy;
            const uint32_t* oft = nullptr;
            if (imp->OriginalFirstThunk)
            {
                oft = (const uint32_t*)(image + imp->OriginalFirstThunk);
            }
            else
            {
                auto p = (const uint32_t*)(image + imp->FirstThunk);
                for (uint32_t i = 0; p[i] && i < 4096; ++i) thunkCopy.push_back(p[i]);
                oft = thunkCopy.data();
            }
            auto ft = (uint32_t*)(image + imp->FirstThunk);
            if (g_hidDebug)
                Out("[HID] %s: OFT=0x%X FT=0x%X thunk0=0x%08X thunk1=0x%08X",
                    dllName, imp->OriginalFirstThunk, imp->FirstThunk, oft[0], oft[1]);
            for (uint32_t i = 0; oft[i]; ++i)
            {
                FARPROC fn;
                if (oft[i] & 0x80000000u)
                {
                    fn = GetProcAddress(hDep, MAKEINTRESOURCEA(oft[i] & 0xFFFF));
                }
                else
                {
                    auto ibn = (const IMAGE_IMPORT_BY_NAME*)(image + oft[i]);
                    fn = GetProcAddress(hDep, (LPCSTR)ibn->Name);
                }
                if (!fn)
                {
                    char nm[160] = {};
                    if (oft[i] & 0x80000000u) snprintf(nm, sizeof(nm), "#%u", oft[i] & 0xFFFF);
                    else snprintf(nm, sizeof(nm), "%.100s", (const char*)(image + oft[i] + 2));
                    *err = std::string("GetProcAddress ") + dllName + "!" + nm;
                    return nullptr;
                }
                ft[i] = (uint32_t)(uintptr_t)
                fn;
            }
        }
    }

    SIZE_T delta = (SIZE_T)image - nt->OptionalHeader.ImageBase;
    auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta && relDir.Size)
    {
        auto rel = (const IMAGE_BASE_RELOCATION*)(image + relDir.VirtualAddress);
        auto relEnd = (const BYTE*)rel + relDir.Size;
        while ((const BYTE*)rel < relEnd && rel->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            WORD n = (WORD)((rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
            auto item = (const WORD*)(rel + 1);
            for (WORD i = 0; i < n; ++i, ++item)
            {
                if ((*item >> 12) != IMAGE_REL_BASED_HIGHLOW) continue;
                auto p = (uint32_t*)(image + rel->VirtualAddress + (*item & 0xFFF));
                *p = (uint32_t)(*p + delta);
            }
            rel = (const IMAGE_BASE_RELOCATION*)((const BYTE*)rel + rel->SizeOfBlock);
        }
    }

    if (nt->OptionalHeader.AddressOfEntryPoint)
    {
        using DllMainFn = BOOL(WINAPI*)(HMODULE, DWORD, LPVOID);
        auto entry = (DllMainFn)(image + nt->OptionalHeader.AddressOfEntryPoint);
        entry((HMODULE)image, DLL_PROCESS_ATTACH, nullptr);
    }
    return (HMODULE)image;
}


static FARPROC ExportByOrdinal(HMODULE img, WORD ord)
{
    auto dos = (const IMAGE_DOS_HEADER*)img;
    auto nt = (const IMAGE_NT_HEADERS*)((const BYTE*)img + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return nullptr;
    auto exp = (const IMAGE_EXPORT_DIRECTORY*)((const BYTE*)img + dir.VirtualAddress);
    if (ord < exp->Base) return nullptr;
    DWORD idx = ord - exp->Base;
    if (idx >= exp->NumberOfFunctions) return nullptr;
    auto funcs = (const DWORD*)((const BYTE*)img + exp->AddressOfFunctions);
    if (!funcs[idx]) return nullptr;
    return (FARPROC)((const BYTE*)img + funcs[idx]);
}

class Msdk
{
public:
    typedef int (__stdcall*FnOpen)(int);
    typedef int (__stdcall*FnMoveTo)(int, int, int);
    typedef int (__stdcall*FnInt)(int);

    HMODULE image = nullptr;
    FnOpen open = nullptr;
    FnMoveTo moveTo = nullptr;
    FnInt releaseAllKey = nullptr;
    FnInt leftDown = nullptr;
    FnInt leftUp = nullptr;
    int hid = 0;

    bool Load(std::string* err)
    {
        image = ManualMapImage(kMsdkBlob, kMsdkSize, err);
        if (!image) return false;
        open = (FnOpen)ExportByOrdinal(image, 0x30);
        moveTo = (FnMoveTo)ExportByOrdinal(image, 0x2E);
        releaseAllKey = (FnInt)ExportByOrdinal(image, 0x33);
        leftDown = (FnInt)ExportByOrdinal(image, 0x22);
        leftUp = (FnInt)ExportByOrdinal(image, 0x23);
        return open && moveTo && releaseAllKey && leftDown && leftUp;
    }


    bool OpenAndReset()
    {
        hid = open ? open(1) : 0;
        if (!hid || hid == -1) return false;
        moveTo(hid, 10, 10);
        Sleep(50);
        releaseAllKey(hid);
        return true;
    }

    void Click(int holdMs)
    {
        if (!hid || !leftDown || !leftUp) return;
        leftDown(hid);
        if (holdMs > 0) Sleep((DWORD)holdMs);
        leftUp(hid);
    }
};


static bool IsKernelVa(uint64_t va) { return (va & 0xFFFF000000000000ull) == 0xFFFF000000000000ull; }

struct LowMem
{
    uint64_t base = 0;
    std::vector<uint8_t> buf;
    bool InRange(uint64_t pa, uint32_t n) const { return pa >= base && pa + n <= base + buf.size(); }
    const uint8_t* At(uint64_t pa) const { return InRange(pa, 1) ? buf.data() + (pa - base) : nullptr; }
};

struct PeInfo
{
    uint64_t pa = 0;
    uint32_t sizeOfImage = 0, exportRva = 0;
};

class PhysMem
{
public:
    Device& dev;
    LowMem lm;
    uint64_t ramTop = 0x800000000ull;

    explicit PhysMem(Device& d) : dev(d)
    {
    }

    uint32_t dbg1g = 0, dbg2m = 0, dbg4k = 0;

    bool Snapshot()
    {
        uint64_t ramSmi = 0, ramKernel = 0;
        if (GetPhysicallyInstalledSystemMemory(&ramSmi)) ramSmi *= 1024;
        {
            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
            if (ntdll)
            {
                typedef LONG (WINAPI
                *PFN_NtQSI
                )
                (ULONG, PVOID, ULONG, PULONG);
                PFN_NtQSI qsi = (PFN_NtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
                if (qsi)
                {
                    ULONG buf[64] = {};
                    ULONG ret = 0;
                    if (qsi(0 /*SystemBasicInformation*/, buf, sizeof(buf), &ret) >= 0)
                    {
                        uint64_t pageSize = buf[2], highest = buf[5], pages = buf[3];
                        if (pageSize && highest) ramKernel = (highest + 1) * pageSize;
                        else if (pageSize && pages) ramKernel = pages * pageSize;
                    }
                }
            }
        }
        ramTop = ramSmi > ramKernel ? ramSmi : ramKernel;
        if (!ramTop) ramTop = 0x800000000ull;


        if (ramTop < 0x8000000000ull) ramTop = 0x8000000000ull;
        Out("[内存] 物理内存：SMBIOS=%llu MB，内核最高页=%llu MB，采用 ramTop=0x%llX（%llu MB）",
            (unsigned long long)(ramSmi >> 20), (unsigned long long)(ramKernel >> 20),
            ramTop, (unsigned long long)(ramTop >> 20));
        g_ramTop = ramTop;

        uint64_t end = g_lowEnd ? g_lowEnd : LOW_END;
        if (end > LOW_MAX) end = LOW_MAX;
        if (end > ramTop) end = ramTop;
        uint32_t pages = (uint32_t)((end - LOW_BEGIN) / PAGE_SZ);
        lm.base = LOW_BEGIN;
        lm.buf.assign((size_t)pages * 0x1000, 0);


        uint32_t ok = 0, skip = 0;
        for (uint32_t i = 0; i < pages; ++i)
        {
            uint64_t pa = LOW_BEGIN + (uint64_t)i * PAGE_SZ;
            if (!PaInRam(pa))
            {
                ++skip;
                continue;
            }
            if (dev.ReadPa(pa, lm.buf.data() + (size_t)i * 0x1000, 0x1000)) ++ok;
            if ((i & 0x3FF) == 0)
            {
                printf("    读取物理内存 %u/%u 页...\r", i, pages);
                fflush(stdout);
            }
        }
        printf("                                        \r");
        Out("[内存] 低内存快照 0x%llX-0x%llX：%u/%u 页可用（%llu MB，跳过 %u 页）",
            LOW_BEGIN, end, ok, pages, (unsigned long long)(pages * 4 / 1024), skip);
        return ok > 0;
    }

    const uint8_t* Bytes(uint64_t pa, uint32_t n, std::vector<uint8_t>* scratch)
    {
        if (lm.InRange(pa, n) && PaInRam(pa, n)) return lm.At(pa);
        if (!PaInRam(pa, n)) return nullptr;
        scratch->assign(n, 0);
        return dev.ReadPa(pa, scratch->data(), n) ? scratch->data() : nullptr;
    }

    bool ProbeNtoskrnl(uint64_t pa, PeInfo* out)
    {
        std::vector<uint8_t> s1, s2, s3;
        const uint8_t* h = Bytes(pa, 0x1000, &s1);
        if (!h || h[0] != 'M' || h[1] != 'Z') return false;
        uint32_t lf = 0;
        memcpy(&lf, h + 0x3C, 4);
        if (lf < 0x40 || lf > 0x200) return false;

        const uint8_t* p = Bytes(pa, lf + 0x200, &s2);
        if (!p || memcmp(p + lf, "PE\0\0", 4) != 0) return false;
        uint16_t magic = 0;
        memcpy(&magic, p + lf + 24, 2);
        if (magic != 0x20B) return false;
        uint32_t soi = 0, erva = 0, esz = 0;
        memcpy(&soi, p + lf + 24 + 56, 4);
        memcpy(&erva, p + lf + 24 + 112, 4);
        memcpy(&esz, p + lf + 24 + 116, 4);
        if (soi < 0x100000 || soi > 0x8000000 || !erva || esz < 40) return false;
        if (erva >= soi || erva + 40 > soi) return false;

        uint8_t ed[40] = {};
        const uint8_t* e = Bytes(pa + erva, 40, &s3);
        if (!e) return false;
        memcpy(ed, e, 40);
        uint32_t nameRva = 0, numNames = 0;
        memcpy(&nameRva, ed + 12, 4);
        memcpy(&numNames, ed + 24, 4);
        if (!nameRva || !numNames || numNames > 8000) return false;
        if (nameRva >= soi) return false;

        char nm[32] = {};
        std::vector<uint8_t> s4;
        const uint8_t* q = Bytes(pa + nameRva, 32, &s4);
        if (!q) return false;
        memcpy(nm, q, 31);
        if (_stricmp(nm, "ntoskrnl.exe") != 0) return false;

        out->pa = pa;
        out->sizeOfImage = soi;
        out->exportRva = erva;
        return true;
    }

    bool FindNtoskrnl(PeInfo* out)
    {
        for (uint64_t pa = lm.base; pa + 0x1000 <= lm.base + lm.buf.size(); pa += 0x1000)
        {
            const uint8_t* p = lm.At(pa);
            if (!p || p[0] != 'M' || p[1] != 'Z') continue;
            PeInfo info;
            if (ProbeNtoskrnl(pa, &info))
            {
                Out("[内存] ntoskrnl 物理基址=0x%llX SizeOfImage=0x%X（快照内命中）",
                    info.pa, info.sizeOfImage);
                *out = info;
                return true;
            }
        }
        Out("[内存] 低内存快照内没有 ntoskrnl，开始安全范围扫描");
        return false;
    }


    bool ScanNtoskrnlSafe(PeInfo* out)
    {
        const uint32_t kBlk = 0x10000;
        std::vector<uint8_t> blk(kBlk);
        uint32_t mzSeen = 0;

        const uint64_t seg[][2] = {
            {lm.base + lm.buf.size(), std::min<uint64_t>(ramTop, 0xC0000000ull)},
            {0x100000000ull, std::min<uint64_t>(ramTop, 0x400000000ull)},
        };
        for (const auto& s : seg)
        {
            if (s[0] >= s[1]) continue;
            Out("[内存] 扫描 0x%llX-0x%llX 找 ntoskrnl...", s[0], s[1]);
            for (uint64_t pa = s[0]; pa + kBlk <= s[1]; pa += kBlk)
            {
                if (!PaInRam(pa, kBlk)) continue;
                if (!dev.ReadPaBulk(pa, blk.data(), kBlk))
                {
                    for (uint32_t i = 0; i < kBlk / 0x1000; ++i)
                    {
                        uint64_t pp = pa + (uint64_t)i * 0x1000;
                        if (!PaInRam(pp)) continue;
                        dev.ReadPa(pp, blk.data() + (size_t)i * 0x1000, 0x1000);
                    }
                }
                for (uint32_t i = 0; i < kBlk / 0x1000; ++i)
                {
                    const uint8_t* h = blk.data() + (size_t)i * 0x1000;
                    if (h[0] != 'M' || h[1] != 'Z') continue;
                    ++mzSeen;
                    uint64_t candPa = pa + (uint64_t)i * 0x1000;
                    PeInfo info;
                    if (!ProbeNtoskrnl(candPa, &info)) continue;
                    Out("[内存] ntoskrnl 物理基址=0x%llX SizeOfImage=0x%X（扫描命中，MZ 候选 %u）",
                        info.pa, info.sizeOfImage, mzSeen);
                    *out = info;
                    return true;
                }
            }
        }
        Out("[内存] 安全范围扫描未找到 ntoskrnl（MZ 候选 %u 个）", mzSeen);
        return false;
    }


    bool FindNtoskrnlViaPml4(uint64_t dtb, PeInfo* out, uint64_t* baseVaOut)
    {
        const uint16_t kMz = 0x5A4D;

        uint64_t pml4[512];
        if (!PaInRam(dtb)) return false;
        if (!dev.ReadPa(dtb, pml4, (uint32_t)sizeof(pml4))) return false;
        if (!(pml4[KR_PML4] & 1))
        {
            if (g_hidDebug) Out("[诊断] dtb=0x%llX 的 PML4[496] 未 present", dtb);
            return false;
        }

        uint32_t bigPages = 0, smallPages = 0, ptScanned = 0, big1gPages = 0;
        uint32_t ptBudget = 48;

        for (int i = KR_PML4; i >= KR_PML4; --i)
        {
            uint64_t e4 = pml4[i];
            if (!(e4 & 1)) continue;
            uint64_t pdptPa = e4 & PA_MASK;
            if (!PaInRam(pdptPa)) continue;
            uint64_t pdpt[512];
            if (!dev.ReadPa(pdptPa, pdpt, (uint32_t)sizeof(pdpt))) continue;

            for (int j = 0; j < 512; ++j)
            {
                uint64_t e3 = pdpt[j];
                if (!(e3 & 1)) continue;


                if (e3 & PS_BIT)
                {
                    uint64_t base = e3 & 0x000FFFFFC0000000ull;
                    if (!PaInRam(base)) continue;
                    ++big1gPages;
                    for (uint32_t off = 0; off < 0x40000000; off += 0x200000)
                    {
                        uint64_t pa = base + off;
                        if (!PaInRam(pa)) break;
                        uint8_t h[2] = {};
                        if (!dev.ReadPa(pa, h, 2)) continue;
                        if (h[0] != 'M' || h[1] != 'Z') continue;
                        PeInfo info;
                        if (!ProbeNtoskrnl(pa, &info)) continue;
                        uint64_t va = ((uint64_t)i << 39) | ((uint64_t)j << 30) | off;
                        if (i >= 256) va |= 0xFFFF000000000000ull;
                        Out("[内存] 经页表(1GB大页+0x%X)找到 ntoskrnl: VA=0x%llX PA=0x%llX SizeOfImage=0x%X",
                            off, va, info.pa, info.sizeOfImage);
                        *out = info;
                        if (baseVaOut) *baseVaOut = va;
                        return true;
                    }
                    continue;
                }


                uint64_t pdPa = e3 & PA_MASK;
                if (!PaInRam(pdPa)) continue;
                uint64_t pd[512];
                if (!dev.ReadPa(pdPa, pd, (uint32_t)sizeof(pd))) continue;

                for (int k = 0; k < 512; ++k)
                {
                    uint64_t e2 = pd[k];
                    if (!(e2 & 1)) continue;

                    if (e2 & PS_BIT)
                    {
                        ++bigPages;
                        uint64_t pa = e2 & 0x000FFFFFFFE00000ull;
                        if (!PaInRam(pa)) continue;


                        uint8_t h[2] = {};
                        if (!dev.ReadPa(pa, h, 2)) continue;
                        if (h[0] != 'M' || h[1] != 'Z') continue;
                        PeInfo info;
                        if (!ProbeNtoskrnl(pa, &info)) continue;

                        uint64_t va = ((uint64_t)i << 39) | ((uint64_t)j << 30) | ((uint64_t)k << 21);
                        if (i >= 256) va |= 0xFFFF000000000000ull;
                        Out("[内存] 经页表(2MB大页)找到 ntoskrnl: VA=0x%llX PA=0x%llX SizeOfImage=0x%X",
                            va, info.pa, info.sizeOfImage);
                        *out = info;
                        if (baseVaOut) *baseVaOut = va;
                        return true;
                    }


                    if (ptBudget == 0) continue;
                    --ptBudget;
                    ++smallPages;
                    uint64_t ptPa = e2 & PA_MASK;
                    if (!PaInRam(ptPa)) continue;
                    uint64_t pt[512];
                    if (!dev.ReadPa(ptPa, pt, (uint32_t)sizeof(pt))) continue;
                    ++ptScanned;
                    for (int l = 0; l < 512; ++l)
                    {
                        uint64_t e1 = pt[l];
                        if (!(e1 & 1)) continue;
                        uint64_t pa = e1 & PA_MASK;
                        if (!PaInRam(pa)) continue;
                        uint16_t mz = 0;
                        if (!dev.ReadPa(pa, &mz, 2)) continue;
                        if (mz != kMz) continue;
                        PeInfo info;
                        if (!ProbeNtoskrnl(pa, &info)) continue;

                        uint64_t va = ((uint64_t)i << 39) | ((uint64_t)j << 30)
                            | ((uint64_t)k << 21) | ((uint64_t)l << 12);
                        if (i >= 256) va |= 0xFFFF000000000000ull;
                        Out("[内存] 经页表(4KB页)找到 ntoskrnl: VA=0x%llX PA=0x%llX SizeOfImage=0x%X",
                            va, info.pa, info.sizeOfImage);
                        *out = info;
                        if (baseVaOut) *baseVaOut = va;
                        return true;
                    }
                }
            }
        }
        dbg1g = big1gPages;
        dbg2m = bigPages;
        dbg4k = ptScanned;
        if (g_hidDebug)
            Out("[诊断] dtb=0x%llX 未命中：1GB大页=%u 2MB大页=%u 4KB候选=%u(读PT %u)",
                dtb, big1gPages, bigPages, smallPages, ptScanned);
        return false;
    }

    bool ExportRva(const PeInfo& img, const char* want, uint32_t* rva)
    {
        uint8_t ed[40] = {};
        if (!PaInRam(img.pa + img.exportRva, 40)) return false;
        if (!dev.ReadPa(img.pa + img.exportRva, ed, 40)) return false;
        uint32_t n = 0, af = 0, an = 0, ao = 0;
        memcpy(&n, ed + 24, 4);
        memcpy(&af, ed + 28, 4);
        memcpy(&an, ed + 32, 4);
        memcpy(&ao, ed + 36, 4);
        if (!n || n > 8000) return false;

        if (af >= img.sizeOfImage || an >= img.sizeOfImage || ao >= img.sizeOfImage) return false;
        for (uint32_t i = 0; i < n; ++i)
        {
            uint32_t nrva = 0;
            uint64_t adr = img.pa + an + i * 4ull;
            if (!PaInRam(adr, 4)) return false;
            if (!dev.ReadPa(adr, &nrva, 4)) continue;
            if (!nrva || nrva >= img.sizeOfImage) continue;
            char nm[64] = {};
            if (!PaInRam(img.pa + nrva, 63)) continue;
            if (!dev.ReadPa(img.pa + nrva, nm, 63)) continue;
            if (strcmp(nm, want) != 0) continue;
            uint16_t ord = 0;
            uint32_t frva = 0;
            uint64_t aor = img.pa + ao + i * 2ull;
            if (!PaInRam(aor, 2)) continue;
            if (!dev.ReadPa(aor, &ord, 2)) continue;
            uint64_t afr = img.pa + af + (uint64_t)ord * 4;
            if (!PaInRam(afr, 4)) continue;
            if (!dev.ReadPa(afr, &frva, 4)) continue;
            if (!frva || frva >= img.sizeOfImage) continue;
            *rva = frva;
            return true;
        }
        return false;
    }
};


static bool LooksLikePml4(const uint8_t* page, uint64_t ramTop)
{
    const uint64_t* e = (const uint64_t*)page;
    uint64_t v = e[KR_PML4];
    if (!(v & 1)) return false;
    uint64_t pa = v & PA_MASK;
    if (!pa || pa + 0x1000 > ramTop) return false;
    if (!PaInRam(pa)) return false;
    return true;
}


static bool LooksLikePml4Strict(const uint8_t* page, uint64_t ramTop)
{
    const uint64_t* e = (const uint64_t*)page;
    uint32_t kern = 0;
    for (uint32_t i = 256; i < 512; ++i)
    {
        uint64_t v = e[i];
        if (!(v & 1)) continue;
        uint64_t pa = v & PA_MASK;
        if (!pa || pa + 0x1000 > ramTop) continue;
        if (!PaInRam(pa)) continue;
        ++kern;
    }
    if (!(e[KR_PML4] & 1)) return false;
    return kern >= 8;
}


static bool ValidatePml4LikeNz(Device& dev, uint64_t dtb)
{
    uint64_t page[512];
    if (!PaInRam(dtb)) return false;
    if (!dev.ReadPa(dtb, page, (uint32_t)sizeof(page))) return false;

    uint32_t userEmpty = 0, kernEmpty = 0;
    bool selfRef = false;
    for (int i = 0; i < 256; ++i) if (!(page[i] & 1)) ++userEmpty;
    for (int i = 256; i < 512; ++i)
    {
        uint64_t v = page[i];
        if (!(v & 1))
        {
            ++kernEmpty;
            continue;
        }

        if ((v & 0xFFFFF000ull) == (dtb & 0xFFFFF000ull) && (v & 0x83) == 0x03)
            selfRef = true;
    }
    if (userEmpty <= 0x40) return false;
    if (kernEmpty <= 0x40) return false;
    if (!(page[KR_PML4] & 1)) return false;
    if (!selfRef) return false;
    return true;
}

static bool FindSystemDtbViaLowStub(Device& dev, uint64_t* dtbOut)
{
    const uint64_t lo = 0x1000, hi = 0xA0000;
    if (!PaInRam(lo, hi - lo)) return false;
    std::vector<uint8_t> buf((size_t)(hi - lo));
    if (!dev.ReadPa(lo, buf.data(), (uint32_t)buf.size())) return false;

    for (uint64_t addr = lo; addr + 0xA8 <= hi; addr += 0x1000)
    {
        const uint8_t* p = buf.data() + (addr - lo);
        uint32_t v0 = 0;
        memcpy(&v0, p, 4);
        if ((v0 & 0xFFFF00FFu) != 0x600E9u) continue;

        uint64_t dtb = 0;
        memcpy(&dtb, p + 0xA0, 8);
        if (!dtb || (dtb & 0xFFF)) continue;

        if (!ValidatePml4LikeNz(dev, dtb)) continue;
        Out("[内存] low stub @0x%llX 反推 CR3=0x%llX，PML4 校验通过", addr, dtb);
        *dtbOut = dtb;
        return true;
    }
    return false;
}

static bool PaToVaAt(Device& dev, const LowMem& lm, const uint64_t* pml4, int ii,
                     uint64_t target, uint64_t* outVa, uint32_t* budget)
{
    uint64_t p4 = pml4[ii];
    if (!(p4 & 1)) return false;
    uint64_t baseVa = (uint64_t)ii << 39;


    uint64_t pdptPa = p4 & PA_MASK;
    if (!PaInRam(pdptPa)) return false;
    uint64_t pdpt[512];
    if (!dev.ReadPa(pdptPa, pdpt, 0x1000)) return false;

    for (uint32_t j = 0; j < 512; ++j)
    {
        uint64_t p3 = pdpt[j];
        if (!(p3 & 1)) continue;
        if (p3 & PS_BIT)
        {
            uint64_t base = p3 & 0x000FFFFFC0000000ull;
            if (target >= base && target < base + 0x40000000ull)
            {
                *outVa = baseVa | ((uint64_t)j << 30) | ((target - base) & 0x3FFFFFFFull);
                return true;
            }
            continue;
        }


        uint64_t pdPa = p3 & PA_MASK;
        if (!PaInRam(pdPa)) continue;
        uint64_t pd[512];
        if (!dev.ReadPa(pdPa, pd, 0x1000)) continue;

        for (uint32_t k = 0; k < 512; ++k)
        {
            uint64_t p2 = pd[k];
            if (!(p2 & 1)) continue;
            if (p2 & PS_BIT)
            {
                uint64_t base = p2 & 0x000FFFFFFFE00000ull;
                if (target >= base && target < base + 0x200000ull)
                {
                    *outVa = baseVa | ((uint64_t)j << 30) | ((uint64_t)k << 21) | ((target - base) & 0x1FFFFFull);
                    return true;
                }
                continue;
            }
            if (*budget == 0) continue;
            --(*budget);
            uint64_t ptPa = p2 & PA_MASK;
            if (!PaInRam(ptPa)) continue;
            uint64_t pt[512];
            if (!dev.ReadPa(ptPa, pt, 0x1000)) continue;
            for (uint32_t l = 0; l < 512; ++l)
            {
                uint64_t p1 = pt[l];
                if (!(p1 & 1)) continue;
                if ((p1 & PA_MASK) == (target & PA_MASK))
                {
                    *outVa = baseVa | ((uint64_t)j << 30) | ((uint64_t)k << 21) | ((uint64_t)l << 12) | (target &
                        0xFFFull);
                    return true;
                }
            }
        }
    }
    return false;
}

static bool PaToKernelVa(Device& dev, const LowMem& lm, uint64_t pml4Pa, uint64_t target, uint64_t* outVa)
{
    uint64_t pml4[512];
    if (!PaInRam(pml4Pa)) return false;
    if (!dev.ReadPa(pml4Pa, pml4, 0x1000)) return false;

    uint32_t budget = 64;
    if (PaToVaAt(dev, lm, pml4, KR_PML4, target, outVa, &budget)) return true;
    for (int i = 511; i >= 256; --i)
    {
        if (i == KR_PML4) continue;
        if (PaToVaAt(dev, lm, pml4, i, target, outVa, &budget)) return true;
        if (!budget) break;
    }
    return false;
}


class Kern
{
public:
    Device& dev;
    const LowMem* lm;
    uint64_t dtb = 0;


    uint64_t ramTop = 0;

    Kern(Device& d, const LowMem* l) : dev(d), lm(l)
    {
    }


    void ResetCache() const { cache_.clear(); }

    bool PaSafe(uint64_t pa, uint64_t size = 0x1000) const
    {
        if (!ramTop) return true;
        return PaInRam(pa, size);
    }

    bool Table(uint64_t pa, uint64_t* t) const
    {
        uint64_t page = pa & PAGE_MSK;
        if (!PaSafe(page)) return false;
        auto it = cache_.find(page);
        if (it == cache_.end())
        {
            if (cache_.size() > 256) cache_.clear();
            std::vector<uint8_t> b(0x1000);

            if (!dev.ReadPa(page, b.data(), 0x1000)) return false;
            it = cache_.emplace(page, std::move(b)).first;
        }
        memcpy(t, it->second.data(), 0x1000);
        return true;
    }

    bool VaToPa(uint64_t va, uint64_t* pa) const
    {
        if (!dtb) return false;
        uint64_t t[512], cur = dtb & PAGE_MSK;
        if (!PaSafe(cur))
        {
            if (g_vtDiag > 0)
            {
                --g_vtDiag;
                Out("[诊断]   VA=0x%llX PML4 页 0x%llX 被 PaSafe 拒绝(ramTop=0x%llX)", va, cur, ramTop);
            }
            return false;
        }
        const uint32_t idx[4] = {
            (uint32_t)((va >> 39) & 0x1FF), (uint32_t)((va >> 30) & 0x1FF),
            (uint32_t)((va >> 21) & 0x1FF), (uint32_t)((va >> 12) & 0x1FF)
        };
        for (int lv = 0; lv < 4; ++lv)
        {
            if (!Table(cur, t))
            {
                if (g_vtDiag > 0)
                {
                    --g_vtDiag;
                    Out("[诊断]   VA=0x%llX 第%d级读页表失败 PA=0x%llX", va, lv, cur);
                }
                return false;
            }
            uint64_t e = t[idx[lv]];
            if (!(e & 1))
            {
                if (g_vtDiag > 0)
                {
                    --g_vtDiag;
                    Out("[诊断]   VA=0x%llX 第%d级未 present (idx=%u PA=0x%llX)", va, lv, idx[lv], cur);
                }
                return false;
            }


            if (lv == 3)
            {
                uint64_t out = (e & PA_MASK) + (va & 0xFFF);
                if (ramTop && (out & PAGE_MSK) + 0x1000 > ramTop)
                {
                    if (g_vtDiag > 0)
                    {
                        --g_vtDiag;
                        Out("[诊断]   VA=0x%llX 叶子页 0x%llX 越界", va, out);
                    }
                    return false;
                }
                *pa = out;
                return true;
            }
            if (e & PS_BIT)
            {
                uint64_t base = (lv == 1) ? (e & 0x000FFFFFC0000000ull) : (e & 0x000FFFFFFFE00000ull);
                uint32_t sh = (lv == 1) ? 30 : 21;
                uint64_t out = base + (va & ((1ull << sh) - 1));
                if (ramTop && (out & PAGE_MSK) + 0x1000 > ramTop) return false;
                *pa = out;
                return true;
            }
            cur = e & PA_MASK;
            if (!PaSafe(cur))
            {
                if (g_vtDiag > 0)
                {
                    --g_vtDiag;
                    Out("[诊断]   VA=0x%llX 第%d级下一层 0x%llX 被拒绝", va, lv, cur);
                }
                return false;
            }
        }
        return false;
    }

    bool Read(uint64_t va, void* dst, uint32_t n) const
    {
        if (readImpl(va, dst, n)) return true;

        cache_.clear();
        return readImpl(va, dst, n);
    }

    bool U64(uint64_t va, uint64_t* v) const { return Read(va, v, 8); }
    bool U32(uint64_t va, uint32_t* v) const { return Read(va, v, 4); }

private:
    bool readImpl(uint64_t va, void* dst, uint32_t n) const
    {
        uint8_t* d = (uint8_t*)dst;
        while (n)
        {
            uint64_t pa = 0;
            if (!VaToPa(va, &pa)) return false;
            uint32_t off = (uint32_t)(pa & 0xFFF);
            uint32_t c = (uint32_t)std::min<uint64_t>(n, 0x1000ull - off);
            if (!dev.ReadPa(pa, d, c)) return false;
            d += c;
            va += c;
            n -= c;
        }
        return true;
    }

    mutable std::unordered_map<uint64_t, std::vector<uint8_t>> cache_;
};


struct EprocLayout
{
    uint64_t links = 0, pid = 0, name = 0, token = 0;
};

struct KernelCtx
{
    uint64_t dtb = 0;
    uint64_t baseVa = 0;
    uint64_t sysProcVa = 0;
    EprocLayout layout;
    PeInfo img;
};


static bool DiscoverLayout(const Kern& km, uint64_t sysProcVa, EprocLayout* out)
{
    std::vector<uint8_t> b(0x800);
    if (!km.Read(sysProcVa, b.data(), (uint32_t)b.size())) return false;
    for (uint64_t L = 0x100; L + 16 <= b.size(); L += 8)
    {
        uint64_t f = 0, bl = 0;
        memcpy(&f, b.data() + L, 8);
        memcpy(&bl, b.data() + L + 8, 8);
        if (!IsKernelVa(f) || !IsKernelVa(bl)) continue;

        uint64_t nb = 0, pf = 0;
        if (!km.U64(f + 8, &nb) || nb != sysProcVa + L) continue;
        if (!km.U64(bl, &pf) || pf != sysProcVa + L) continue;

        uint64_t pidOff = 0;
        for (uint64_t p = (L >= 0x40 ? L - 0x40 : 0); p + 8 <= L; p += 8)
        {
            uint64_t v = 0;
            memcpy(&v, b.data() + p, 8);
            if (v == 4)
            {
                pidOff = p;
                break;
            }
        }
        if (!pidOff) continue;

        uint64_t nameOff = 0;
        for (size_t i = (size_t)L + 16; i + 8 <= b.size(); ++i)
            if (!memcmp(b.data() + i, "System", 6) && b[i + 6] == 0 && b[i - 1] == 0)
            {
                nameOff = i;
                break;
            }
        if (!nameOff) continue;

        out->links = L;
        out->pid = pidOff;
        out->name = nameOff;
        return true;
    }
    return false;
}

static bool InitKernel(PhysMem& pm, Device& dev, KernelCtx* kc)
{
    if (!pm.Snapshot()) return false;


    if (g_dumpDtb)
    {
        std::vector<uint64_t> pml4(512);
        if (!PaInRam(g_dumpDtb) || !dev.ReadPa(g_dumpDtb, pml4.data(), 4096))
        {
            Out("[dump] 读取 PML4 @0x%llX 失败", g_dumpDtb);
        }
        else
        {
            Out("[dump] ===== PML4 @0x%llX（内核半区 present 项）=====", g_dumpDtb);
            uint32_t n = 0;
            for (int i = 256; i < 512; ++i)
            {
                if (!(pml4[i] & 1)) continue;
                ++n;
                if (i >= 496 || i <= 264)
                    Out("[dump]   PML4[%3d] = 0x%016llX  ->  PA=0x%llX", i, pml4[i], pml4[i] & PA_MASK);
            }
            Out("[dump] 内核半区 present 项共 %u 个", n);

            for (int idx : {260, 496})
            {
                uint64_t pe = pml4[idx];
                if (!(pe & 1))
                {
                    Out("[dump] PML4[%d] 未 present", idx);
                    continue;
                }
                uint64_t ppa = pe & PA_MASK;
                Out("[dump] ===== PML4[%d] -> PDPT @0x%llX =====", idx, ppa);
                if (!PaInRam(ppa))
                {
                    Out("[dump]   PDPT 地址越界");
                    continue;
                }
                std::vector<uint64_t> pdpt(512);
                if (!dev.ReadPa(ppa, pdpt.data(), 4096))
                {
                    Out("[dump]   PDPT 读取失败");
                    continue;
                }
                uint32_t pn = 0;
                for (int j = 0; j < 512; ++j)
                {
                    if (!(pdpt[j] & 1)) continue;
                    ++pn;
                    if (j == 55 || j <= 4 || (idx == 496 && j == 17))
                        Out("[dump]   PDPT[%3d] = 0x%016llX  ->  PA=0x%llX%s",
                            j, pdpt[j], pdpt[j] & PA_MASK, (pdpt[j] & PS_BIT) ? " (1GB大页)" : "");
                }
                Out("[dump]   PDPT present 项共 %u 个；PDPT[55] = 0x%016llX", pn, pdpt[55]);
            }
            Out("[dump] ================= 结束 =================");
        }
    }

    std::vector<uint64_t> cands;
    uint64_t stubDtb = 0;


    if (g_forceDtb)
    {
        cands.push_back(g_forceDtb);
        Out("[内存] 命令行指定 DTB=0x%llX（跳过自动搜索）", g_forceDtb);
    }


    PeInfo img;
    uint32_t rva = 0;
    uint64_t sysProcPhys = 0;
    bool haveImg = pm.FindNtoskrnl(&img);
    if (!haveImg) haveImg = pm.ScanNtoskrnlSafe(&img);
    if (haveImg)
    {
        if (!pm.ExportRva(img, "PsInitialSystemProcess", &rva))
        {
            Out("[内存] 导出表里没有 PsInitialSystemProcess");
            return false;
        }
        Out("[内存] PsInitialSystemProcess RVA=0x%X", rva);


        uint64_t v = 0;
        if (PaInRam(img.pa + rva, 8) && dev.ReadPa(img.pa + rva, &v, 8) && IsKernelVa(v))
        {
            sysProcPhys = v;
            Out("[内存] 物理直读 PsInitialSystemProcess = 0x%llX", v);
        }
        else
        {
            Out("[内存] 物理直读失败");
        }
    }


    if (FindSystemDtbViaLowStub(dev, &stubDtb))
    {
        cands.push_back(stubDtb);
    }

    if (sysProcPhys)
    {
        const uint32_t sysIdx = (uint32_t)((sysProcPhys >> 39) & 0x1FF);
        uint32_t present = 0;
        for (uint64_t pa = pm.lm.base; pa + 0x1000 <= pm.lm.base + pm.lm.buf.size(); pa += 0x1000)
        {
            const uint8_t* p = pm.lm.At(pa);
            if (!p) continue;
            uint64_t e = 0;
            memcpy(&e, p + (size_t)sysIdx * 8, 8);
            if (!(e & 1)) continue;
            uint64_t hpa = e & PA_MASK;
            if (!hpa || hpa + 0x1000 > pm.ramTop) continue;
            ++present;
            if (std::find(cands.begin(), cands.end(), pa) == cands.end()) cands.push_back(pa);
        }
        Out("[内存] sysProc PML4[%u] present 的候选 = %u 个", sysIdx, present);


        uint32_t loose = 0;
        for (uint64_t pa = pm.lm.base; pa + 0x1000 <= pm.lm.base + pm.lm.buf.size(); pa += 0x1000)
        {
            if (pa >= 0xA0000 && pa < 0x100000) continue;
            const uint8_t* p = pm.lm.At(pa);
            if (!p) continue;
            if (!LooksLikePml4(p, pm.ramTop)) continue;
            ++loose;
            if (std::find(cands.begin(), cands.end(), pa) == cands.end()) cands.push_back(pa);
        }
        Out("[内存] 加上结构合格页，候选合计 %zu 个（结构合格 %u）", cands.size(), loose);


        Out("[内存] 遍历低内存每页实测能否翻译 sysProc...");
        uint32_t hit = 0;
        for (uint64_t pa = pm.lm.base; pa + 0x1000 <= pm.lm.base + pm.lm.buf.size(); pa += 0x1000)
        {
            if (!PaInRam(pa)) continue;
            Kern k(dev, &pm.lm);
            k.ramTop = pm.ramTop;
            k.dtb = pa;
            uint64_t outpa = 0;
            if (!k.VaToPa(sysProcPhys, &outpa)) continue;
            ++hit;
            if (std::find(cands.begin(), cands.end(), pa) == cands.end()) cands.push_back(pa);
            if (g_hidDebug)
                Out("[诊断] dtb=0x%llX 能翻译 sysProc → PA=0x%llX", pa, outpa);
        }
        Out("[内存] 实测可翻译 sysProc 的 DTB = %u 个", hit);
    }
    else if (cands.empty())
    {
        Out("[内存] 没有 sysProc 可用，按 0x40C360 判据扫描（含自映射）");
        uint32_t strict = 0;
        for (uint64_t pa = pm.lm.base; pa + 0x1000 <= pm.lm.base + pm.lm.buf.size(); pa += 0x1000)
        {
            if (pa >= 0xA0000 && pa < 0x100000) continue;
            if (!PaInRam(pa)) continue;
            if (!ValidatePml4LikeNz(dev, pa)) continue;
            ++strict;
            cands.push_back(pa);
        }
        Out("[内存] 严格判据候选 = %u 个", strict);
        if (cands.empty())
        {
            Out("[内存] 严格判据无候选，退回宽松结构扫描");
            for (uint64_t pa = pm.lm.base; pa + 0x1000 <= pm.lm.base + pm.lm.buf.size(); pa += 0x1000)
            {
                if (pa >= 0xA0000 && pa < 0x100000) continue;
                const uint8_t* p = pm.lm.At(pa);
                if (p && LooksLikePml4(p, pm.ramTop)) cands.push_back(pa);
            }
            Out("[内存] 宽松候选 = %zu 个", cands.size());
        }
        if (cands.empty())
        {
            Out("[内存] 结构判据全空，暴力把低内存每页都当候选");
            for (uint64_t pa = pm.lm.base; pa + 0x1000 <= pm.lm.base + pm.lm.buf.size(); pa += 0x1000)
            {
                if (!PaInRam(pa)) continue;
                cands.push_back(pa);
            }
            Out("[内存] 暴力候选 = %zu 个", cands.size());
        }
    }

    if (cands.empty())
    {
        Out("[内存] 找不到可用的 System DTB");
        return false;
    }


    for (uint64_t dtb : cands)
    {
        PeInfo use = img;
        uint64_t baseVa = 0;
        uint64_t sysProc = 0;


        if (g_hidDebug && sysProcPhys)
        {
            g_vtDiag = 6;
            Kern kd(dev, &pm.lm);
            kd.ramTop = pm.ramTop;
            kd.dtb = dtb;
            uint64_t pa = 0;
            bool tok = kd.VaToPa(sysProcPhys, &pa);
            uint8_t hdr[16] = {};
            bool rok = tok && kd.Read(sysProcPhys, hdr, sizeof(hdr));
            Out("[诊断] dtb=0x%llX sysProc 翻译=%s PA=0x%llX 头16=%s",
                dtb, tok ? "成功" : "失败", pa,
                rok ? "ok" : "fail");
            if (rok)
            {
                Out("[诊断]   %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                    hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
                    hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15]);
            }
        }


        if (!pm.FindNtoskrnlViaPml4(dtb, &use, &baseVa))
        {
            if (g_hidDebug)
                Out("[诊断] dtb=0x%llX 页表未找到 ntoskrnl（1GB大页=%u 2MB大页=%u 4KB候选=%u）",
                    dtb, pm.dbg1g, pm.dbg2m, pm.dbg4k);
            continue;
        }
        if (!pm.ExportRva(use, "PsInitialSystemProcess", &rva)) continue;


        if (!g_autoDumped && sysProcPhys)
        {
            g_autoDumped = 1;
            Out("[dump] ==== 完整翻译 sysProc=0x%llX (dtb=0x%llX) ====", sysProcPhys, dtb);
            uint64_t va = sysProcPhys, cur = dtb;
            const char* lvName[4] = {"PML4", "PDPT", "PD", "PT"};
            for (int lv = 0; lv < 4; ++lv)
            {
                uint32_t idx = (uint32_t)((va >> (39 - lv * 9)) & 0x1FF);
                if (!PaInRam(cur))
                {
                    Out("[dump] %s: 页 0x%llX 被 PaInRam 拒绝", lvName[lv], cur);
                    break;
                }
                std::vector<uint64_t> pg(512);
                if (!dev.ReadPa(cur, pg.data(), 4096))
                {
                    Out("[dump] %s: 读 0x%llX 失败", lvName[lv], cur);
                    break;
                }
                uint64_t e = pg[idx];
                Out("[dump] %s @0x%llX [%u] = 0x%016llX  present=%d PS=%d PA=0x%llX",
                    lvName[lv], cur, idx, e, (int)(e & 1), (int)((e >> 7) & 1), e & PA_MASK);
                if (!(e & 1))
                {
                    Out("[dump] >>> 卡在 %s[%u] 未 present", lvName[lv], idx);
                    break;
                }
                if (lv == 3)
                {
                    uint64_t out = (e & PA_MASK) + (va & 0xFFF);
                    Out("[dump] >>> 翻译成功 PA=0x%llX", out);
                    break;
                }
                if (e & PS_BIT)
                {
                    uint64_t base = (lv == 1) ? (e & 0x000FFFFFC0000000ull) : (e & 0x000FFFFFFFE00000ull);
                    uint32_t sh = (lv == 1) ? 30 : 21;
                    Out("[dump] >>> %s 大页，PA=0x%llX", lvName[lv], base + (va & ((1ull << sh) - 1)));
                    break;
                }
                cur = e & PA_MASK;
            }
            Out("[dump] ========== 结束 ==========");
        }
        Out("[内存] PsInitialSystemProcess RVA=0x%X", rva);
        {
            Kern k0(dev, &pm.lm);
            k0.ramTop = pm.ramTop;
            k0.dtb = dtb;
            if (!k0.U64(baseVa + rva, &sysProc) || !IsKernelVa(sysProc)) continue;
        }

        Kern km(dev, &pm.lm);
        km.ramTop = pm.ramTop;
        km.dtb = dtb;
        EprocLayout L;
        if (!DiscoverLayout(km, sysProc, &L))
        {
            if (g_hidDebug)
                Out("[诊断] dtb=0x%llX sysProc=0x%llX → EPROCESS 布局验证失败", dtb, sysProc);
            continue;
        }

        kc->img = use;
        kc->dtb = dtb;
        kc->baseVa = baseVa;
        kc->sysProcVa = sysProc;
        kc->layout = L;
        Out("[内存] DTB=0x%llX 内核基址=0x%llX System=0x%llX", dtb, baseVa, sysProc);
        Out("[内存] EPROCESS: links=0x%llX pid=0x%llX name=0x%llX",
            L.links, L.pid, L.name);
        return true;
    }
    Out("[内存] 没有候选能通过验证");
    return false;
}


static const uint64_t kDirTableBaseOff = 0x28;

static bool FindEprocess(const Kern& km, const KernelCtx& kc, uint32_t pid,
                         uint64_t* eproc, uint64_t* dtbOut, char* nameOut, size_t n)
{
    uint64_t node = kc.sysProcVa;
    std::vector<uint8_t> b(0x800);
    for (int i = 0; i < 100000; ++i)
    {
        if (!km.Read(node, b.data(), (uint32_t)b.size())) return false;
        uint64_t cur = 0;
        memcpy(&cur, b.data() + kc.layout.pid, 8);
        if (cur == pid)
        {
            if (nameOut)
            {
                memcpy(nameOut, b.data() + kc.layout.name, n - 1);
                nameOut[n - 1] = 0;
            }
            *eproc = node;
            if (dtbOut)
            {
                uint64_t dtb = 0;
                memcpy(&dtb, b.data() + kDirTableBaseOff, 8);

                if (!dtb) memcpy(&dtb, b.data() + kDirTableBaseOff + 8, 8);
                *dtbOut = dtb & PAGE_MSK;
            }
            return true;
        }
        uint64_t f = 0;
        memcpy(&f, b.data() + kc.layout.links, 8);
        if (!IsKernelVa(f)) return false;
        uint64_t next = f - kc.layout.links;
        if (!IsKernelVa(next) || next == kc.sysProcVa) return false;
        node = next;
    }
    return false;
}


struct ModInfo
{
    uint64_t base = 0, peb = 0, dtb = 0;
    uint32_t sizeOfImage = 0, timestamp = 0, e_lfanew = 0;
    uint32_t magic = 0;
    bool is64 = false;
};


static bool ProbeImage(const Kern& kmUser, uint64_t addr, ModInfo* mi)
{
    if (addr < 0x10000 || addr > 0x00007FFFFFFFFFFFull) return false;
    if (addr & 0xFFFu) return false;


    uint8_t hdr[0x1000] = {};
    if (!kmUser.Read(addr, hdr, sizeof(hdr))) return false;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return false;
    uint32_t lf = 0;
    memcpy(&lf, hdr + 0x3C, 4);

    if (lf < 0x40 || lf > 0xE00u) return false;
    if (lf + 0x100 > sizeof(hdr)) return false;
    if (memcmp(hdr + lf, "PE\0\0", 4) != 0) return false;

    uint16_t magic = 0;
    memcpy(&magic, hdr + lf + 24, 2);
    if (magic != 0x10B && magic != 0x20B) return false;
    uint32_t soi = 0;
    memcpy(&soi, hdr + lf + 24 + 56, 4);
    if (soi < 0x1000 || soi > 0x40000000u) return false;

    mi->base = addr;
    mi->e_lfanew = lf;
    mi->magic = magic;
    mi->is64 = (magic == 0x20B);
    mi->sizeOfImage = soi;
    memcpy(&mi->timestamp, hdr + lf + 8, 4);
    return true;
}


static bool FindViaPeb(const Kern& kmUser, const std::vector<uint8_t>& b, ModInfo* mi, uint64_t* pebOffOut)
{
    for (uint64_t off = 0x100; off + 8 <= b.size(); off += 8)
    {
        uint64_t peb = 0;
        memcpy(&peb, b.data() + off, 8);
        if (peb < 0x10000 || peb > 0x00007FFFFFFFFFFFull) continue;
        if (peb & 0xFu) continue;

        uint64_t imgBase = 0;
        if (!kmUser.U64(peb + 0x10, &imgBase)) continue;
        if (!ProbeImage(kmUser, imgBase, mi)) continue;

        mi->peb = peb;
        if (pebOffOut) *pebOffOut = off;
        return true;
    }
    return false;
}

static bool DiscoverModule(const Kern& kmKernel, const Kern& kmUser, uint64_t eproc, ModInfo* mi)
{
    std::vector<uint8_t> b(0x800);
    if (!kmKernel.Read(eproc, b.data(), (uint32_t)b.size())) return false;


    Out("[附加] 目标 DTB=0x%llX kmUser.dtb=0x%llX ramTop=0x%llX",
        (unsigned long long)kmUser.dtb, (unsigned long long)kmUser.dtb,
        (unsigned long long)kmUser.ramTop);
    g_vtDiag = 0;


    {
        static const uint64_t kCandOffs[] = {0x520, 0x550, 0x560, 0x4F0, 0x3F8, 0x3E8, 0x270};
        for (uint64_t off : kCandOffs)
        {
            uint64_t v = 0;
            if (!kmKernel.U64(eproc + off, &v)) continue;
            Out("[附加] 试 EPROCESS+0x%llX → 0x%llX", off, v);
            if (v < 0x10000 || v > 0x00007FFFFFFFFFFFull)
            {
                Out("[附加]   非用户态，跳过");
                continue;
            }


            if (ProbeImage(kmUser, v, mi))
            {
                uint64_t peb = 0;
                if (kmKernel.U64(eproc + 0x550, &peb)
                    && peb >= 0x10000 && peb <= 0x00007FFFFFFFFFFFull)
                    mi->peb = peb;
                Out("[附加] (a) 直接是映像基址 @EPROCESS+0x%llX = 0x%llX (%s, SizeOfImage=0x%X) PEB=0x%llX",
                    off, mi->base, mi->is64 ? "PE32+" : "PE32", mi->sizeOfImage, mi->peb);
                return true;
            }
            {
                uint64_t tpa = 0;
                bool tok = kmUser.VaToPa(v, &tpa);
                uint8_t h2[4] = {};
                bool rok = tok && kmUser.Read(v, h2, 4);
                Out("[附加]   (a) VaToPa=%s PA=0x%llX Read=%s 头=%02X %02X",
                    tok ? "ok" : "fail", (unsigned long long)tpa, rok ? "ok" : "fail", h2[0], h2[1]);
            }


            if ((v & 0xFu) == 0)
            {
                uint64_t imgBase = 0;
                if (kmUser.U64(v + 0x10, &imgBase)
                    && imgBase >= 0x10000 && imgBase <= 0x00007FFFFFFFFFFFull
                    && ProbeImage(kmUser, imgBase, mi))
                {
                    Out("[附加] (b) Peb @EPROCESS+0x%llX = 0x%llX → ImageBaseAddress = 0x%llX (%s, SizeOfImage=0x%X)",
                        off, v, mi->base, mi->is64 ? "PE32+" : "PE32", mi->sizeOfImage);
                    mi->peb = v;
                    return true;
                }
            }


            {
                uint64_t al = v & ~0x1FFFFFull;
                for (int i = 0; i < 16; ++i)
                {
                    uint64_t cand = al - (uint64_t)i * 0x200000ull;
                    if (cand < 0x10000) break;
                    if (ProbeImage(kmUser, cand, mi))
                    {
                        Out("[附加] (c) 向下扫描命中 @EPROCESS+0x%llX：起点 0x%llX - %d*2MB → 0x%llX (%s, SizeOfImage=0x%X)",
                            off, al, i, mi->base, mi->is64 ? "PE32+" : "PE32", mi->sizeOfImage);
                        mi->peb = 0;
                        return true;
                    }
                }
            }
        }
    }


    {
        uint64_t pebOff = 0;
        for (uint64_t off = 0x100; off + 8 <= b.size(); off += 8)
        {
            uint64_t v = 0;
            memcpy(&v, b.data() + off, 8);
            if (!v || v > 0x00007FFFFFFFFFFFull) continue;
            if (ProbeImage(kmUser, v, mi))
            {
                pebOff = off;
                break;
            }
        }
        if (!mi->base)
        {
            Out("[附加] 找不到 Peb/ImageBaseAddress（固定偏移与兜底扫描都没命中）");
            return false;
        }
        Out("[附加] 兜底扫描命中 @EPROCESS+0x%llX = 0x%llX (%s, SizeOfImage=0x%X)",
            pebOff, mi->base, mi->is64 ? "PE32+" : "PE32", mi->sizeOfImage);
    }
    return true;
}


struct ModEntry
{
    uint64_t base = 0, size = 0;
    char name[64] = {};
};

static bool EnumModules(const Kern& kmUser, uint64_t peb, bool is64,
                        std::vector<ModEntry>* out, uint32_t cap = 256)
{
    if (!peb) return false;
    uint64_t ldr = 0;
    if (!kmUser.U64(peb + 0x18, &ldr) || !ldr) return false;

    const uint64_t head = ldr + (is64 ? 0x10 : 0x0C);
    const uint64_t offBase = is64 ? 0x30 : 0x18;
    const uint64_t offSize = is64 ? 0x40 : 0x20;
    const uint64_t offName = is64 ? 0x58 : 0x2C;
    const uint64_t offBuf = is64 ? 0x08 : 0x04;

    uint64_t cur = 0;
    if (!kmUser.U64(head, &cur) || !cur) return false;

    for (uint32_t i = 0; i < cap && cur && cur != head; ++i)
    {
        ModEntry e;
        if (!kmUser.U64(cur + offBase, &e.base)) break;
        kmUser.U64(cur + offSize, &e.size);

        uint16_t len = 0;
        uint64_t buf = 0;
        if (kmUser.Read(cur + offName, &len, 2) &&
            kmUser.U64(cur + offName + offBuf, &buf) && buf)
        {
            wchar_t wbuf[64] = {};
            uint32_t nch = len / 2;
            if (nch > 63) nch = 63;
            if (nch && kmUser.Read(buf, wbuf, nch * 2))
            {
                WideCharToMultiByte(CP_ACP, 0, wbuf, (int)nch, e.name, sizeof(e.name) - 1, nullptr, nullptr);
            }
        }
        out->push_back(e);
        if (!kmUser.U64(cur, &cur)) break;
    }
    return !out->empty();
}


struct Config
{
    std::string password = "dfeag";
    int startMin = 10, beforeMin = 10, beforeMax = 20, endMin = 10, endMax = 20, startMax = 30;

    uint64_t triggerRva = 0x904174ull;
    int triggerCheck = 0;
    int gateCheck = 0;
    bool loaded = false;
};

static Config LoadConfig()
{
    Config c;
    if (GetFileAttributesW(kConfigPath) == INVALID_FILE_ATTRIBUTES)
    {
        OutW(L"[配置] %ls 不存在，使用内置默认值", kConfigPath);
        return c;
    }


    std::string text;
    {
        FILE* f = nullptr;
        _wfopen_s(&f, kConfigPath, L"rb");
        if (f)
        {
            char buf[4096];
            size_t got;
            while ((got = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, got);
            fclose(f);
        }
    }

    auto iniValue = [&text](const char* key, const char* def) -> std::string
    {
        size_t pos = 0;
        while (pos < text.size())
        {
            size_t eol = text.find_first_of("\r\n", pos);
            if (eol == std::string::npos) eol = text.size();
            std::string line = text.substr(pos, eol - pos);
            pos = eol + 1;
            size_t b = line.find_first_not_of(" \t");
            if (b == std::string::npos) continue;
            if (line[b] == ';' || line[b] == '#' || line[b] == '[') continue;
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string k = line.substr(b, eq - b);
            while (!k.empty() && (k.back() == ' ' || k.back() == '\t')) k.pop_back();
            if (_stricmp(k.c_str(), key) != 0) continue;
            std::string v = line.substr(eq + 1);
            size_t vb = v.find_first_not_of(" \t");
            size_t ve = v.find_last_not_of(" \t\r");
            if (vb == std::string::npos) return def;
            return v.substr(vb, ve - vb + 1);
        }
        return def;
    };
    auto readInt = [&iniValue](const char* key, int def)
    {
        std::string v = iniValue(key, "");
        if (v.empty()) return def;
        return atoi(v.c_str());
    };

    auto readU64 = [&iniValue](const char* key, uint64_t def)
    {
        std::string v = iniValue(key, "");
        if (v.empty()) return def;
        uint64_t r = strtoull(v.c_str(), nullptr, 0);
        return r ? r : def;
    };

    std::string pwd = iniValue("password", "dfeag");
    c.password = pwd;

    c.startMin = readInt("start_min", c.startMin);
    c.beforeMin = readInt("before_min", c.beforeMin);
    c.beforeMax = readInt("before_max", c.beforeMax);
    c.endMin = readInt("end_min", c.endMin);
    c.endMax = readInt("end_max", c.endMax);
    c.startMax = readInt("start_max", c.startMax);
    c.triggerCheck = readInt("trigger_check", c.triggerCheck);
    c.gateCheck = readInt("gate_check", c.gateCheck);
    c.triggerRva = readU64("trigger_rva", c.triggerRva);
    if (g_noGate >= 0) c.gateCheck = g_noGate ? 0 : 1;
    c.loaded = true;
    Out(
        "[配置] gate_check=%d（0=跳过bit17门控） password=%s start=%d..%d before=%d..%d end=%d..%d trigger_check=%d trigger_rva=0x%llX",
        c.gateCheck, c.password.c_str(), c.startMin, c.startMax, c.beforeMin, c.beforeMax,
        c.endMin, c.endMax, c.triggerCheck, (unsigned long long)c.triggerRva);
    return c;
}

static int RandRange(int lo, int hi)
{
    if (hi <= lo) return lo;
    return lo + (int)(rand() % (hi - lo + 1));
}


static std::string RunAndCapture(const wchar_t* cmdLine, DWORD timeoutMs)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi = {};

    std::wstring cmd = cmdLine;
    BOOL ok = CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                             nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);
    if (!ok)
    {
        CloseHandle(hRead);
        return "";
    }

    WaitForSingleObject(pi.hProcess, timeoutMs);
    std::string out;
    char buf[512];
    DWORD got = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &got, nullptr) && got > 0) out.append(buf, got);

    CloseHandle(hRead);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return out;
}

static std::string GetCpuId()
{
    std::string raw = RunAndCapture(L"wmic cpu get ProcessorId", 3000);
    size_t p = raw.find("ProcessorId");
    if (p == std::string::npos) return "";
    p += strlen("ProcessorId");
    while (p < raw.size() && (raw[p] == '\r' || raw[p] == '\n' || raw[p] == ' ' || raw[p] == '\t')) ++p;
    size_t e = p;
    while (e < raw.size() && raw[e] != '\r' && raw[e] != '\n' && raw[e] != ' ') ++e;
    return raw.substr(p, e - p);
}

static std::string GetMac()
{
    IP_ADAPTER_INFO ai[16] = {};
    ULONG len = sizeof(ai);
    if (GetAdaptersInfo(ai, &len) != ERROR_SUCCESS) return "";


    static const uint8_t kVirt[][3] = {
        {0x00, 0x50, 0x56}, {0x08, 0x00, 0x27}, {0x00, 0x1C, 0x42}, {0x00, 0x0C, 0x29}, {0x00, 0x15, 0x5D},
    };
    for (IP_ADAPTER_INFO* p = ai; p; p = p->Next)
    {
        if (p->AddressLength < 6) continue;
        bool zero = true;
        for (int i = 0; i < 6; ++i) if (p->Address[i])
        {
            zero = false;
            break;
        }
        if (zero) continue;
        bool virt = false;
        for (auto& v : kVirt) if (!memcmp(p->Address, v, 3))
        {
            virt = true;
            break;
        }
        if (virt) continue;

        char out[32] = {};
        snprintf(out, sizeof(out), "%02X%02X%02X%02X%02X%02X",
                 p->Address[0], p->Address[1], p->Address[2],
                 p->Address[3], p->Address[4], p->Address[5]);
        return out;
    }
    return "";
}

static uint32_t Fnv1a(const std::string& s)
{
    uint32_t h = 2166136261u;
    for (unsigned char c : s)
    {
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

static std::string RandKey(int n)
{
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string s;
    for (int i = 0; i < n; ++i) s += alpha[rand() % (sizeof(alpha) - 1)];
    return s;
}


static HWND FindGameWindow()
{
    std::wstring cls = Deobf(kObfWindowClass, sizeof(kObfWindowClass) / sizeof(uint16_t));
    std::wstring title = Deobf(kObfWindowTitle, sizeof(kObfWindowTitle) / sizeof(uint16_t));
    return FindWindowW(cls.c_str(), title.c_str());
}


static bool AttachTarget(const Kern& kmKernel, const KernelCtx& kc, DWORD pid,
                         ModInfo* outMod = nullptr, Kern* kmUser = nullptr)
{
    uint64_t eproc = 0, dtb = 0;
    char name[16] = {};
    if (!FindEprocess(kmKernel, kc, pid, &eproc, &dtb, name, sizeof(name)))
    {
        Out("[附加] PID %lu 不在进程链表里", pid);
        return false;
    }
    if (!dtb || dtb >= 0x1000000000ull)
    {
        Out("[附加] EPROCESS+0x28 取到的 DTB 不合理: 0x%llX（偏移可能不对）", dtb);
        return false;
    }


    uint64_t dtb2 = 0;
    if (kmKernel.U64(eproc + 0x30, &dtb2)) dtb2 &= PAGE_MSK;
    if (dtb2 >= 0x1000000000ull) dtb2 = 0;
    Out("[附加] PID %lu EPROCESS=0x%llX name=%s DTB(+0x28)=0x%llX DTB(+0x30)=0x%llX",
        pid, eproc, name, dtb, dtb2);

    if (!kmUser) return false;

    ModInfo mi;
    bool got = false;
    uint64_t usedDtb = 0;
    uint64_t candDtbs[2] = {dtb, dtb2};
    for (int i = 0; i < 2 && !got; ++i)
    {
        uint64_t d = candDtbs[i];
        if (!d) continue;
        if (i == 1 && d == dtb) continue;
        Out("[附加] ---- 尝试 DTB(%s)=0x%llX ----", (i == 0) ? "+0x28" : "+0x30", d);
        kmUser->dtb = d;
        kmUser->ResetCache();
        mi = ModInfo();
        got = DiscoverModule(kmKernel, *kmUser, eproc, &mi);
        if (got) usedDtb = d;
    }
    if (!got)
    {
        kmUser->dtb = dtb;
        kmUser->ResetCache();
        mi.dtb = dtb;
        if (outMod) *outMod = mi;
        Out("[附加] 没能定位映像基址（+0x28 与 +0x30 两个 DTB 下都读不到 MZ）");
        return false;
    }
    mi.dtb = usedDtb;
    if (outMod) *outMod = mi;
    Out("[附加] 采用 DTB=0x%llX", usedDtb);
    Out("[附加] 映像基址=0x%llX SizeOfImage=0x%X TimeDateStamp=0x%08X PEB=0x%llX",
        mi.base, mi.sizeOfImage, mi.timestamp, mi.peb);


    uint8_t head[16] = {};
    if (kmUser->Read(mi.base, head, sizeof(head)))
    {
        Out("[附加] 目标 PE 头（经目标DTB）: %02X %02X %02X %02X %02X %02X %02X %02X ...",
            head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7]);
    }
    else
    {
        Out("[附加] 目标 PE 头读取失败（切了 DTB 仍读不到，检查 EPROCESS+0x28 偏移）");
        return false;
    }


    std::vector<ModEntry> mods;
    if (mi.peb && EnumModules(*kmUser, mi.peb, mi.is64, &mods))
    {
        Out("[附加] 模块链表可枚举，共 %zu 个：", mods.size());
        for (size_t i = 0; i < mods.size() && i < 8; ++i)
            Out("    %-20s base=0x%llX size=0x%X", mods[i].name, mods[i].base, mods[i].size);
        for (const auto& m : mods)
        {
            if (_stricmp(m.name, "xxx.exe") == 0)
            {
                Out("[附加] 按名字命中 xxx.exe: base=0x%llX（与 PEB.ImageBaseAddress 一致=%s）",
                    m.base, m.base == mi.base ? "是" : "否");
                break;
            }
        }
    }
    else
    {
        Out("[附加] 模块链表枚举失败（PEB.Ldr 结构或偏移不匹配）");
    }
    return true;
}


static const uint64_t kTriggerRva = 0x904174ull;
static const float kTriggerThreshold = 2.5f;

struct GameState
{
    uint64_t p = 0, v1 = 0, v2 = 0;
    uint32_t flags = 0;
    bool readOk = false;
    bool trigger = false;
};


static GameState PollGameState(const Kern& km, uint64_t moduleBase, bool is64)
{
    GameState s;
    s.p = moduleBase + 0x490F990;
    uint64_t v1 = 0;
    if (!km.U64(s.p, &v1) || !v1) return s;

    auto shred = [is64](uint64_t v) -> uint64_t
    {
        if (is64) return 0;
        return v & 0xFFFFFFFFull;
    };

    auto tryChain = [&](uint64_t p1, uint64_t* o1, uint64_t* o2, uint32_t* of) -> bool
    {
        uint64_t v2 = 0;
        if (!km.U64(p1 + 0x18, &v2) || !v2)
        {
            uint64_t t = shred(p1);
            if (!t || !km.U64(t + 0x18, &v2) || !v2) return false;
            p1 = t;
        }
        uint64_t v2b = v2;
        uint32_t f = 0;
        if (!km.U32(v2b + 0x1A14, &f))
        {
            uint64_t t = shred(v2b);
            if (!t || !km.U32(t + 0x1A14, &f)) return false;
            v2b = t;
        }
        *o1 = p1;
        *o2 = v2b;
        *of = f;
        return true;
    };

    if (!tryChain(v1, &s.v1, &s.v2, &s.flags)) return s;
    s.readOk = true;
    s.trigger = (s.flags & 0x20000) != 0;
    return s;
}


static volatile LONG g_stop = 0;
static volatile LONG g_active = 0;
static volatile LONG g_trigger = 0;
static Msdk* g_msdk = nullptr;


static void ReleaseHid()
{
    if (!g_msdk || !g_msdk->hid) return;
    if (g_msdk->leftUp) g_msdk->leftUp(g_msdk->hid);
    if (g_msdk->releaseAllKey) g_msdk->releaseAllKey(g_msdk->hid);
}

static BOOL WINAPI OnCtrl(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT)
    {
        InterlockedExchange(&g_stop, 1);
        ReleaseHid();
        return TRUE;
    }
    return FALSE;
}


static DWORD WINAPI HotkeyThread(LPVOID)
{
    auto flip = [](volatile LONG* p) -> bool
    {
        LONG cur = InterlockedCompareExchange(p, 0, 0);
        LONG nv = cur ? 0 : 1;
        InterlockedExchange(p, nv);
        return nv != 0;
    };
    bool prevF2 = false, prevF3 = false;
    while (!InterlockedCompareExchange(&g_stop, 0, 0))
    {
        bool f3 = (GetAsyncKeyState(VK_F3) & 0x8000) != 0;
        bool f2 = (GetAsyncKeyState(VK_F2) & 0x8000) != 0;

        if (f3 && !prevF3)
        {
            bool on = flip(&g_trigger);
            PlaySoundW(on ? kSoundInsert : kSoundRemove, nullptr,
                       SND_FILENAME | SND_ASYNC | SND_NODEFAULT);
            Out("[热键] F3 → 触发判定(trigger_check) = %s", on ? "开（按阈值）" : "关（无条件连点）");
        }
        if (f2 && !prevF2)
        {
            bool on = flip(&g_active);
            if (on)
            {
                Out("[热键] F2 → 总开关 = 开（开始附加游戏）");
                PlaySoundW(kSoundInsert, nullptr, SND_FILENAME | SND_ASYNC | SND_NODEFAULT);
            }
            else
            {
                Out("[热键] F2 → 总开关 = 关（松开鼠标并停止）");
                ReleaseHid();
                PlaySoundW(kSoundRemove, nullptr, SND_FILENAME | SND_ASYNC | SND_NODEFAULT);
            }
        }
        prevF2 = f2;
        prevF3 = f3;
        Sleep(10);
    }
    return 0;
}

int main(int argc, char** argv)
{
    bool once = false, noInstall = false, uninstall = false, selftest = false, hidProbe = false;

    for (int i = 1; i < argc; ++i)
    {
        if (!strcmp(argv[i], "--once")) once = true;
        else if (!strcmp(argv[i], "--no-install")) noInstall = true;
        else if (!strcmp(argv[i], "--uninstall")) uninstall = true;
        else if (!strcmp(argv[i], "--selftest")) selftest = true;
        else if (!strcmp(argv[i], "--msgbox")) g_msgbox = true;
        else if (!strcmp(argv[i], "--diag")) g_hidDebug = true;
        else if (!strcmp(argv[i], "--hid-probe")) hidProbe = true;
        else if (!strcmp(argv[i], "--scan-end") && i + 1 < argc) g_lowEnd = strtoull(argv[++i], nullptr, 0);
        else if (!strcmp(argv[i], "--dtb") && i + 1 < argc) g_forceDtb = strtoull(argv[++i], nullptr, 0);
        else if (!strcmp(argv[i], "--dump-dtb") && i + 1 < argc) g_dumpDtb = strtoull(argv[++i], nullptr, 0);
        else if (!strcmp(argv[i], "--no-gate")) g_noGate = 1;
        else if (!strcmp(argv[i], "--gate")) g_noGate = 0;
    }
    SetConsoleOutputCP(CP_UTF8);
    srand((unsigned)GetTickCount() ^ GetCurrentProcessId());
    SetConsoleCtrlHandler(OnCtrl, TRUE);

    Out("============================================================");
    Out("  Xxx (公共版) —— xxx.exe 逻辑复刻");
    Out("  样本 SHA256 aef6d5a7a3808da779740e59643f04dd293b8b4b9a49edb43cc99382d6095701");
    Out("============================================================");


    if (hidProbe)
    {
        Msdk m;
        std::string err;
        Out("[HID] 内嵌 msdk.dll %u 字节", kMsdkSize);
        if (!m.Load(&err))
        {
            Out("[HID] 加载失败: %s", err.c_str());
            return 1;
        }
        Out("[HID] 内存映射 @0x%p", m.image);
        Out("[HID] M_Open=0x%p M_MoveTo=0x%p M_ReleaseAllKey=0x%p M_LeftDown=0x%p M_LeftUp=0x%p",
            m.open, m.moveTo, m.releaseAllKey, m.leftDown, m.leftUp);
        int h = m.open ? m.open(1) : 0;
        Out("[HID] M_Open(1) = %d  %s", h, (h && h != -1) ? "（设备已就绪）" : "（0/-1 = 没有可用 HID 设备）");
        if (h && h != -1) m.releaseAllKey(h);
        return 0;
    }

    if (selftest)
    {
        std::wstring c = Deobf(kObfWindowClass, sizeof(kObfWindowClass) / sizeof(uint16_t));
        std::wstring t = Deobf(kObfWindowTitle, sizeof(kObfWindowTitle) / sizeof(uint16_t));
        std::wstring p = Deobf(kObfProcess, sizeof(kObfProcess) / sizeof(uint16_t));
        OutW(L"[自检] 窗口类 = %ls", c.c_str());
        OutW(L"[自检] 窗口名 = %ls", t.c_str());
        OutW(L"[自检] 进程名 = %ls", p.c_str());
        Out("[自检] 内嵌驱动 %u 字节", kDriverBlobSize);
        WinVer v = QueryWinVer();
        Out("[自检] 系统 %u.%u build %u %s", v.major, v.minor, v.build, sizeof(void*) == 8 ? "x64" : "x86");
        Out("[自检] 管理员 = %s", IsElevated() ? "是" : "否");
        Config cfg = LoadConfig();
        (void)cfg;
        std::string cpu = GetCpuId(), mac = GetMac();
        char machine[32] = {};
        snprintf(machine, sizeof(machine), "%08X", Fnv1a(cpu + "|" + mac));
        Out("[自检] CPU=%s MAC=%s 机器码=%s", cpu.c_str(), mac.c_str(), machine);


        Msdk m;
        std::string err;
        Out("[自检] 内嵌 msdk.dll %u 字节", kMsdkSize);
        if (m.Load(&err))
        {
            Out("[自检] msdk 内存映射 @0x%p", m.image);
            Out("[自检] 导出(按序号): M_Open=0x%p M_MoveTo=0x%p M_ReleaseAllKey=0x%p M_LeftDown=0x%p M_LeftUp=0x%p",
                m.open, m.moveTo, m.releaseAllKey, m.leftDown, m.leftUp);
        }
        else
        {
            Out("[自检] msdk 加载失败: %s", err.c_str());
        }
        return 0;
    }


    if (!IsElevated())
    {
        Fatal(true, L"需要管理员权限运行");
        return 1;
    }
    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    if (sizeof(void*) == 4 && !wow64)
    {
        Fatal(true, L"unsupported Windows architecture; only x64 Windows 10 is supported");
        return 1;
    }

    WinVer v = QueryWinVer();
    Out("[系统] Windows %u.%u Build=%u %s", v.major, v.minor, v.build, sizeof(void*) == 8 ? "x64" : "x86");
    if (v.major != 10)
    {
        OutW(L"[警告] 样本只支持 Windows 10（当前 %u.%u），继续但偏移可能不匹配", v.major, v.minor);
    }


    OutW(L"初始化中.....请不要关闭程序");

    if (uninstall)
    {
        RemoveDriver();
        return 0;
    }


    Msdk msdk;
    {
        std::string err;
        if (!msdk.Load(&err))
        {
            Out("[HID] msdk.dll 内存加载失败: %s", err.c_str());
            Fatal(true, L"设备初始化失败！");
            return 1;
        }
        Out("[HID] msdk.dll 已内存映射 @0x%p（无文件落地）", msdk.image);
        if (!msdk.OpenAndReset())
        {
            Out("[HID] M_Open(1) 失败 → 设备初始化失败！");
            Fatal(true, L"设备初始化失败！");
            return 1;
        }
        Out("[HID] M_Open 成功 hid=%d，鼠标已复位到 (10,10) 并释放所有键", msdk.hid);
    }
    g_msdk = &msdk;


    if (!noInstall)
    {
        std::wstring drvPath;
        if (!WriteDriverFile(&drvPath))
        {
            Fatal(true, L"驱动加载失败！");
            return 1;
        }
        if (!InstallAndStartDriver(drvPath))
        {
            DeleteFileW(drvPath.c_str());
            OutW(L"[驱动] 已回收 %ls", drvPath.c_str());
            Fatal(true, L"驱动加载失败！");
            return 1;
        }
    }


    Device dev;
    if (!dev.Open())
    {
        Out("[设备] 打开 %ls 失败 err=%lu", kDevicePath, GetLastError());
        Fatal(true, L"设备初始化失败！");
        return 1;
    }
    uint32_t ver = dev.Version();
    if (ver == 0x55AA0001u) Out("[设备] 驱动应答 version=0x%X", ver);
    else Out("[设备] 版本探测=0x%X（不致命）", ver);


    PhysMem pm(dev);
    KernelCtx kc;
    if (!InitKernel(pm, dev, &kc))
    {
        Fatal(true, L"设备初始化失败！");
        return 1;
    }


    Config cfg = LoadConfig();
    OutW(L"[时序] start_min=%d start_max=%d before=%d..%d end=%d..%d （毫秒）",
         cfg.startMin, cfg.startMax, cfg.beforeMin, cfg.beforeMax, cfg.endMin, cfg.endMax);
    if (cfg.startMin > 0)
        Sleep((DWORD)std::max(1, RandRange(cfg.startMin, cfg.startMax > cfg.startMin ? cfg.startMax : cfg.startMin)));


    std::string cpu = GetCpuId();
    std::string mac = GetMac();
    char machine[32] = {};
    snprintf(machine, sizeof(machine), "%08X", Fnv1a(cpu + "|" + mac));
    Out("[机器码] CPU=%s MAC=%s -> %s", cpu.c_str(), mac.c_str(), machine);


    std::wstring wantProc = Deobf(kObfProcess, sizeof(kObfProcess) / sizeof(uint16_t));
    std::wstring wantTitle = Deobf(kObfWindowTitle, sizeof(kObfWindowTitle) / sizeof(uint16_t));
    OutW(L"[目标] 进程=%ls 窗口类/标题已解码（标题=%ls）", wantProc.c_str(), wantTitle.c_str());

    HWND hwnd = FindGameWindow();
    if (hwnd)
    {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        OutW(L"[目标] 找到窗口 0x%p，PID=%lu", hwnd, pid);
        Kern kmK(dev, &pm.lm);
        kmK.ramTop = pm.ramTop;
        kmK.dtb = kc.dtb;
        Kern kmU(dev, &pm.lm);
        kmU.ramTop = pm.ramTop;
        ModInfo mi;
        AttachTarget(kmK, kc, pid, &mi, &kmU);
        PlaySoundW(kSoundInsert, nullptr, SND_FILENAME | SND_ASYNC);
    }
    else
    {
        OutW(L"[目标] 暂未找到游戏窗口（等主循环里再找）");
    }

    OutW(L"初始化完成！");
    OutW(L"[热键] F2 = 总开关（激活/停止）   F3 = 触发判定开关（无条件连点 / 按阈值）");
    if (once)
    {
        dev.Close();
        return 0;
    }


    HANDLE hHotkey = CreateThread(nullptr, 0, HotkeyThread, nullptr, 0, nullptr);
    DWORD lastPid = 0;
    ModInfo mi;
    uint32_t ticks = 0;
    uint32_t readFail = 0;
    Kern kmK(dev, &pm.lm);
    kmK.ramTop = pm.ramTop;
    kmK.dtb = kc.dtb;
    Kern kmU(dev, &pm.lm);
    kmU.ramTop = pm.ramTop;

    while (!InterlockedCompareExchange(&g_stop, 0, 0))
    {
        if (!InterlockedCompareExchange(&g_active, 0, 0))
        {
            if (lastPid)
            {
                Out("[循环] F2 关闭 → 停止附加");
                ReleaseHid();
                lastPid = 0;
                mi = ModInfo();
                readFail = 0;
                kmU.dtb = 0;
                kmU.ResetCache();
            }
            Sleep(100);
            continue;
        }


        if (!lastPid || !mi.base)
        {
            HWND h = FindGameWindow();
            if (!h)
            {
                Sleep(100);
                continue;
            }
            DWORD pid = 0;
            GetWindowThreadProcessId(h, &pid);
            if (!pid)
            {
                Sleep(100);
                continue;
            }
            if (!AttachTarget(kmK, kc, pid, &mi, &kmU))
            {
                Sleep(100);
                continue;
            }
            lastPid = pid;
            readFail = 0;
            continue;
        }


        GameState st = PollGameState(kmU, mi.base, mi.is64);
        if (!st.readOk)
        {
            if (++readFail > 20)
            {
                Out("[循环] 目标读取连续失败 %u 次 → 重新附加", readFail);
                ReleaseHid();
                lastPid = 0;
                mi = ModInfo();
                readFail = 0;
                kmU.dtb = 0;
                kmU.ResetCache();
            }
            Sleep(10);
            continue;
        }
        readFail = 0;


        {
            static uint32_t dbgTick = 0;
            if ((++dbgTick % 300) == 1)
            {
                Out("[状态] v1=0x%llX v2=0x%llX flags=0x%08X bit17=%u%s",
                    st.v1, st.v2, st.flags, (st.flags >> 17) & 1u,
                    (st.flags & 0x20000) ? "" : "  (未置位→不动作)");


                if (g_hidDebug && st.v1)
                {
                    uint64_t q[8] = {};
                    if (kmU.Read(st.v1, q, sizeof(q)))
                    {
                        Out("[诊断] v1+0x00..0x3F:");
                        for (int i = 0; i < 8; ++i)
                            Out("[诊断]   +0x%02X = 0x%016llX", i * 8, q[i]);
                    }
                    else Out("[诊断] v1 读取失败");


                    uint64_t cands[64] = {};
                    if (kmU.Read(st.v1, cands, sizeof(cands)))
                    {
                        for (int i = 0; i < 64; ++i)
                        {
                            uint64_t c = cands[i];
                            if (c < 0x10000ull || c > 0x00007FFFFFFFFFFFull) continue;
                            if (c & 0x7ull) continue;
                            uint32_t f2 = 0;
                            if (!kmU.U32(c + 0x1A14, &f2)) continue;
                            if (!f2) continue;
                            Out("[诊断] >>> v1+0x%03X = 0x%llX → +0x1A14 = 0x%08X (bit17=%u)",
                                i * 8, c, f2, (f2 >> 17) & 1u);
                        }
                    }
                }
                if (st.v2)
                {
                    uint64_t q2[8] = {};
                    if (kmU.Read(st.v2 + 0x1A00, q2, sizeof(q2)))
                    {
                        Out("[诊断] v2+0x1A00..0x1A3F:");
                        for (int i = 0; i < 8; ++i)
                            Out("[诊断]   +0x%04X = 0x%016llX", 0x1A00 + i * 8, q2[i]);
                    }
                    else Out("[诊断] v2 读取失败");
                }
            }
        }
        if (cfg.gateCheck && !(st.flags & 0x20000))
        {
            Sleep(2);
            continue;
        }
        if ((++ticks % 200) == 1)
            Out("[状态] v1=0x%llX v2=0x%llX flags=0x%08X bit17=%u%s",
                st.v1, st.v2, st.flags, (st.flags >> 17) & 1u,
                cfg.gateCheck ? "" : "  (门控已跳过)");


        Sleep((DWORD)std::max(1, RandRange(cfg.startMin, cfg.startMax)));
        if (InterlockedCompareExchange(&g_stop, 0, 0)) break;


        float v = 0.0f;
        uint64_t taddr = mi.base + cfg.triggerRva;
        bool haveV = kmU.Read(taddr, &v, sizeof(v));
        bool trigOn = InterlockedCompareExchange(&g_trigger, 0, 0) != 0;
        bool fire;
        if (!trigOn)
        {
            fire = true;
        }
        else
        {
            fire = haveV && (v >= kTriggerThreshold);
        }


        if (fire)
        {
            msdk.leftUp(msdk.hid);


            Sleep((DWORD)std::max(1, RandRange(cfg.endMin, cfg.endMax)));
            msdk.leftDown(msdk.hid);
            if ((ticks % 20) == 1)
                Out("[动作] 开火 0x%llX=%.4f%s", taddr, haveV ? v : 0.0f,
                    haveV ? "" : " (读取失败)");
        }
        else if ((ticks % 20) == 1)
        {
            Out("[触发] 未满足 0x%llX=%.4f < %.1f", taddr, haveV ? v : 0.0f, kTriggerThreshold);
        }


        Sleep((DWORD)std::max(1, RandRange(cfg.beforeMin, cfg.beforeMax)));
        Sleep(2);
    }

    InterlockedExchange(&g_stop, 1);
    ReleaseHid();
    if (hHotkey)
    {
        WaitForSingleObject(hHotkey, 2000);
        CloseHandle(hHotkey);
    }
    g_msdk = nullptr;
    dev.Close();
    Out("[退出] 已停止");
    return 0;
}
