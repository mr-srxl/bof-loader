// cl.exe /O2 bof_loader.cpp /Fe:bof_loader.exe
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>

// ==========================================
// Headers & Definitions (from bof_loader.h)
// ==========================================
#pragma pack(push, 1)
typedef struct { short Machine; short NumberOfSections; int TimeDateStamp; int PointerToSymbolTable; int NumberOfSymbols; short SizeOfOptionalHeader; short Characteristics; } COF_HEADER;
typedef struct { char Name[8]; int VirtualSize; int VirtualAddress; int SizeOfRawData; int PointerToRawData; int PointerToRelocations; int PointerToLineNumbers; short NumberOfRelocations; short NumberOfLinenumbers; int Characteristics; } COF_SECTION;
typedef struct { int VirtualAddress; int SymbolTableIndex; short Type; } COF_RELOCATION;
typedef struct { union { char cName[8]; int dwName[2]; } Name; int Value; short SectionNumber; short Type; char StorageClass; char NumberOfAuxSymbols; } COF_SYMBOL;
#pragma pack(pop)

#define MAX_SECTIONS          25
#define MAP_FUNCTIONS_SIZE    4096

#define IMAGE_REL_AMD64_ADDR64     0x0001
#define IMAGE_REL_AMD64_ADDR32NB   0x0003
#define IMAGE_REL_AMD64_REL32      0x0004
#define IMAGE_REL_AMD64_REL32_1    0x0005
#define IMAGE_REL_AMD64_REL32_2    0x0006
#define IMAGE_REL_AMD64_REL32_3    0x0007
#define IMAGE_REL_AMD64_REL32_4    0x0008
#define IMAGE_REL_AMD64_REL32_5    0x0009

#define IMAGE_REL_I386_DIR32       0x0006
#define IMAGE_REL_I386_REL32       0x0014

#ifndef IMAGE_SYM_CLASS_EXTERNAL
#define IMAGE_SYM_CLASS_EXTERNAL       2
#endif
#ifndef IMAGE_SYM_CLASS_EXTERNAL_DEF
#define IMAGE_SYM_CLASS_EXTERNAL_DEF   2
#endif

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

typedef struct { char* original; char* buffer; int length; int size; } datap;
typedef struct { char* original; char* buffer; int length; int size; } formatp;

class Packer {
    DWORD size;
    DWORD capacity;
    BYTE* buffer;
    DWORD index;
    bool  ownsBuffer;
public:
    Packer();
    Packer(BYTE* buffer, ULONG size);
    ~Packer();

    VOID Set32(ULONG offset, ULONG value);
    VOID EnsureCapacity(ULONG needed);

    VOID Pack64(ULONG64 value);
    VOID Pack32(ULONG value);
    VOID Pack16(WORD value);
    VOID Pack8(BYTE value);
    VOID PackBytes(PBYTE data, ULONG data_size);
    VOID PackFlatBytes(PBYTE data, ULONG data_size);
    VOID PackStringA(LPSTR str);

    BYTE  Unpack8();
    ULONG Unpack32();
    BYTE* UnpackBytes(ULONG* size);
    BYTE* UnpackBytesCopy(ULONG* size);

    VOID  Clear(BOOL renew);
    PBYTE data();
    ULONG datasize();
};

typedef struct {
    const char* name;
    LPVOID      proc;
} BOF_API_ENTRY;

extern Packer* bofOutputPacker;
extern int     bofOutputCount;
extern ULONG   bofTaskId;

void    InitBofOutputData();
Packer* ObjectExecute(ULONG taskId, char* targetFuncName, unsigned char* coffFile, unsigned int cofFileSize, unsigned char* args, int argsSize);

// Ensure section characteristic macros are defined
#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#endif
#ifndef IMAGE_SCN_MEM_READ
#define IMAGE_SCN_MEM_READ 0x40000000
#endif
#ifndef IMAGE_SCN_MEM_WRITE
#define IMAGE_SCN_MEM_WRITE 0x80000000
#endif

// ==========================================
// Packer Implementation
// ==========================================
Packer::Packer() {
    capacity = 1024;
    buffer = (BYTE*)LocalAlloc(LPTR, capacity);
    size = 0;
    index = 0;
    ownsBuffer = true;
}
Packer::Packer(BYTE* buf, ULONG sz) {
    buffer = buf; capacity = sz; size = sz; index = 0; ownsBuffer = false;
}
Packer::~Packer() {
    if (ownsBuffer && buffer) { LocalFree(buffer); buffer = NULL; }
}
VOID Packer::EnsureCapacity(ULONG needed) {
    if (needed <= capacity) return;
    ULONG newCap = capacity * 2;
    if (newCap < needed) newCap = needed;

    BYTE* newBuf = (BYTE*)LocalReAlloc(buffer, newCap, LMEM_MOVEABLE | LMEM_ZEROINIT);
    if (newBuf) {
        buffer = newBuf;
        capacity = newCap;
    }
}
VOID Packer::Set32(ULONG offset, ULONG value) {
    if (offset + 4 <= capacity) memcpy(buffer + offset, &value, 4);
}
VOID Packer::Pack64(ULONG64 value) { EnsureCapacity(index + 8); memcpy(buffer + index, &value, 8); index += 8; }
VOID Packer::Pack32(ULONG value) { EnsureCapacity(index + 4); memcpy(buffer + index, &value, 4); index += 4; }
VOID Packer::Pack16(WORD value) { EnsureCapacity(index + 2); memcpy(buffer + index, &value, 2); index += 2; }
VOID Packer::Pack8(BYTE value) { EnsureCapacity(index + 1); buffer[index] = value; index += 1; }
VOID Packer::PackBytes(PBYTE data, ULONG data_size) {
    EnsureCapacity(index + 4 + data_size);
    memcpy(buffer + index, &data_size, 4); index += 4;
    if (data_size > 0 && data) { memcpy(buffer + index, data, data_size); index += data_size; }
}
VOID Packer::PackFlatBytes(PBYTE data, ULONG data_size) {
    EnsureCapacity(index + data_size);
    if (data_size > 0 && data) { memcpy(buffer + index, data, data_size); index += data_size; }
}
VOID Packer::PackStringA(LPSTR str) { ULONG len = str ? (ULONG)strlen(str) : 0; PackBytes((PBYTE)str, len); }
BYTE Packer::Unpack8() { BYTE val = 0; if (index + 1 <= size) { val = buffer[index]; index += 1; } return val; }
ULONG Packer::Unpack32() { ULONG val = 0; if (index + 4 <= size) { memcpy(&val, buffer + index, 4); index += 4; } return val; }
BYTE* Packer::UnpackBytes(ULONG* outSize) {
    ULONG len = 0;
    if (index + 4 > size) { if (outSize) *outSize = 0; return NULL; }
    memcpy(&len, buffer + index, 4); index += 4;
    if (index + len > size) { if (outSize) *outSize = 0; return NULL; }
    BYTE* ptr = buffer + index; index += len;
    if (outSize) *outSize = len;
    return ptr;
}
BYTE* Packer::UnpackBytesCopy(ULONG* outSize) {
    ULONG len = 0; BYTE* src = UnpackBytes(&len);
    if (!src || len == 0) { if (outSize) *outSize = 0; return NULL; }
    BYTE* copy = (BYTE*)LocalAlloc(LPTR, len);
    if (copy) memcpy(copy, src, len);
    if (outSize) *outSize = len;
    return copy;
}
VOID Packer::Clear(BOOL renew) {
    index = 0;
    if (renew && ownsBuffer) {
        LocalFree(buffer);
        capacity = 1024;
        buffer = (BYTE*)LocalAlloc(LPTR, capacity);
    }
}
PBYTE Packer::data() { return buffer; }
ULONG Packer::datasize() { return index; }

/* ================ Globals ================ */
Packer* bofOutputPacker = NULL;
int     bofOutputCount  = 0;
ULONG   bofTaskId       = 0;

/* ================ Internal CS Memory Allocators ================ */
void* intAlloc(int size) { return LocalAlloc(LPTR, size); }
void intFree(void* ptr) { if (ptr) LocalFree(ptr); }

/* ================ Beacon API ================ */
void InitBofOutputData() {
    if (!bofOutputPacker) bofOutputPacker = new Packer();
    else bofOutputPacker->Clear(TRUE);
    bofOutputCount = 0;
}

void BeaconOutput(int type, const char* data, int len) {
    if (!bofOutputPacker || !data || len <= 0) return;
    bofOutputPacker->Pack32(type);
    bofOutputPacker->PackBytes((PBYTE)data, len);
    bofOutputCount++;
}

void BeaconPrintf(int type, const char* fmt, ...) {
    if (!bofOutputPacker || !fmt) return;
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len > 0) {
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        BeaconOutput(type, buf, len);
    }
}

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (!parser || !buffer) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    if (size < 4) {
        parser->length = 0;
        parser->size = 0;
        parser->buffer = NULL;
        return;
    }
    parser->length   = size - 4;
    parser->size     = size - 4;
    parser->buffer  += 4;
}
int BeaconDataInt(datap* parser) {
    if (!parser || parser->length < 4) return 0;
    int val = 0; memcpy(&val, parser->buffer, 4);
    parser->buffer += 4; parser->length -= 4;
    return val;
}
short BeaconDataShort(datap* parser) {
    if (!parser || parser->length < 2) return 0;
    short val = 0; memcpy(&val, parser->buffer, 2);
    parser->buffer += 2; parser->length -= 2;
    return val;
}
int BeaconDataLength(datap* parser) { return parser ? parser->length : 0; }
char* BeaconDataExtract(datap* parser, int* size) {
    if (!parser || parser->length < 4) { if (size) *size = 0; return NULL; }
    unsigned int len = 0; memcpy(&len, parser->buffer, 4);
    parser->length -= 4; parser->buffer += 4;
    if (len > (unsigned int)parser->length) { if (size) *size = 0; return NULL; }
    char* out = parser->buffer;
    parser->length -= len; parser->buffer += len;
    if (size) *size = (int)len;
    return out;
}

/* Format API stubs */
void BeaconFormatAlloc(formatp* format, int maxsz) { if (!format) return; format->original = (char*)LocalAlloc(LPTR, maxsz); format->buffer = format->original; format->length = 0; format->size = maxsz; }
void BeaconFormatReset(formatp* format) { if (!format || !format->original) return; memset(format->original, 0, format->size); format->buffer = format->original; format->length = 0; }
void BeaconFormatAppend(formatp* format, const char* text, int len) { if (!format || !text) return; memcpy(format->buffer, text, len); format->buffer += len; format->length += len; }
void BeaconFormatPrintf(formatp* format, const char* fmt, ...) { if (!format || !fmt) return; va_list ap; va_start(ap, fmt); int len = vsnprintf(NULL, 0, fmt, ap); va_end(ap); if (len <= 0 || format->length + len > format->size) return; va_start(ap, fmt); vsnprintf(format->buffer, len + 1, fmt, ap); va_end(ap); format->length += len; format->buffer += len; }
char* BeaconFormatToString(formatp* format, int* size) { if (!format) { if (size) *size = 0; return NULL; } if (size) *size = format->length; return format->original; }
void BeaconFormatFree(formatp* format) { if (!format) return; if (format->original) { LocalFree(format->original); format->original = NULL; } format->buffer = NULL; format->length = 0; format->size = 0; }
void BeaconFormatInt(formatp* format, int value) { if (!format || format->length + 4 > format->size) return; unsigned int out = ((value >> 24) & 0xff) | ((value << 8) & 0xff0000) | ((value >> 8) & 0xff00) | ((value << 24) & 0xff000000); memcpy(format->buffer, &out, 4); format->length += 4; format->buffer += 4; }

/* Stub APIs */
BOOL  BeaconUseToken(HANDLE token) { return FALSE; }
void  BeaconRevertToken(void) {}
BOOL  BeaconIsAdmin(void) { return FALSE; }
BOOL  toWideChar(char* src, wchar_t* dst, int max) { if (!src || max < (int)sizeof(wchar_t)) return FALSE; return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, max / sizeof(wchar_t)) > 0; }
BOOL  BeaconAddValue(const char* key, void* ptr) { return FALSE; }
void* BeaconGetValue(const char* key) { return NULL; }
BOOL  BeaconRemoveValue(const char* key) { return FALSE; }
BOOL  BeaconRegisterThreadCallback(PVOID cb, PVOID data) { return TRUE; }
BOOL  BeaconUnregisterThreadCallback(void) { return TRUE; }
void  BeaconWakeup(void) {}
HANDLE BeaconGetStopJobEvent(void) { return NULL; }

/* Proxy APIs */
HMODULE proxy_LoadLibraryA(LPCSTR n) { return LoadLibraryA(n); }
HMODULE proxy_GetModuleHandleA(LPCSTR n) { return GetModuleHandleA(n); }
FARPROC proxy_GetProcAddress(HMODULE h, LPCSTR n) { return GetProcAddress(h, n); }
BOOL    proxy_FreeLibrary(HMODULE h) { return FreeLibrary(h); }

/* ================ BOF Loader Implementation ================ */
static BOF_API_ENTRY BeaconFunctions[] = {
    { "BeaconDataParse",              (LPVOID)BeaconDataParse },
    { "BeaconDataInt",                (LPVOID)BeaconDataInt },
    { "BeaconDataShort",              (LPVOID)BeaconDataShort },
    { "BeaconDataLength",             (LPVOID)BeaconDataLength },
    { "BeaconDataExtract",            (LPVOID)BeaconDataExtract },
    { "BeaconOutput",                 (LPVOID)BeaconOutput },
    { "BeaconPrintf",                 (LPVOID)BeaconPrintf },
    { "BeaconFormatAlloc",            (LPVOID)BeaconFormatAlloc },
    { "BeaconFormatReset",            (LPVOID)BeaconFormatReset },
    { "BeaconFormatAppend",           (LPVOID)BeaconFormatAppend },
    { "BeaconFormatPrintf",           (LPVOID)BeaconFormatPrintf },
    { "BeaconFormatToString",         (LPVOID)BeaconFormatToString },
    { "BeaconFormatFree",             (LPVOID)BeaconFormatFree },
    { "BeaconFormatInt",              (LPVOID)BeaconFormatInt },
    { "BeaconUseToken",               (LPVOID)BeaconUseToken },
    { "BeaconRevertToken",            (LPVOID)BeaconRevertToken },
    { "BeaconIsAdmin",                (LPVOID)BeaconIsAdmin },
    { "toWideChar",                   (LPVOID)toWideChar },
    { "BeaconAddValue",               (LPVOID)BeaconAddValue },
    { "BeaconGetValue",               (LPVOID)BeaconGetValue },
    { "BeaconRemoveValue",            (LPVOID)BeaconRemoveValue },
    { "BeaconRegisterThreadCallback",  (LPVOID)BeaconRegisterThreadCallback },
    { "BeaconUnregisterThreadCallback",(LPVOID)BeaconUnregisterThreadCallback },
    { "BeaconWakeup",                 (LPVOID)BeaconWakeup },
    { "BeaconGetStopJobEvent",        (LPVOID)BeaconGetStopJobEvent },
    { "LoadLibraryA",                 (LPVOID)proxy_LoadLibraryA },
    { "GetModuleHandleA",             (LPVOID)proxy_GetModuleHandleA },
    { "FreeLibrary",                  (LPVOID)proxy_FreeLibrary },
    { "GetProcAddress",               (LPVOID)proxy_GetProcAddress },
    { "intAlloc",                     (LPVOID)intAlloc },
    { "intFree",                      (LPVOID)intFree },
    { "__C_specific_handler",         NULL },
};
#define BEACON_FUNCTIONS_COUNT (sizeof(BeaconFunctions) / sizeof(BOF_API_ENTRY))

static void* FindProcBySymbol(char* symbol) {
    if (!symbol) return NULL;
    char* cleanName = symbol;
    if (strncmp(symbol, "__imp_", 6) == 0) cleanName = symbol + 6;
    else if (strncmp(symbol, "__imp__", 7) == 0) cleanName = symbol + 7;
    if (cleanName[0] == '_') cleanName++;

    char nameBuf[1024] = {0};
    strncpy(nameBuf, cleanName, sizeof(nameBuf) - 1);
    char* at = strchr(nameBuf, '@');
    if (at) *at = 0;
    cleanName = nameBuf;

    for (DWORD i = 0; i < BEACON_FUNCTIONS_COUNT; i++) {
        if (!BeaconFunctions[i].proc) continue;
        if (strcmp(cleanName, BeaconFunctions[i].name) == 0)
            return BeaconFunctions[i].proc;
    }

    char* dollar = strchr(nameBuf, '$');
    if (dollar) {
        *dollar = 0;
        char* moduleName = nameBuf;
        char* funcName = dollar + 1;
        at = strchr(funcName, '@');
        if (at) *at = 0;
        HMODULE hMod = LoadLibraryA(moduleName);
        if (!hMod) {
            char dllName[270]; _snprintf(dllName, 270, "%s.dll", moduleName);
            hMod = LoadLibraryA(dllName);
        }
        if (hMod) {
            void* proc = (void*)GetProcAddress(hMod, funcName);
            if (proc) return proc;
        }
    }

    static HMODULE hMods[16] = { NULL };
    static bool inited = false;
    if (!inited) {
        hMods[0] = GetModuleHandleA(NULL);
        hMods[1] = GetModuleHandleA("kernel32.dll");
        hMods[2] = GetModuleHandleA("ntdll.dll");
        hMods[3] = LoadLibraryA("user32.dll");
        hMods[4] = LoadLibraryA("advapi32.dll");
        hMods[5] = LoadLibraryA("msvcrt.dll");
        hMods[6] = LoadLibraryA("ws2_32.dll");
        hMods[7] = LoadLibraryA("iphlpapi.dll");
        hMods[8] = LoadLibraryA("credui.dll");
        hMods[9] = LoadLibraryA("secur32.dll");
        hMods[10] = LoadLibraryA("ole32.dll");
        hMods[11] = LoadLibraryA("shlwapi.dll");
        inited = true;
    }
    for (int i = 0; i < 16 && hMods[i]; i++) {
        void* proc = (void*)GetProcAddress(hMods[i], cleanName);
        if (proc) return proc;
    }

    BeaconPrintf(CALLBACK_ERROR, "Failed to resolve symbol: %s\n", cleanName);
    return NULL;
}

static char* PrepareEntryName(char* targetFuncName) {
#if defined(_WIN64)
    size_t len = strlen(targetFuncName);
    char* out = (char*)LocalAlloc(LPTR, len + 1);
    if (out) memcpy(out, targetFuncName, len + 1);
    return out;
#else
    size_t len = strlen(targetFuncName);
    char* out = (char*)LocalAlloc(LPTR, len + 2);
    if (out) { out[0] = '_'; memcpy(out + 1, targetFuncName, len + 1); }
    return out;
#endif
}

static bool AllocateSections(unsigned char* coffFile, COF_HEADER* pHeader, PCHAR* mapSections) {
    for (int i = 0; i < pHeader->NumberOfSections; i++) {
        COF_SECTION* pSec = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + (sizeof(COF_SECTION) * i));
        mapSections[i] = (char*)VirtualAlloc(NULL, pSec->SizeOfRawData, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
        if (!mapSections[i] && pSec->SizeOfRawData) return FALSE;
        if (pSec->PointerToRawData) memcpy(mapSections[i], coffFile + pSec->PointerToRawData, pSec->SizeOfRawData);
        else memset(mapSections[i], 0, pSec->SizeOfRawData);
    }
    return TRUE;
}

static void CleanupSections(PCHAR* mapSections, int maxSections) {
    for (int i = 0; i < maxSections; i++) {
        if (mapSections[i]) { VirtualFree(mapSections[i], 0, MEM_RELEASE); mapSections[i] = NULL; }
    }
}

static bool ProcessRelocations(unsigned char* coffFile, COF_HEADER* pHeader, PCHAR* mapSections, COF_SYMBOL* pSymbolTable, LPVOID* mapFunctions) {
    bool status = TRUE;
    int  mapFunctionsSize = 0;
    int maxFunctions = MAP_FUNCTIONS_SIZE / sizeof(LPVOID);

    for (int si = 0; si < pHeader->NumberOfSections; si++) {
        COF_SECTION* pSec = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + (sizeof(COF_SECTION) * si));
        COF_RELOCATION* pRel = (COF_RELOCATION*)(coffFile + pSec->PointerToRelocations);

        for (int ri = 0; ri < pSec->NumberOfRelocations; ri++) {
            COF_SYMBOL sym = pSymbolTable[pRel->SymbolTableIndex];
            if (pRel->SymbolTableIndex >= pHeader->NumberOfSymbols) return FALSE;

            char  shortName[9] = {0};
            char* symName = NULL;
            if (sym.Name.dwName[0] == 0) {
                symName = ((char*)(pSymbolTable + pHeader->NumberOfSymbols)) + sym.Name.dwName[1];
            } else {
                if (sym.Name.cName[7] != 0) {
                    memcpy(shortName, sym.Name.cName, 8); shortName[8] = 0; symName = shortName;
                } else { symName = sym.Name.cName; }
            }

            int   offset = 0;
            void* procAddr = NULL;
#ifdef _WIN64
            unsigned long long bigOff = 0;
#endif

            if (sym.SectionNumber > 0) {
                procAddr = mapSections[sym.SectionNumber - 1] + sym.Value;
            } else if (sym.Value == 0 && (sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL || sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF)) {
                procAddr = FindProcBySymbol(symName);
                if (!procAddr) { status = FALSE; }
                else {
#ifdef _WIN64
                    if (mapFunctionsSize < maxFunctions) {
                        mapFunctions[mapFunctionsSize] = procAddr;
                        procAddr = &mapFunctions[mapFunctionsSize];
                        mapFunctionsSize++;
                    } else {
                        BeaconPrintf(CALLBACK_ERROR, "BOF exceeded max imports (%d)", maxFunctions);
                        status = FALSE;
                    }
#endif
                }
            } else { status = FALSE; }

            if (status) {
#ifdef _WIN64
                switch (pRel->Type) {
                case IMAGE_REL_AMD64_ADDR64:
                    memcpy(&bigOff, mapSections[si] + pRel->VirtualAddress, sizeof(unsigned long long));
                    bigOff += (unsigned long long)procAddr;
                    memcpy(mapSections[si] + pRel->VirtualAddress, &bigOff, sizeof(unsigned long long));
                    break;
                case IMAGE_REL_AMD64_ADDR32NB:
                    memcpy(&offset, mapSections[si] + pRel->VirtualAddress, sizeof(int));
                    offset = ((char*)(mapSections[sym.SectionNumber - 1] + offset) - (char*)(mapSections[si] + pRel->VirtualAddress + 4));
                    offset += pSymbolTable[pRel->SymbolTableIndex].Value;
                    memcpy(mapSections[si] + pRel->VirtualAddress, &offset, sizeof(int));
                    break;
                case IMAGE_REL_AMD64_REL32:
                case IMAGE_REL_AMD64_REL32_1:
                case IMAGE_REL_AMD64_REL32_2:
                case IMAGE_REL_AMD64_REL32_3:
                case IMAGE_REL_AMD64_REL32_4:
                case IMAGE_REL_AMD64_REL32_5: {
                    int ti = pRel->Type - 4;
                    memcpy(&offset, mapSections[si] + pRel->VirtualAddress, sizeof(int));
                    if (llabs((long long)procAddr - (long long)(mapSections[si] + pRel->VirtualAddress + 4 + ti)) > (long long)UINT_MAX) return FALSE;
                    offset += (int)((size_t)procAddr - (size_t)(mapSections[si] + pRel->VirtualAddress + 4 + ti));
                    memcpy(mapSections[si] + pRel->VirtualAddress, &offset, sizeof(int));
                    break;
                }
                default: status = FALSE; break;
                }
#else
                switch (pRel->Type) {
                case IMAGE_REL_I386_DIR32:
                    memcpy(&offset, mapSections[si] + pRel->VirtualAddress, sizeof(int));
                    offset = (unsigned int)procAddr + offset;
                    memcpy(mapSections[si] + pRel->VirtualAddress, &offset, sizeof(unsigned int));
                    break;
                case IMAGE_REL_I386_REL32:
                    memcpy(&offset, mapSections[si] + pRel->VirtualAddress, sizeof(int));
                    offset = (unsigned int)procAddr - (unsigned int)(mapSections[si] + pRel->VirtualAddress + 4);
                    memcpy(mapSections[si] + pRel->VirtualAddress, &offset, sizeof(unsigned int));
                    break;
                default: status = FALSE; break;
                }
#endif
            }
            pRel = (COF_RELOCATION*)((char*)pRel + sizeof(COF_RELOCATION));
        }
    }
    return status;
}

static void ExecuteProc(char* entryName, unsigned char* args, int argsSize, COF_SYMBOL* pSymTab, COF_HEADER* pHeader, PCHAR* mapSections) {
    char nameBuf[256] = {0};
    for (int i = 0; i < pHeader->NumberOfSymbols; i++) {
        if (pSymTab[i].Name.dwName[0] == 0) {
            char* n = ((char*)(pSymTab + pHeader->NumberOfSymbols)) + pSymTab[i].Name.dwName[1];
            strncpy(nameBuf, n, sizeof(nameBuf) - 1);
        } else {
            memcpy(nameBuf, pSymTab[i].Name.cName, 8); nameBuf[8] = 0;
        }

        if (strcmp(nameBuf, entryName) == 0) {
            void(*proc)(char*, unsigned long) = (void(*)(char*, unsigned long))(mapSections[pSymTab[i].SectionNumber - 1] + pSymTab[i].Value);
            proc((char*)args, argsSize);
            return;
        }
    }
    BeaconPrintf(CALLBACK_ERROR, "Entry point '%s' not found\n", entryName);
}

Packer* ObjectExecute(ULONG taskId, char* targetFuncName, unsigned char* coffFile, unsigned int cofFileSize, unsigned char* args, int argsSize) {
    COF_HEADER* pHeader = NULL; COF_SYMBOL* pSymTab = NULL;
    char* entryName = NULL; LPVOID* mapFunctions = NULL;
    PCHAR mapSections[MAX_SECTIONS] = {0};

    InitBofOutputData();
    bofTaskId = taskId;

    if (!coffFile || !targetFuncName) goto RET;

    pHeader = (COF_HEADER*)coffFile;
    pSymTab = (COF_SYMBOL*)(coffFile + pHeader->PointerToSymbolTable);
    entryName = PrepareEntryName(targetFuncName);
    if (!entryName) goto RET;

    if (!AllocateSections(coffFile, pHeader, mapSections)) {
        BeaconPrintf(CALLBACK_ERROR, "Section allocation failed\n");
        goto RET;
    }

    mapFunctions = (LPVOID*)VirtualAlloc(NULL, MAP_FUNCTIONS_SIZE, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
    if (!mapFunctions) goto RET;

    if (!ProcessRelocations(coffFile, pHeader, mapSections, pSymTab, mapFunctions))
        goto RET;

    // W^X Compliance: Set memory protections based on section characteristics
    for (int i = 0; i < pHeader->NumberOfSections; i++) {
        COF_SECTION* pSec = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + (sizeof(COF_SECTION) * i));
        if (mapSections[i] && pSec->SizeOfRawData > 0) {
            DWORD oldProtect;
            DWORD newProtect = PAGE_READONLY; // Default

            bool isExec = (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isWrite = (pSec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            bool isRead = (pSec->Characteristics & IMAGE_SCN_MEM_READ) != 0;

            if (isExec && isWrite) newProtect = PAGE_EXECUTE_READWRITE;
            else if (isExec && isRead) newProtect = PAGE_EXECUTE_READ;
            else if (isWrite && isRead) newProtect = PAGE_READWRITE;
            else if (isExec) newProtect = PAGE_EXECUTE;
            else if (isWrite) newProtect = PAGE_WRITECOPY;

            VirtualProtect(mapSections[i], pSec->SizeOfRawData, newProtect, &oldProtect);
        }
    }

    __try {
        ExecuteProc(entryName, args, argsSize, pSymTab, pHeader, mapSections);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        const char* err_msg = "\n[CRASH] BOF caused an exception but the beacon survived.\n";
        bofOutputPacker->Pack32(CALLBACK_ERROR);
        bofOutputPacker->PackBytes((PBYTE)err_msg, (ULONG)strlen(err_msg));
    }

RET:
    if (mapFunctions) VirtualFree(mapFunctions, 0, MEM_RELEASE);
    if (entryName) LocalFree(entryName);
    CleanupSections(mapSections, MAX_SECTIONS);
    bofTaskId = 0;
    return bofOutputPacker;
}

// ==========================================
// Standalone Main & Arg Packer
// ==========================================
unsigned char* BuildArgs(int argc, char** argv, int* outSize) {
    std::vector<std::vector<unsigned char>> argBuffers;
    int totalSize = 0;

    for (int i = 3; i < argc; i++) {
        std::string s = argv[i];
        std::vector<unsigned char> buf;

        if (s.rfind("i:", 0) == 0) {
            int val = std::stoi(s.substr(2));
            buf.resize(4);
            memcpy(buf.data(), &val, 4);
        } else if (s.rfind("s:", 0) == 0) {
            std::string str = s.substr(2);
            int len = str.length() + 1;
            buf.resize(4 + len);
            memcpy(buf.data(), &len, 4);
            memcpy(buf.data() + 4, str.c_str(), str.length());
            buf[4 + str.length()] = 0;
        } else if (s.rfind("w:", 0) == 0) {
            std::string str = s.substr(2);
            std::wstring wstr(str.begin(), str.end());
            int len = (wstr.length() + 1) * 2;
            buf.resize(4 + len);
            memcpy(buf.data(), &len, 4);
            memcpy(buf.data() + 4, wstr.c_str(), len);
        } else if (s.rfind("f:", 0) == 0) {
            // FIX: File handler! Reads file from disk and packs raw bytes.
            std::string filePath = s.substr(2);
            FILE* f = fopen(filePath.c_str(), "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                long fileSize = ftell(f);
                fseek(f, 0, SEEK_SET);
                
                buf.resize(4 + fileSize);
                memcpy(buf.data(), &fileSize, 4); // Pack size first
                fread(buf.data() + 4, 1, fileSize, f); // Pack raw bytes
                fclose(f);
            } else {
                fprintf(stderr, "[-] Failed to open file: %s\n", filePath.c_str());
                exit(1);
            }
        } else {
            // Auto-infer
            bool isNumber = true;
            for (char c : s) {
                if (!isdigit(c)) { isNumber = false; break; }
            }
            if (isNumber && !s.empty()) {
                int val = std::stoi(s);
                buf.resize(4);
                memcpy(buf.data(), &val, 4);
            } else {
                int len = s.length() + 1;
                buf.resize(4 + len);
                memcpy(buf.data(), &len, 4);
                memcpy(buf.data() + 4, s.c_str(), s.length());
                buf[4 + s.length()] = 0;
            }
        }
        totalSize += buf.size();
        argBuffers.push_back(buf);
    }

    *outSize = 4 + totalSize;
    unsigned char* finalBuf = (unsigned char*)calloc(1, *outSize);
    memcpy(finalBuf, &totalSize, 4);
    int offset = 4;
    for (auto& b : argBuffers) {
        memcpy(finalBuf + offset, b.data(), b.size());
        offset += b.size();
    }
    return finalBuf;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: bof_loader.exe <obj_file> <entry_point> [args...]\n");
        printf("Argument formats:\n");
        printf("  i:1234       (Integer)\n");
        printf("  s:Hello      (String)\n");
        printf("  w:Hello      (Wide String)\n");
        printf("  f:C:\\path\\file.exe (File - reads raw bytes into buffer)\n"); // Added documentation for f:
        printf("  1234         (Auto-inferred Integer)\n");
        printf("  Hello        (Auto-inferred String)\n");
        printf("  \"Hello World\" (String with spaces)\n");
        return 1;
    }

    const char* obj_file = argv[1];
    const char* entry_point = argv[2];

    // Read BOF file
    FILE* f = fopen(obj_file, "rb");
    if (!f) {
        fprintf(stderr, "[-] Failed to open %s\n", obj_file);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc(size);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, size, f);
    fclose(f);

    // Pack arguments
    int argsSize = 0;
    unsigned char* packedArgs = BuildArgs(argc, argv, &argsSize);

    // Execute BOF
    Packer* out = ObjectExecute(0, (char*)entry_point, buf, size, packedArgs, argsSize);

    // Print output
    if (out) {
        BYTE* data = out->data();
        ULONG outSize = out->datasize();
        ULONG index = 0;
        while (index + 8 <= outSize) {
            ULONG type = *(ULONG*)(data + index);
            ULONG len = *(ULONG*)(data + index + 4);
            index += 8;
            if (index + len <= outSize) {
                if (type == CALLBACK_OUTPUT || type == CALLBACK_OUTPUT_OEM || type == CALLBACK_OUTPUT_UTF8) {
                    printf("%.*s", len, (char*)(data + index));
                } else if (type == CALLBACK_ERROR) {
                    fprintf(stderr, "[ERROR] %.*s\n", len, (char*)(data + index));
                }
            }
            index += len;
        }
    }

    free(buf);
    free(packedArgs);
    return 0;
}