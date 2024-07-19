#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <Dbghelp.h>
#include <iostream>
#include <string>
#include "Psapi.h"
#include "urlmon.h"
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib, "Dbghelp.lib") 


#define MODE_LOADLIBRARYA 0
#define MODE_LOADLIBRARYEXA 1
#define MODE_LDRLOADDLL 2
#define MODE_LDRPLOADDLL 3
#define MODE_LDRPLOADDLLINTERNAL 4
#define MODE_LDRPPROCESSWORK 5

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

struct LDR_UNKSTRUCT
{
	PWSTR pInitNameMaybe;
	__declspec(align(16)) PWSTR Buffer;
	int Flags;
	PWSTR pDllName;
	char Pad1[84];
	BOOLEAN IsInitedMaybe;
	char Pad2[3];
};
typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(
	_In_ PVOID DllHandle,
	_In_ ULONG Reason,
	_In_opt_ PVOID Context
	);
typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;
typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;
typedef enum _LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;
typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union
	{
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY* RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY* CondenseLink;
	ULONG PreorderNumber;
	ULONG Pad;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;
typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x4
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x8
			UCHAR Balance : 2;                                                //0x8
		};
		ULONG ParentValue;                                                  //0x8
	};
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;
typedef enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonEnclavePrimary, // since REDSTONE3
	LoadReasonEnclaveDependency,
	LoadReasonPatchImage, // since WIN11
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;
typedef enum _LDR_HOT_PATCH_STATE
{
	LdrHotPatchBaseImage,
	LdrHotPatchNotApplied,
	LdrHotPatchAppliedReverse,
	LdrHotPatchAppliedForward,
	LdrHotPatchFailedToPatch,
	LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PIMAGE_DOS_HEADER DllBase;
	PLDR_INIT_ROUTINE EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ChpeEmulatorImage : 1;
			ULONG ReservedFlags5 : 1;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID Lock; // RtlAcquireSRWLockExclusive
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason; // since WIN8
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount; // since WIN10
	ULONG DependentLoadFlags;
	UCHAR SigningLevel; // since REDSTONE2
	ULONG CheckSum; // since 22H1
	PVOID ActivePatchImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDRP_LOAD_CONTEXT
{
	UNICODE_STRING BaseDllName;
	LDR_UNKSTRUCT* UnkStruct;
	HANDLE SectionHandle;
	DWORD Flags;
	NTSTATUS* pStatus;
	LDR_DATA_TABLE_ENTRY* Entry;
	_LIST_ENTRY WorkQueueListEntry;
	LDR_DATA_TABLE_ENTRY* ReplacedEntry;
	LDR_DATA_TABLE_ENTRY** pvImports;
	LDR_DATA_TABLE_ENTRY** IATCheck;
	PVOID pvIAT;
	ULONG SizeOfIAT;
	ULONG CurrentDll;
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	ULONG ImageImportDescriptorLen;
	__declspec(align(8)) ULONG OriginalIATProtect;
	PVOID GuardCFCheckFunctionPointer;
	__int64 GuardFlags;
	__int64 DllNameLenCompare;
	__int64 UnknownFunc;
	SIZE_T Size;
	__int64 UnknownPtr;
	HANDLE FileHandle;
	PIMAGE_DOS_HEADER ImageBase;
	wchar_t BaseDllNameBuffer[260];
} LDRP_LOAD_CONTEXT, * PLDRP_LOAD_CONTEXT;

typedef NTSTATUS(WINAPI* pLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
typedef NTSTATUS(__fastcall* pRtlInitUnicodeStringEx)(PUNICODE_STRING target, PCWSTR source);
typedef NTSTATUS(__fastcall* pLdrpLoadDll)(PUNICODE_STRING DllName, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, LDR_DATA_TABLE_ENTRY** DllEntry);
typedef NTSTATUS(WINAPI* pfnLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
typedef NTSTATUS(__fastcall* pLdrpLoadDllInternal)(PUNICODE_STRING FullPath, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY LdrEntry2, PLDR_DATA_TABLE_ENTRY* DllEntry, NTSTATUS* pStatus);
typedef NTSTATUS(__fastcall* pLdrpInitializeDllPath)(PWSTR DllName, PWSTR DllPath, LDR_UNKSTRUCT* DllPathInited);
typedef NTSTATUS(__fastcall* pLdrpPreprocessDllName)(PUNICODE_STRING DllName, PUNICODE_STRING ResName, PULONG pZero, PULONG pFlags);
typedef NTSTATUS(__fastcall* pLdrpFindOrPrepareLoadingModule)(PUNICODE_STRING FullPath, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY* pLdrEntryLoaded, NTSTATUS* pStatus);
typedef NTSTATUS(__fastcall* pLdrpProcessWork)(PLDRP_LOAD_CONTEXT LoadContext, BOOLEAN IsLoadOwner);

bool GetPdbSignature(const std::string& dllPath, GUID& pdbGuid, DWORD& pdbAge) {
	if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
		return false;
	}
	HMODULE hModule = LoadLibraryExA(dllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hModule) {
		SymCleanup(GetCurrentProcess());
		return false;
	}
	MODULEINFO modInfo;
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
		FreeLibrary(hModule);
		SymCleanup(GetCurrentProcess());
		return false;
	}
	DWORD64 baseAddr = reinterpret_cast<DWORD64>(modInfo.lpBaseOfDll);
	IMAGEHLP_MODULE64 moduleInfo;
	ZeroMemory(&moduleInfo, sizeof(moduleInfo));
	moduleInfo.SizeOfStruct = sizeof(moduleInfo);

	if (!SymGetModuleInfo64(GetCurrentProcess(), (DWORD64)modInfo.lpBaseOfDll, &moduleInfo)) {
		FreeLibrary(hModule);
		SymCleanup(GetCurrentProcess());
		return false;
	}
	pdbGuid = moduleInfo.PdbSig70;
	pdbAge = moduleInfo.PdbAge;
	FreeLibrary(hModule);
	SymCleanup(GetCurrentProcess());

	return true;
}

bool downloadDebugSymbols(const std::wstring& guid, const std::wstring& filename) {
	std::wstring baseUrl = L"https://msdl.microsoft.com/download/symbols";
	std::wstring pdbUrl = baseUrl + L"/" + filename + L"/" + guid + L"/" + filename;

	HRESULT hr = URLDownloadToFileW(
		NULL,
		pdbUrl.c_str(),
		filename.c_str(),
		0,
		NULL
	);

	return SUCCEEDED(hr);
}

FARPROC GetAddressFromSymbols(HANDLE hProcess, LPCSTR fullModulePath, LPCSTR pdbPath, LPCSTR lpProcName) {
	if (!SymInitialize(hProcess, NULL, TRUE)) {
		printf("SymInitialize failed: %lu\n", GetLastError());
		return 0;
	}
	if (!SymSetSearchPath(hProcess, pdbPath)) {
		printf("SymSetSearchPath failed: %lu\n", GetLastError());
		SymCleanup(hProcess);
		return 0;
	}
	DWORD64 baseOfDll = SymLoadModuleEx(hProcess, NULL, fullModulePath, NULL, 0, 0, NULL, 0);
	if (baseOfDll == 0) {
		printf("SymLoadModuleEx failed: %lu\n", GetLastError());
		SymCleanup(hProcess);
		return 0;
	}
	SYMBOL_INFO* symbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR));
	symbol->MaxNameLen = MAX_SYM_NAME;
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	if (SymFromName(hProcess, lpProcName, symbol)) {
		printf("Symbol found: %s at address 0x%0llX\n", symbol->Name, symbol->Address);
		FARPROC result = (FARPROC)symbol->Address;
		free(symbol);
		SymCleanup(hProcess);
		return result;
	}
	else {
		printf("SymFromName failed: %lu\n", GetLastError());
	}
	free(symbol);
	SymCleanup(hProcess);
	return 0;
}


typedef int (WINAPI* MessageBoxWFunc)(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
	);
const wchar_t* GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}
int main()
{
	//CONFIG START
	//SELECT MODE AND DLL NAME TO LOAD
	int mode = MODE_LDRPPROCESSWORK;
	char dllName[] = "user32.dll";
	//CONFIG END

	GUID pdbGuid;
	DWORD pdbAge;

	std::string dllPath = "ntdll.dll";
	GetPdbSignature(dllPath, pdbGuid, pdbAge);

	wchar_t guid_string[MAX_PATH] = {};


	swprintf(
		guid_string, sizeof(guid_string) / sizeof(guid_string[0]),
		L"%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%01x",
		pdbGuid.Data1, pdbGuid.Data2, pdbGuid.Data3,
		pdbGuid.Data4[0], pdbGuid.Data4[1], pdbGuid.Data4[2],
		pdbGuid.Data4[3], pdbGuid.Data4[4], pdbGuid.Data4[5],
		pdbGuid.Data4[6], pdbGuid.Data4[7], pdbAge);

	bool success = downloadDebugSymbols(guid_string, L"ntdll.pdb");
	HMODULE hNtDll = NULL;
	hNtDll = LoadLibraryA("ntdll.dll");
	pRtlInitUnicodeStringEx RtlInitUnicodeStringEx = (pRtlInitUnicodeStringEx)GetProcAddress(hNtDll, "RtlInitUnicodeStringEx");

	HMODULE hResModule = NULL;


	switch (mode)
	{
	case MODE_LOADLIBRARYA: {
		hResModule = LoadLibraryA(dllName);
		break;
	}
	case MODE_LOADLIBRARYEXA: {
		hResModule = LoadLibraryExA(dllName, 0, 0);
		break;
	}
	case MODE_LDRLOADDLL: {
		pLdrLoadDll fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(hNtDll, "LdrLoadDll");
		UNICODE_STRING ModuleFileName;
		RtlInitUnicodeStringEx(&ModuleFileName, GetWC(dllName));
		HANDLE hModule = NULL;
		NTSTATUS status = fnLdrLoadDll((PWSTR)(0x7F08 | 1), 0, &ModuleFileName, &hModule);
		break;
	}
	case MODE_LDRPLOADDLL: {
		LDR_UNKSTRUCT someStruct = {};
		LDR_DATA_TABLE_ENTRY* DllEntry = {};
		ULONG flags = 0;
		UNICODE_STRING uniDllName;
		RtlInitUnicodeStringEx(&uniDllName, GetWC(dllName));
		pLdrpInitializeDllPath ldrpInitializeDllPath = (pLdrpInitializeDllPath)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpInitializeDllPath"));
		ldrpInitializeDllPath(uniDllName.Buffer, (PWSTR)(0x7F08 | 1), &someStruct);
		pLdrpLoadDll ldrpLoadDll = (pLdrpLoadDll)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpLoadDll"));
		ldrpLoadDll(&uniDllName, &someStruct, NULL, &DllEntry);
		break;
	}
	case MODE_LDRPLOADDLLINTERNAL: {
		LDR_UNKSTRUCT someStruct = {};
		LDR_DATA_TABLE_ENTRY* DllEntry = {};
		ULONG flags = 0;
		UNICODE_STRING uniDllName;
		RtlInitUnicodeStringEx(&uniDllName, GetWC(dllName));
		UNICODE_STRING FullDllPath;
		WCHAR Buffer[128];
		FullDllPath.Length = 0;
		FullDllPath.MaximumLength = MAX_PATH - 4;
		FullDllPath.Buffer = Buffer;
		Buffer[0] = 0;
		pLdrpPreprocessDllName ldrpPreprocessDllName = (pLdrpPreprocessDllName)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpPreprocessDllName"));
		pLdrpLoadDllInternal ldrpLoadDllInternal = (pLdrpLoadDllInternal)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpLoadDllInternal"));

		NTSTATUS res = ldrpPreprocessDllName(&uniDllName, &FullDllPath, 0, &flags);
		ldrpLoadDllInternal(&FullDllPath, &someStruct, flags, 0x4, 0, 0, &DllEntry, &res);

		break;
	}
	case MODE_LDRPPROCESSWORK: {
		LDR_DATA_TABLE_ENTRY* pLdrEntryLoaded = 0;
		LDR_UNKSTRUCT undefStruct = {};
		UNICODE_STRING uniDllName;
		RtlInitUnicodeStringEx(&uniDllName, GetWC(dllName));
		pLdrpInitializeDllPath ldrpInitializeDllPath = (pLdrpInitializeDllPath)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpInitializeDllPath"));
		ldrpInitializeDllPath(uniDllName.Buffer, (PWSTR)(0x7F08 | 1), &undefStruct);
		ULONG flags = 0;
		UNICODE_STRING FullDllPath;
		WCHAR Buffer[128];
		FullDllPath.Length = 0;
		FullDllPath.MaximumLength = MAX_PATH - 4;
		FullDllPath.Buffer = Buffer;
		Buffer[0] = 0;
		pLdrpPreprocessDllName ldrpPreprocessDllName = (pLdrpPreprocessDllName)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpPreprocessDllName"));
		NTSTATUS res = ldrpPreprocessDllName(&uniDllName, &FullDllPath, 0, &flags);
		pLdrpFindOrPrepareLoadingModule ldrpFindOrPrepareLoadingModule = (pLdrpFindOrPrepareLoadingModule)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpFindOrPrepareLoadingModule"));
		NTSTATUS Status = ldrpFindOrPrepareLoadingModule(&FullDllPath, &undefStruct, flags, 0x4, 0, &pLdrEntryLoaded, &res);
		pLdrpProcessWork ldrpProcessWork = (pLdrpProcessWork)(GetAddressFromSymbols(GetCurrentProcess(), "C:\\Windows\\System32\\ntdll.dll", "./ntdll.pdb", "LdrpProcessWork"));

		if (Status == STATUS_DLL_NOT_FOUND)
			NTSTATUS res = ldrpProcessWork(pLdrEntryLoaded->LoadContext, TRUE);
		break;
	}

	}
	MessageBoxWFunc MessageBoxWPtr = (MessageBoxWFunc)(GetProcAddress(GetModuleHandleA(dllName), "MessageBoxW"));
	MessageBoxWPtr(NULL, L":)", L"FunnyWhale", MB_OK);

	return 0;
}