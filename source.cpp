typedef unsigned char   undefined;

typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef unsigned short    wchar16;
typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo * LPCPINFO;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

typedef ulong DWORD;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef ushort WORD;

typedef BYTE * LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOW * LPSTARTUPINFOW;

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAW * LPWIN32_FIND_DATAW;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT * PCONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef char * va_list;

typedef uint uintptr_t;

typedef struct lconv lconv, *Plconv;

struct lconv {
    char * decimal_point;
    char * thousands_sep;
    char * grouping;
    char * int_curr_symbol;
    char * currency_symbol;
    char * mon_decimal_point;
    char * mon_thousands_sep;
    char * mon_grouping;
    char * positive_sign;
    char * negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t * _W_decimal_point;
    wchar_t * _W_thousands_sep;
    wchar_t * _W_int_curr_symbol;
    wchar_t * _W_currency_symbol;
    wchar_t * _W_mon_decimal_point;
    wchar_t * _W_mon_thousands_sep;
    wchar_t * _W_positive_sign;
    wchar_t * _W_negative_sign;
};

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct * pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount {
    char * locale;
    wchar_t * wlocale;
    int * refcount;
    int * wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int * lconv_intl_refcount;
    int * lconv_num_refcount;
    int * lconv_mon_refcount;
    struct lconv * lconv;
    int * ctype1_refcount;
    ushort * ctype1;
    ushort * pctype;
    uchar * pclmap;
    uchar * pcumap;
    struct __lc_time_data * lc_time_curr;
    wchar_t * locale_name[6];
};

struct __lc_time_data {
    char * wday_abbr[7];
    char * wday[7];
    char * month_abbr[12];
    char * month[12];
    char * ampm[2];
    char * ww_sdatefmt;
    char * ww_ldatefmt;
    char * ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t * _W_wday_abbr[7];
    wchar_t * _W_wday[7];
    wchar_t * _W_month_abbr[12];
    wchar_t * _W_month[12];
    wchar_t * _W_ampm[2];
    wchar_t * _W_ww_sdatefmt;
    wchar_t * _W_ww_ldatefmt;
    wchar_t * _W_ww_timefmt;
    wchar_t * _W_ww_locale_name;
};

typedef uint size_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct * pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t * mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef struct localeinfo_struct * _locale_t;

typedef size_t rsize_t;

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_226 _union_226, *P_union_226;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS;

typedef char CHAR;

typedef CHAR * LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef struct _MEMORY_BASIC_INFORMATION * PMEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef CHAR * LPSTR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _IMAGE_SECTION_HEADER * PIMAGE_SECTION_HEADER;

typedef WCHAR * LPCWSTR;

typedef LARGE_INTEGER * PLARGE_INTEGER;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[16]; // Actual DOS program
};

typedef ULONG_PTR DWORD_PTR;

typedef DWORD * LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef struct _FILETIME * LPFILETIME;

typedef int (* FARPROC)(void);

typedef HANDLE * LPHANDLE;

typedef WORD * LPWORD;

typedef BOOL * LPBOOL;

typedef BYTE * PBYTE;

typedef void * LPCVOID;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
};

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

struct _is_ctype_compatible {
    ulong id;
    int is_clike;
};

struct setloc_struct {
    wchar_t * pchLanguage;
    wchar_t * pchCountry;
    int iLocState;
    int iPrimaryLen;
    BOOL bAbbrevLanguage;
    BOOL bAbbrevCountry;
    UINT _cachecp;
    wchar_t _cachein[131];
    wchar_t _cacheout[131];
    struct _is_ctype_compatible _Loc_c[5];
    wchar_t _cacheLocaleName[85];
};

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct setloc_struct _setloc_struct;

struct _tiddata {
    ulong _tid;
    uintptr_t _thandle;
    int _terrno;
    ulong _tdoserrno;
    uint _fpds;
    ulong _holdrand;
    char * _token;
    wchar_t * _wtoken;
    uchar * _mtoken;
    char * _errmsg;
    wchar_t * _werrmsg;
    char * _namebuf0;
    wchar_t * _wnamebuf0;
    char * _namebuf1;
    wchar_t * _wnamebuf1;
    char * _asctimebuf;
    wchar_t * _wasctimebuf;
    void * _gmtimebuf;
    char * _cvtbuf;
    uchar _con_ch_buf[5];
    ushort _ch_buf_used;
    void * _initaddr;
    void * _initarg;
    void * _pxcptacttab;
    void * _tpxcptinfoptrs;
    int _tfpecode;
    pthreadmbcinfo ptmbcinfo;
    pthreadlocinfo ptlocinfo;
    int _ownlocale;
    ulong _NLG_dwCode;
    void * _terminate;
    void * _unexpected;
    void * _translator;
    void * _purecall;
    void * _curexception;
    void * _curcontext;
    int _ProcessingThrow;
    void * _curexcspec;
    void * _pFrameInfoChain;
    _setloc_struct _setloc_data;
    void * _reserved1;
    void * _reserved2;
    void * _reserved3;
    void * _reserved4;
    void * _reserved5;
    int _cxxReThrow;
    ulong __initDomain;
    int _initapartment;
};

typedef struct _tiddata * _ptiddata;

typedef dword unsigned_long;

typedef struct __crt_multibyte_data __crt_multibyte_data, *P__crt_multibyte_data;

struct __crt_multibyte_data { // PlaceHolder Structure
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};


// WARNING! conflicting data type names: /Demangler/wchar_t - /wchar_t

typedef dword unsigned_char;

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef dword unsigned_int;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef struct _Iostream_error_category _Iostream_error_category, *P_Iostream_error_category;

struct _Iostream_error_category { // PlaceHolder Structure
};

typedef struct _System_error_category _System_error_category, *P_System_error_category;

struct _System_error_category { // PlaceHolder Structure
};

typedef struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>, *Pbasic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>;

struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> { // PlaceHolder Structure
};

typedef struct error_condition error_condition, *Perror_condition;

struct error_condition { // PlaceHolder Structure
};

typedef struct error_category error_category, *Perror_category;

struct error_category { // PlaceHolder Structure
};

typedef struct error_code error_code, *Perror_code;

struct error_code { // PlaceHolder Structure
};

typedef struct SchedulerPolicy SchedulerPolicy, *PSchedulerPolicy;

struct SchedulerPolicy { // PlaceHolder Structure
};




void InitializeGlobalStructAndVerify(void)

{
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621ba08;
  *in_FS_OFFSET = &s10;
  DAT_6624b4d8 = allocate_initialized_struct101();
  s8 = 0xffffffff;
  CheckPointerAppendedSuccessfully(FUN_6621bb80);
  *in_FS_OFFSET = s10;
  return;
}



undefined4 returnzero(void)

{
  return 0;
}



void __thiscall WGetContext(void *this,short **param_1)

{
                    // This is a wrapper
  get_context(this,param_1);
  return;
}



void HandleBootErrorAndTerminate(int param_1,short *param_2)

{
  code *pcVar1;
  
  DisplayConfigurableMessageBox
            (u_ThinApp_Boot_Loader_Error_6621c2c8,param_1,param_2,&stack0x0000000c,0x10);
  SafeShutdownWithExit(0xfffffffd);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void SafeShutdownWithExit(UINT param_1)

{
  __DllMainCRTStartup_12(0,0,0);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



undefined4 ThinAppBootstrapAndLaunch(void)

{
  HMODULE pHVar1;
  undefined4 uVar1;
  DWORD DVar1;
  uint uVar2;
  size_t sVar1;
  short **context_blob;
  ushort *has_offset;
  short *sanity_check_parameter;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  undefined auStack1664 [128];
  undefined4 uStack1536;
  undefined4 uStack1532;
  int iStack1528;
  short *psStack1524;
  short *psStack1520;
  short *psStack1516;
  short *psStack1512;
  short *psVar1;
  int iVar1;
  
  init_proc();
  sanity_check_parameter = (short *)0x0;
  pHVar1 = GetModuleHandleW((LPCWSTR)0x0);
  LogModuleLoadEvent(u_boot_loader_exe_6621c2fc,pHVar1,(undefined *)0x0);
  reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x310));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  uVar1 = DynamicBufferCallbackHandler
                    (GetModuleFileNameW_exref,(undefined4 *)(unaff_EBP + -0x310),pHVar1);
  if ((char)uVar1 != '\0') goto LAB_66201169;
  psVar1 = (short *)0x0;
  DVar1 = GetLastError();
  do {
    HandleBootErrorAndTerminate(DVar1,psVar1);
LAB_66201169:
    reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x470));
    *(undefined *)(unaff_EBP + -4) = 1;
    cleanup_ctxblob(&stack0xfffff97c,(short **)(unaff_EBP + -0x310));
    uVar2 = ExecuteAppSyncUpdateWorkflow();
    if ((char)uVar2 != '\0') {
      iVar1 = -1;
      psVar1 = (short *)find_backslash((int *)(unaff_EBP + -0x310));
      pass_context_to_handler((void *)(unaff_EBP + -0xd0),psVar1,iVar1);
      iVar1 = *(int *)(unaff_EBP + -0xcc);
      *(undefined *)(unaff_EBP + -4) = 2;
      sVar1 = _wcslen((wchar_t *)&DAT_6621c31c);
      context_blob = (short **)
                     cleanupmemstate((void *)(unaff_EBP + -0xd0),(void *)(unaff_EBP + -0x5d0),
                                     (short *)(iVar1 - sVar1));
      *(undefined *)(unaff_EBP + -4) = 3;
      get_context((void *)(unaff_EBP + -0xd0),context_blob);
      *(undefined *)(unaff_EBP + -4) = 2;
      manage_memstate((void **)(unaff_EBP + -0x5d0));
      psStack1512 = (short *)0x6620121e;
      invoke_qhandler((void *)(unaff_EBP + -0xd0),'\x01',(short *)&DAT_6621c324,-1,
                      (int)sanity_check_parameter,(undefined4 *)sanity_check_parameter);
      psStack1512 = (short *)0x66201239;
      invoke_qhandler((void *)(unaff_EBP + -0x470),'\x01',*(short **)(unaff_EBP + -0xd0),
                      *(int *)(unaff_EBP + -0xcc),(int)sanity_check_parameter,
                      (undefined4 *)sanity_check_parameter);
      cleanup_ctxblob(auStack1664,(short **)(unaff_EBP + -0x470));
      HandleApplicationUpdateAndRestart();
      *(undefined *)(unaff_EBP + -4) = 1;
      manage_memstate((void **)(unaff_EBP + -0xd0));
    }
    InitializeExtendedObjectState((undefined4 *)(unaff_EBP + -0x260));
    *(undefined *)(unaff_EBP + -4) = 4;
    iVar1 = LoadAndVerifyThinAppPackage
                      ((void *)(unaff_EBP + -0x260),*(short **)(unaff_EBP + -0x310),'\x01',
                       (void *)0xa0100000,sanity_check_parameter);
    if (-1 < iVar1) goto LAB_662012ac;
    do {
      psVar1 = *(short **)(unaff_EBP + -0x260);
      iVar1 = RtlNtStatusToDosError();
      HandleBootErrorAndTerminate(iVar1,psVar1);
LAB_662012ac:
      reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x520));
      iVar1 = -1;
      *(undefined *)(unaff_EBP + -4) = 5;
      has_offset = FUN_662048b0(*(void **)(unaff_EBP + -0xe8),u_UpgradePath_6621c374);
      safeget_ctxblob((void *)(unaff_EBP + -0x520),(short *)has_offset,iVar1);
      reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x3c0));
      *(undefined *)(unaff_EBP + -4) = 6;
      uVar2 = CheckForUpdatedDatFile();
      if ((char)uVar2 == '\0') {
        update_context((void *)(unaff_EBP + -0x3c0),(uint)sanity_check_parameter);
        LaunchUpdatedOrOriginalProcess();
      }
      if (*(int *)(unaff_EBP + -0x3bc) == 0) break;
      FUN_66204b90((void **)(unaff_EBP + -0x260));
      iVar1 = LoadAndVerifyThinAppPackage
                        ((void *)(unaff_EBP + -0x260),*(short **)(unaff_EBP + -0x310),'\x01',
                         (void *)0xa0100000,*(short **)(unaff_EBP + -0x3c0));
    } while (iVar1 < 0);
    SetEnvironmentVariableW(u_TS_ORIGIN_6621c38c,*(LPCWSTR *)(unaff_EBP + -0x260));
    iStack1528 = unaff_EBP + -0x260;
    uStack1532 = *(undefined4 *)(unaff_EBP + -0x260);
    uStack1536 = 0x6620138f;
    psStack1524 = sanity_check_parameter;
    psStack1520 = sanity_check_parameter;
    psStack1516 = sanity_check_parameter;
    psStack1512 = sanity_check_parameter;
    iVar1 = FUN_66205330();
    psVar1 = sanity_check_parameter;
    if (-1 < iVar1) {
      sanity_check_parameter = *(short **)(unaff_EBP + -0xf0);
      *(undefined4 *)(unaff_EBP + -0x10) = *(undefined4 *)(unaff_EBP + -0x260);
      *(undefined4 *)(unaff_EBP + -0x14) = 0xfffffffc;
      GetCommandLineW();
      psStack1512 = *(short **)(unaff_EBP + -0x10);
      psStack1516 = *(short **)(unaff_EBP + -0x18);
      psStack1520 = *(short **)(unaff_EBP + -0x1c);
      psStack1524 = (short *)0x662013df;
      iVar1 = (**(code **)(unaff_EBP + -0x20))();
      if (-1 < iVar1) {
        uVar1 = *(undefined4 *)(unaff_EBP + -0x14);
        *(undefined *)(unaff_EBP + -4) = 5;
        manage_memstate((void **)(unaff_EBP + -0x3c0));
        *(undefined *)(unaff_EBP + -4) = 4;
        manage_memstate((void **)(unaff_EBP + -0x520));
        *(undefined *)(unaff_EBP + -4) = 1;
        FUN_66204a40((void **)(unaff_EBP + -0x260));
        *(undefined *)(unaff_EBP + -4) = 0;
        manage_memstate((void **)(unaff_EBP + -0x470));
        *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
        manage_memstate((void **)(unaff_EBP + -0x310));
        *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
        return uVar1;
      }
      psVar1 = (short *)0x0;
    }
    DVar1 = RtlNtStatusToDosError();
  } while( true );
}



void entry(void)

{
  code *pcVar1;
  UINT UVar1;
  bool in_ZF;
  
  if (in_ZF) {
                    // WARNING: Subroutine does not return
    ExitProcess(0xfffffffe);
  }
  UVar1 = ThinAppBootstrapAndLaunch();
  SafeShutdownWithExit(UVar1);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void LaunchUpdatedOrOriginalProcess(void)

{
  LPCWSTR *ppWVar1;
  WCHAR WVar1;
  int iVar1;
  ushort *puVar1;
  uint uVar1;
  WCHAR *func_hasoffset;
  BOOL BVar1;
  int process_info;
  WCHAR *pWVar1;
  undefined4 *in_FS_OFFSET;
  LPCWSTR lpApplicationName;
  LPWSTR lpCommandLine;
  
  init_proc();
  pass_context_to_handler((void *)(process_info + -0x110),*(short **)(process_info + 8),-1);
  ppWVar1 = *(LPCWSTR **)(process_info + 0x10);
  *(undefined4 *)(process_info + -4) = 0;
  if (ppWVar1[1] != (LPCWSTR)0x0) {
    ExpandEnvironmentStringsW(*ppWVar1,(LPWSTR)(process_info + -0x3c8),0x104);
  }
  iVar1 = _wcscmp(*(wchar_t **)(process_info + 8),*(wchar_t **)(process_info + 0xc));
  puVar1 = (ushort *)(process_info + -0x3c8);
  if (ppWVar1[1] == (LPCWSTR)0x0) {
    puVar1 = (ushort *)0x0;
  }
  uVar1 = FUN_66206550((ushort **)(process_info + -0x110),puVar1,0,(ushort **)0x0,0);
  if ((char)uVar1 != '\0') {
    FUN_6620d410(process_info + -0x60,0,0x44);
    *(undefined4 *)(process_info + -0x60) = 0x44;
    GetStartupInfoW((LPSTARTUPINFOW)(process_info + -0x60));
    func_hasoffset = GetCommandLineW();
    pass_context_to_handler((void *)(process_info + -0x1c0),func_hasoffset,-1);
    *(undefined *)(process_info + -4) = 1;
    if (iVar1 == 0) {
      WVar1 = *func_hasoffset;
      if (WVar1 == L'\"') {
        do {
          pWVar1 = func_hasoffset;
          func_hasoffset = pWVar1 + 1;
          if (*func_hasoffset == L'\0') goto LAB_66201561;
        } while (*func_hasoffset != L'\"');
        func_hasoffset = pWVar1 + 2;
      }
      else {
        while ((WVar1 != L'\0' && (WVar1 != L' '))) {
          func_hasoffset = func_hasoffset + 1;
          WVar1 = *func_hasoffset;
        }
      }
LAB_66201561:
      Concurrency::SchedulerPolicy::SchedulerPolicy
                ((SchedulerPolicy *)0x22,process_info - 0x1c0,u___ls__ls_6621c7a8,
                 *(undefined4 *)(process_info + -0x110),func_hasoffset);
    }
    SetEnvironmentVariableW(u_TS_SOURCE_6621c7bc,(LPCWSTR)0x0);
    SetEnvironmentVariableW(u_TS_ORIGIN_6621c38c,(LPCWSTR)0x0);
    if (iVar1 == 0) {
      lpCommandLine = *(LPWSTR *)(process_info + -0x1c0);
      lpApplicationName = *(LPCWSTR *)(process_info + -0x110);
    }
    else {
      SetEnvironmentVariableW(u_TS_UPDATED_DATFILE_6621c7d0,*(LPCWSTR *)(process_info + -0x110));
      lpCommandLine = *(LPWSTR *)(process_info + -0x1c0);
      lpApplicationName = *(LPCWSTR *)(process_info + 0xc);
    }
    BVar1 = CreateProcessW(lpApplicationName,lpCommandLine,(LPSECURITY_ATTRIBUTES)0x0,
                           (LPSECURITY_ATTRIBUTES)0x0,1,0,(LPVOID)0x0,(LPCWSTR)0x0,
                           (LPSTARTUPINFOW)(process_info + -0x60),
                           (LPPROCESS_INFORMATION)(process_info + -0x1c));
    if (BVar1 != 0) {
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    *(undefined *)(process_info + -4) = 0;
    manage_memstate((void **)(process_info + -0x1c0));
  }
  *(undefined4 *)(process_info + -4) = 0xffffffff;
  manage_memstate((void **)(process_info + -0x110));
  *in_FS_OFFSET = *(undefined4 *)(process_info + -0xc);
  return;
}



uint CheckForUpdatedDatFile(void)

{
  int iVar1;
  uint uVar1;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  
  init_proc();
  reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0xbc));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  update_context(*(void **)(unaff_EBP + 8),0);
  iVar1 = queryVar_allocatePolicy(u_TS_UPDATED_DATFILE_6621c7d0,(void *)(unaff_EBP + -0xbc),0);
  if (-1 < iVar1) {
    get_context(*(void **)(unaff_EBP + 8),(short **)(unaff_EBP + -0xbc));
    SetEnvironmentVariableW(u_TS_UPDATED_DATFILE_6621c7d0,(LPCWSTR)0x0);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  uVar1 = manage_memstate((void **)(unaff_EBP + -0xbc));
  *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return (uVar1 & 0xffffff00) | (uint)(-1 < iVar1);
}



uint ExecuteAppSyncUpdateWorkflow(void)

{
  short **this;
  bool bVar1;
  DWORD environment_variables;
  int EnvVar;
  HANDLE hHandle;
  uint got_ctx_search_results;
  short *backslash_position;
  uint substring_pos;
  SchedulerPolicy *this_00;
  SchedulerPolicy *this_01;
  SchedulerPolicy *this_02;
  SchedulerPolicy *this_03;
  byte bVar2;
  int object_context;
  undefined4 *in_FS_OFFSET;
  undefined auStack1948 [168];
  undefined4 uStack1780;
  undefined auStack1772 [152];
  undefined4 uStack1620;
  uint uVar1;
  
  init_proc();
  bVar2 = 0;
  *(undefined4 *)(object_context + -4) = 0;
  environment_variables =
       GetEnvironmentVariableW(u_TS_SBCLEANUP_6621c588,(LPWSTR)(object_context + -0x63c),0x104);
  if (environment_variables != 0) goto LAB_66201ce5;
  pass_context_to_handler((void *)(object_context + -0x434),has_offset,-1);
  *(undefined *)(object_context + -4) = 1;
  reset_flags_clean_memory((undefined4 *)(object_context + -900));
  this = *(short ***)(object_context + 0xb8);
  *(undefined *)(object_context + -4) = 2;
  update_context(this,0);
  EnvVar = queryVar_allocatePolicy
                     (*(undefined4 *)(object_context + -0x434),(void *)(object_context + -900),0);
  if (-1 < EnvVar) {
    hHandle = (HANDLE)Wwide_char_to_integer(*(ushort **)(object_context + -900));
    WaitForSingleObject(hHandle,0xffffffff);
    SetEnvironmentVariableW(*(LPCWSTR *)(object_context + -0x434),(LPCWSTR)0x0);
  }
  update_context((void *)(object_context + -900),0);
  safeget_ctxblob((void *)(object_context + -0x434),u_TS_UPDATE_COMPLETE_6621c560,-1);
  EnvVar = queryVar_allocatePolicy
                     (*(undefined4 *)(object_context + -0x434),(void *)(object_context + -900),0);
  if (-1 < EnvVar) {
    cleanup_ctxblob((void *)(object_context + -0xc4),(short **)(object_context + -900));
    *(undefined *)(object_context + -4) = 3;
    uStack1620 = 0x662017b1;
    invoke_qhandler((void *)(object_context + -0xc4),'\x01',(short *)&DAT_6621c540,-1,0,
                    (undefined4 *)0x0);
    uStack1620 = 0x662017c8;
    invoke_qhandler((void *)(object_context + -0xc4),'\x01',u__ase_6621c548,-1,0,(undefined4 *)0x0);
    *(undefined **)(object_context + -0x14) = auStack1772;
    uStack1780 = 0x662017df;
    cleanup_ctxblob(auStack1772,(short **)(object_context + -0xc4));
    *(undefined *)(object_context + -4) = 4;
    cleanup_ctxblob(auStack1948,(short **)(object_context + -900));
    *(undefined *)(object_context + -4) = 3;
    file_cleanup();
    get_context((void *)(object_context + -0xc4),(short **)(object_context + -900));
    uStack1620 = 0x6620182f;
    invoke_qhandler((void *)(object_context + -0xc4),'\x01',(short *)&DAT_6621c540,-1,0,
                    (undefined4 *)0x0);
    uStack1620 = 0x66201846;
    invoke_qhandler((void *)(object_context + -0xc4),'\x01',u__asd_6621c554,-1,0,(undefined4 *)0x0);
    *(undefined **)(object_context + -0x10) = auStack1772;
    uStack1780 = 0x6620185d;
    cleanup_ctxblob(auStack1772,(short **)(object_context + -0xc4));
    *(undefined *)(object_context + -4) = 5;
    cleanup_ctxblob(auStack1948,(short **)(object_context + -900));
    *(undefined *)(object_context + -4) = 3;
    file_cleanup();
    SetEnvironmentVariableW(*(LPCWSTR *)(object_context + -0x434),(LPCWSTR)0x0);
    *(undefined *)(object_context + -4) = 2;
    manage_memstate((void **)(object_context + -0xc4));
  }
  bVar2 = 0;
  reset_flags_clean_memory((undefined4 *)(object_context + -0xc4));
  *(undefined *)(object_context + -4) = 6;
  Concurrency::SchedulerPolicy::SchedulerPolicy(this_00,object_context - 0xc4);
  reset_flags_clean_memory((undefined4 *)(object_context + -0x2d4));
  while( true ) {
    *(undefined *)(object_context + -4) = 7;
    EnvVar = queryVar_allocatePolicy
                       (*(undefined4 *)(object_context + -0xc4),(void *)(object_context + -0x2d4),0)
    ;
    if (EnvVar < 0) break;
    got_ctx_search_results = search_array((void *)(object_context + -0x2d4),0x3b,0);
    pass_context_to_handler
              ((void *)(object_context + -0x224),
               (short *)(*(int *)(object_context + -0x2d4) + (got_ctx_search_results * 2) + 2),-1);
    backslash_position = this[1];
    *(undefined *)(object_context + -4) = 8;
    if (backslash_position == (short *)0x0) {
      get_context(this,(short **)(object_context + -0x224));
      uVar1 = 0xffffffff;
      substring_pos = 0;
      backslash_position = (short *)find_backslash((int *)this);
      substring_pos = find_backslash_substring(this,backslash_position,substring_pos,uVar1);
      update_context(this,substring_pos);
    }
    update_context((void *)(object_context + -0x2d4),got_ctx_search_results);
    cleanup_ctxblob((void *)(object_context + -0x174),(short **)(object_context + -0x224));
    *(undefined *)(object_context + -4) = 9;
    uStack1620 = 0x6620196d;
    invoke_qhandler((void *)(object_context + -0x174),'\x01',(short *)&DAT_6621c5c0,-1,3,
                    (undefined4 *)0x0);
    EnvVar = backup_file((LPCWSTR *)(object_context + -0x2d4),(LPCWSTR *)(object_context + -0x224),
                         (LPCWSTR *)(object_context + -0x174));
    if (EnvVar == 0) {
      *(undefined *)(object_context + -4) = 8;
      bVar1 = false;
      bVar2 = 0;
      manage_memstate((void **)(object_context + -0x174));
      *(undefined *)(object_context + -4) = 7;
      manage_memstate((void **)(object_context + -0x224));
      goto LAB_66201a33;
    }
    bVar2 = 1;
    SetEnvironmentVariableW(*(LPCWSTR *)(object_context + -0xc4),(LPCWSTR)0x0);
    *(undefined *)(object_context + -4) = 8;
    manage_memstate((void **)(object_context + -0x174));
    *(undefined *)(object_context + -4) = 7;
    manage_memstate((void **)(object_context + -0x224));
    *(undefined *)(object_context + -4) = 6;
    manage_memstate((void **)(object_context + -0x2d4));
    *(undefined *)(object_context + -4) = 2;
    manage_memstate((void **)(object_context + -0xc4));
    reset_flags_clean_memory((undefined4 *)(object_context + -0xc4));
    *(undefined *)(object_context + -4) = 6;
    Concurrency::SchedulerPolicy::SchedulerPolicy(this_01,object_context - 0xc4);
    reset_flags_clean_memory((undefined4 *)(object_context + -0x2d4));
  }
  bVar1 = true;
LAB_66201a33:
  *(undefined *)(object_context + -4) = 6;
  manage_memstate((void **)(object_context + -0x2d4));
  *(undefined *)(object_context + -4) = 2;
  manage_memstate((void **)(object_context + -0xc4));
  if (bVar2 == 0) {
    if (!bVar1) goto LAB_66201b43;
  }
  else if (bVar1) {
    cleanup_ctxblob((void *)(object_context + -0x174),this);
    *(undefined *)(object_context + -4) = 10;
    uStack1620 = 0x66201a89;
    invoke_qhandler((void *)(object_context + -0x174),'\x01',(short *)&DAT_6621c540,-1,0,
                    (undefined4 *)0x0);
    uStack1620 = 0x66201aa1;
    invoke_qhandler((void *)(object_context + -0x174),'\x01',u__old_6621c4c0,-1,0,(undefined4 *)0x0)
    ;
    *(undefined **)(object_context + -0x10) = auStack1772;
    uStack1780 = 0x66201ab8;
    cleanup_ctxblob(auStack1772,(short **)(object_context + -0x174));
    *(undefined *)(object_context + -4) = 0xb;
    cleanup_ctxblob(auStack1948,this);
    *(undefined *)(object_context + -4) = 10;
    file_cleanup();
    LaunchUpdateProcessAndCleanup();
    DisplayAppSyncUpdateNotification();
    uStack1780 = 0x66201af5;
    cleanup_ctxblob(auStack1772,(short **)(object_context + 8));
    ProcessAppSyncPathAndCleanup();
    *(undefined *)(object_context + -4) = 2;
    manage_memstate((void **)(object_context + -0x174));
  }
  else {
LAB_66201b43:
    if (this[1] != (short *)0x0) {
      cleanup_ctxblob((void *)(object_context + -0x174),this);
      *(undefined *)(object_context + -4) = 0xc;
      uStack1620 = 0x66201b75;
      invoke_qhandler((void *)(object_context + -0x174),'\x01',(short *)&DAT_6621c540,-1,0,
                      (undefined4 *)0x0);
      uStack1620 = 0x66201b8b;
      invoke_qhandler((void *)(object_context + -0x174),'\x01',u__old_6621c4c0,-1,0,
                      (undefined4 *)0x0);
      *(undefined **)(object_context + -0x10) = auStack1772;
      uStack1780 = 0x66201ba2;
      cleanup_ctxblob(auStack1772,(short **)(object_context + -0x174));
      *(undefined *)(object_context + -4) = 0xd;
      cleanup_ctxblob(auStack1948,this);
      *(undefined *)(object_context + -4) = 0xc;
      handle_legacy_files();
      reset_flags_clean_memory((undefined4 *)(object_context + -0xc4));
      *(undefined *)(object_context + -4) = 0xe;
      Concurrency::SchedulerPolicy::SchedulerPolicy(this_02,object_context - 0xc4);
      reset_flags_clean_memory((undefined4 *)(object_context + -0x224));
      while( true ) {
        *(undefined *)(object_context + -4) = 0xf;
        EnvVar = queryVar_allocatePolicy
                           (*(undefined4 *)(object_context + -0xc4),
                            (void *)(object_context + -0x224),0);
        if (EnvVar < 0) break;
        SetEnvironmentVariableW(*(LPCWSTR *)(object_context + -0xc4),(LPCWSTR)0x0);
        *(undefined *)(object_context + -4) = 0xe;
        manage_memstate((void **)(object_context + -0x224));
        *(undefined *)(object_context + -4) = 0xc;
        manage_memstate((void **)(object_context + -0xc4));
        reset_flags_clean_memory((undefined4 *)(object_context + -0xc4));
        *(undefined *)(object_context + -4) = 0xe;
        Concurrency::SchedulerPolicy::SchedulerPolicy(this_03,object_context - 0xc4);
        reset_flags_clean_memory((undefined4 *)(object_context + -0x224));
      }
      *(undefined *)(object_context + -4) = 0xe;
      manage_memstate((void **)(object_context + -0x224));
      *(undefined *)(object_context + -4) = 0xc;
      manage_memstate((void **)(object_context + -0xc4));
      MessageBoxW((HWND)0x0,u_Appsync_failed_to_upgrade_older_p_6621c5c8,u_AppSync_6621c3dc,0);
      *(undefined *)(object_context + -4) = 2;
      bVar2 = 1;
      manage_memstate((void **)(object_context + -0x174));
    }
    uStack1780 = 0x66201cbc;
    cleanup_ctxblob(auStack1772,(short **)(object_context + 8));
    ProcessAppSyncPathAndCleanup();
  }
  *(undefined *)(object_context + -4) = 1;
  manage_memstate((void **)(object_context + -900));
  *(undefined *)(object_context + -4) = 0;
  manage_memstate((void **)(object_context + -0x434));
LAB_66201ce5:
  *(undefined4 *)(object_context + -4) = 0xffffffff;
  got_ctx_search_results = manage_memstate((void **)(object_context + 8));
  *in_FS_OFFSET = *(undefined4 *)(object_context + -0xc);
  return (got_ctx_search_results & 0xffffff00) | (uint)bVar2;
}



void DisplayAppSyncUpdateNotification(void)

{
  int iVar1;
  SchedulerPolicy *this;
  int policy_pair_count;
  undefined4 *in_FS_OFFSET;
  
  init_proc();
  reset_flags_clean_memory((undefined4 *)(policy_pair_count + -0x16c));
  *(undefined4 *)(policy_pair_count + -4) = 0;
  Concurrency::SchedulerPolicy::SchedulerPolicy
            (this,policy_pair_count - 0x16c,u_TS_APPSYNC_UPDATE_MESSAGE_6621c50c);
  reset_flags_clean_memory((undefined4 *)(policy_pair_count + -0xbc));
  *(undefined *)(policy_pair_count + -4) = 1;
  iVar1 = queryVar_allocatePolicy
                    (*(undefined4 *)(policy_pair_count + -0x16c),(void *)(policy_pair_count + -0xbc)
                     ,0);
  if (-1 < iVar1) {
    MessageBoxW((HWND)0x0,*(LPCWSTR *)(policy_pair_count + -0xbc),u_AppSync_6621c3dc,0);
  }
  *(undefined *)(policy_pair_count + -4) = 0;
  manage_memstate((void **)(policy_pair_count + -0xbc));
  *(undefined4 *)(policy_pair_count + -4) = 0xffffffff;
  manage_memstate((void **)(policy_pair_count + -0x16c));
  *in_FS_OFFSET = *(undefined4 *)(policy_pair_count + -0xc);
  return;
}



void LaunchUpdateProcessAndCleanup(void)

{
  int iVar1;
  BOOL process;
  uint arraysearch_result;
  LPCWSTR *ppWVar1;
  SchedulerPolicy *this;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  
  init_proc();
  reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x270));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x1c0));
  *(undefined *)(unaff_EBP + -4) = 1;
  Concurrency::SchedulerPolicy::SchedulerPolicy(this,unaff_EBP - 0x1c0,u_TS_UPDATE_THINREG_6621c4cc)
  ;
  iVar1 = queryVar_allocatePolicy
                    (*(undefined4 *)(unaff_EBP + -0x1c0),(void *)(unaff_EBP + -0x270),0);
  if (iVar1 == 0) {
    cleanup_ctxblob((void *)(unaff_EBP + -0xcc),(short **)(unaff_EBP + -0x270));
    *(undefined *)(unaff_EBP + -4) = 2;
    invoke_qhandler((void *)(unaff_EBP + -0xcc),'\x01',(short *)&DAT_6621c4f0,-1,0,(undefined4 *)0x0
                   );
    invoke_qhandler((void *)(unaff_EBP + -0xcc),'\x01',**(short ***)(unaff_EBP + 8),
                    (int)(*(short ***)(unaff_EBP + 8))[1],0,(undefined4 *)0x0);
    invoke_qhandler((void *)(unaff_EBP + -0xcc),'\x01',u____exe_6621c4f8,-1,0,(undefined4 *)0x0);
    invoke_qhandler((void *)(unaff_EBP + -0xcc),'\x01',(short *)&DAT_6621c508,-1,0,(undefined4 *)0x0
                   );
    FUN_6620d410(unaff_EBP + -0x110,0,0x44);
    *(undefined4 *)(unaff_EBP + -0x110) = 0x44;
    process = CreateProcessW((LPCWSTR)0x0,*(LPWSTR *)(unaff_EBP + -0xcc),(LPSECURITY_ATTRIBUTES)0x0,
                             (LPSECURITY_ATTRIBUTES)0x0,0,0,(LPVOID)0x0,(LPCWSTR)0x0,
                             (LPSTARTUPINFOW)(unaff_EBP + -0x110),
                             (LPPROCESS_INFORMATION)(unaff_EBP + -0x1c));
    if (process != 0) {
      CloseHandle(*(HANDLE *)(unaff_EBP + -0x18));
      WaitForSingleObject(*(HANDLE *)(unaff_EBP + -0x1c),0xffffffff);
      CloseHandle(*(HANDLE *)(unaff_EBP + -0x1c));
    }
    if (**(short **)(unaff_EBP + -0xcc) == 0x22) {
      arraysearch_result = search_array((void *)(unaff_EBP + -0xcc),0x22,1);
      if (arraysearch_result != 0xffffffff) {
        ppWVar1 = (LPCWSTR *)ProcessAndCleanupSubstring();
        DeleteFileW(*ppWVar1);
        manage_memstate((void **)(unaff_EBP + -800));
      }
    }
    SetEnvironmentVariableW(u_TS_UPDATE_THINREG_6621c4cc,(LPCWSTR)0x0);
    *(undefined *)(unaff_EBP + -4) = 1;
    manage_memstate((void **)(unaff_EBP + -0xcc));
  }
  *(undefined *)(unaff_EBP + -4) = 0;
  manage_memstate((void **)(unaff_EBP + -0x1c0));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  manage_memstate((void **)(unaff_EBP + -0x270));
  *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return;
}



void file_cleanup(void)

{
  HANDLE file_found;
  BOOL nextfile;
  int filename;
  undefined4 *in_FS_OFFSET;
  
  init_proc();
  *(undefined4 *)(filename + -4) = 1;
  cleanup_ctxblob((void *)(filename + -0xbc),(short **)(filename + 8));
  *(undefined *)(filename + -4) = 2;
  file_found = FindFirstFileW(*(LPCWSTR *)(filename + 0xb8),(LPWIN32_FIND_DATAW)(filename + -0x30c))
  ;
  do {
    invoke_qhandler((void *)(filename + -0xbc),'\x01',(short *)(filename + -0x2e0),-1,0,
                    (undefined4 *)0x0);
    DeleteFileW(*(LPCWSTR *)(filename + -0xbc));
    get_context((void *)(filename + -0xbc),(short **)(filename + 8));
    nextfile = FindNextFileW(file_found,(LPWIN32_FIND_DATAW)(filename + -0x30c));
  } while (nextfile != 0);
  *(undefined *)(filename + -4) = 1;
  manage_memstate((void **)(filename + -0xbc));
  *(undefined *)(filename + -4) = 0;
  manage_memstate((void **)(filename + 8));
  *(undefined4 *)(filename + -4) = 0xffffffff;
  manage_memstate((void **)(filename + 0xb8));
  *in_FS_OFFSET = *(undefined4 *)(filename + -0xc);
  return;
}



void handle_legacy_files(void)

{
  HANDLE hFindFile;
  size_t sVar1;
  BOOL BVar1;
  int previous_state_tracking;
  undefined4 *in_FS_OFFSET;
  int prevstates;
  
                    // Careful version tracking
  init_proc();
  *(undefined4 *)(previous_state_tracking + -4) = 1;
  cleanup_ctxblob((void *)(previous_state_tracking + -0xbc),(short **)(previous_state_tracking + 8))
  ;
  *(undefined *)(previous_state_tracking + -4) = 2;
  hFindFile = FindFirstFileW(*(LPCWSTR *)(previous_state_tracking + 0xb8),
                             (LPWIN32_FIND_DATAW)(previous_state_tracking + -0x46c));
  do {
    invoke_qhandler((void *)(previous_state_tracking + -0xbc),'\x01',
                    (short *)(previous_state_tracking + -0x440),-1,0,(undefined4 *)0x0);
    cleanup_ctxblob((void *)(previous_state_tracking + -0x21c),
                    (short **)(previous_state_tracking + -0xbc));
    prevstates = *(int *)(previous_state_tracking + -0xb8);
    *(undefined *)(previous_state_tracking + -4) = 3;
    sVar1 = _wcslen(u__old_6621c4c0);
    cleanupmemstate((void *)(previous_state_tracking + -0xbc),
                    (void *)(previous_state_tracking + -0x16c),(short *)(prevstates - sVar1));
    *(undefined *)(previous_state_tracking + -4) = 4;
    MoveFileExW(*(LPCWSTR *)(previous_state_tracking + -0x21c),
                *(LPCWSTR *)(previous_state_tracking + -0x16c),1);
    get_context((void *)(previous_state_tracking + -0xbc),(short **)(previous_state_tracking + 8));
    *(undefined *)(previous_state_tracking + -4) = 3;
    manage_memstate((void **)(previous_state_tracking + -0x16c));
    *(undefined *)(previous_state_tracking + -4) = 2;
    manage_memstate((void **)(previous_state_tracking + -0x21c));
    BVar1 = FindNextFileW(hFindFile,(LPWIN32_FIND_DATAW)(previous_state_tracking + -0x46c));
  } while (BVar1 != 0);
  *(undefined *)(previous_state_tracking + -4) = 1;
  manage_memstate((void **)(previous_state_tracking + -0xbc));
  *(undefined *)(previous_state_tracking + -4) = 0;
  manage_memstate((void **)(previous_state_tracking + 8));
  *(undefined4 *)(previous_state_tracking + -4) = 0xffffffff;
  manage_memstate((void **)(previous_state_tracking + 0xb8));
  *in_FS_OFFSET = *(undefined4 *)(previous_state_tracking + -0xc);
  return;
}



void HandleApplicationUpdateAndRestart(void)

{
  int iVar1;
  void **ppvVar1;
  HANDLE hTargetProcessHandle;
  HANDLE hSourceHandle;
  HANDLE hSourceProcessHandle;
  SchedulerPolicy *this;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  LPHANDLE lpTargetHandle;
  DWORD dwDesiredAccess;
  BOOL BVar1;
  DWORD dwOptions;
  
  init_proc();
  *(undefined4 *)(unaff_EBP + -4) = 0;
  reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x214));
  *(undefined *)(unaff_EBP + -4) = 1;
  Concurrency::SchedulerPolicy::SchedulerPolicy(this,unaff_EBP - 0x214,u_TS_UPDATE_CMDLINE_6621c3b4)
  ;
  reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x114));
  *(undefined *)(unaff_EBP + -4) = 2;
  iVar1 = queryVar_allocatePolicy
                    (*(undefined4 *)(unaff_EBP + -0x214),(void *)(unaff_EBP + -0x114),0);
  if (-1 < iVar1) {
    ppvVar1 = pass_context_to_handler((void *)(unaff_EBP + -0x374),(short *)&DAT_6621c3d8,-1);
    *(undefined *)(unaff_EBP + -4) = 3;
    iVar1 = CompareAndProcessObjects((void *)(unaff_EBP + -0x114),ppvVar1,0);
    *(undefined *)(unaff_EBP + -4) = 2;
    manage_memstate((void **)(unaff_EBP + -0x374));
    if (iVar1 == 0) {
      MessageBoxW((HWND)0x0,u_Your_application_was_updated__Pl_6621c3f0,u_AppSync_6621c3dc,0);
      goto LAB_662021f5;
    }
    SetEnvironmentVariableW(u_TS_UPDATE_CMDLINE_6621c3b4,(LPCWSTR)0x0);
  }
  FUN_6620d410(unaff_EBP + -100,0,0x44);
  *(undefined4 *)(unaff_EBP + -100) = 0x44;
  GetStartupInfoW((LPSTARTUPINFOW)(unaff_EBP + -100));
  cleanup_ctxblob((void *)(unaff_EBP + -0x2c4),(short **)(unaff_EBP + -0x114));
  lpTargetHandle = (LPHANDLE)(unaff_EBP + -0x10);
  dwOptions = 2;
  BVar1 = 1;
  dwDesiredAccess = 0;
  hTargetProcessHandle = GetCurrentProcess();
  hSourceHandle = GetCurrentProcess();
  hSourceProcessHandle = GetCurrentProcess();
  DuplicateHandle(hSourceProcessHandle,hSourceHandle,hTargetProcessHandle,lpTargetHandle,
                  dwDesiredAccess,BVar1,dwOptions);
  wsprintfW((LPWSTR)(unaff_EBP + -0x164),(LPCWSTR)&param_2_6621c494,
            *(undefined4 *)(unaff_EBP + -0x10));
  SetEnvironmentVariableW(has_offset,(LPCWSTR)(unaff_EBP + -0x164));
  BVar1 = CreateProcessW(*(LPCWSTR *)(unaff_EBP + 8),*(LPWSTR *)(unaff_EBP + -0x2c4),
                         (LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,1,0,(LPVOID)0x0,
                         (LPCWSTR)0x0,(LPSTARTUPINFOW)(unaff_EBP + -100),
                         (LPPROCESS_INFORMATION)(unaff_EBP + -0x20));
  if (BVar1 == 0) {
    manage_memstate((void **)(unaff_EBP + -0x2c4));
    *(undefined *)(unaff_EBP + -4) = 1;
    manage_memstate((void **)(unaff_EBP + -0x114));
    *(undefined *)(unaff_EBP + -4) = 0;
    manage_memstate((void **)(unaff_EBP + -0x214));
    *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
    manage_memstate((void **)(unaff_EBP + 8));
    *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
    return;
  }
LAB_662021f5:
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void ProcessAppSyncPathAndCleanup(void)

{
  short *backslash_position;
  SchedulerPolicy *this;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  undefined auStack720 [168];
  undefined4 uStack552;
  undefined auStack544 [152];
  undefined4 uStack392;
  uint uVar1;
  uint uVar2;
  
  init_proc();
  *(undefined4 *)(unaff_EBP + -4) = 0;
  uVar2 = 0xffffffff;
  uVar1 = 0;
  backslash_position = (short *)find_backslash((int *)(unaff_EBP + 8));
  uVar1 = find_backslash_substring((void *)(unaff_EBP + 8),backslash_position,uVar1,uVar2);
  update_context((void *)(unaff_EBP + 8),uVar1);
  cleanup_ctxblob((void *)(unaff_EBP + -0xc4),(short **)(unaff_EBP + 8));
  *(undefined *)(unaff_EBP + -4) = 1;
  uStack392 = 0x6620234a;
  invoke_qhandler((void *)(unaff_EBP + -0xc4),'\x01',(short *)&DAT_6621c540,-1,0,(undefined4 *)0x0);
  uStack392 = 0x66202361;
  invoke_qhandler((void *)(unaff_EBP + -0xc4),'\x01',u__ase_6621c548,-1,0,(undefined4 *)0x0);
  *(undefined **)(unaff_EBP + -0x14) = auStack544;
  uStack552 = 0x66202378;
  cleanup_ctxblob(auStack544,(short **)(unaff_EBP + -0xc4));
  *(undefined *)(unaff_EBP + -4) = 2;
  cleanup_ctxblob(auStack720,(short **)(unaff_EBP + 8));
  *(undefined *)(unaff_EBP + -4) = 1;
  file_cleanup();
  get_context((void *)(unaff_EBP + -0xc4),(short **)(unaff_EBP + 8));
  uStack392 = 0x662023be;
  invoke_qhandler((void *)(unaff_EBP + -0xc4),'\x01',(short *)&DAT_6621c540,-1,0,(undefined4 *)0x0);
  uStack392 = 0x662023d5;
  invoke_qhandler((void *)(unaff_EBP + -0xc4),'\x01',u__asd_6621c554,-1,0,(undefined4 *)0x0);
  *(undefined **)(unaff_EBP + -0x10) = auStack544;
  uStack552 = 0x662023ec;
  cleanup_ctxblob(auStack544,(short **)(unaff_EBP + -0xc4));
  *(undefined *)(unaff_EBP + -4) = 3;
  cleanup_ctxblob(auStack720,(short **)(unaff_EBP + 8));
  *(undefined *)(unaff_EBP + -4) = 1;
  file_cleanup();
  reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0x174));
  *(undefined *)(unaff_EBP + -4) = 4;
  Concurrency::SchedulerPolicy::SchedulerPolicy(this,unaff_EBP - 0x174);
  SetEnvironmentVariableW(*(LPCWSTR *)(unaff_EBP + -0x174),*(LPCWSTR *)(unaff_EBP + 8));
  *(undefined *)(unaff_EBP + -4) = 1;
  manage_memstate((void **)(unaff_EBP + -0x174));
  *(undefined *)(unaff_EBP + -4) = 0;
  manage_memstate((void **)(unaff_EBP + -0xc4));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  manage_memstate((void **)(unaff_EBP + 8));
  *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return;
}



undefined4 ProcessAndCleanupSubstring(void)

{
  undefined4 uVar1;
  undefined4 *this;
  short **ppsVar1;
  int *extraout_ECX;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  
  init_proc();
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  this = reset_flags_clean_memory((undefined4 *)(unaff_EBP + -0xc0));
  *(undefined4 *)(unaff_EBP + -4) = 1;
  ppsVar1 = (short **)
            ProcessSubstringOperation
                      (this,extraout_ECX,*(uint *)(unaff_EBP + 0xc),*(uint *)(unaff_EBP + 0x10));
  cleanup_ctxblob(*(void **)(unaff_EBP + 8),ppsVar1);
  *(undefined4 *)(unaff_EBP + -0x10) = 1;
  *(undefined *)(unaff_EBP + -4) = 0;
  manage_memstate((void **)(unaff_EBP + -0xc0));
  uVar1 = *(undefined4 *)(unaff_EBP + 8);
  *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return uVar1;
}



undefined4 __cdecl backup_file(LPCWSTR *existingfile,LPCWSTR *filename,LPCWSTR *newfile2)

{
  DWORD file_attributes;
  int iVar1;
  BOOL BVar1;
  int iVar2;
  
  iVar2 = 0;
                    // If file is empty, delete, if not, move, if cant, copy
  if (existingfile[1] == (LPCWSTR)0) {
    DeleteFileW(*filename);
  }
  else {
    file_attributes = GetFileAttributesW(*filename);
    if (file_attributes == 0xffffffff) {
      CopyFileW(*existingfile,*filename,1);
    }
    else {
      iVar1 = MoveFileW(*filename,*newfile2);
      while (iVar1 == 0) {
        Sleep(200);
        iVar2 = iVar2 + 1;
                    // time limit
        if (iVar2 == 150) break;
        iVar1 = MoveFileW(*filename,*newfile2);
      }
      BVar1 = CopyFileW(*existingfile,*filename,1);
      if (BVar1 == 0) {
        return 0;
      }
      get_context(existingfile,filename);
    }
  }
  return 1;
}



void __fastcall acquire_lock(int *resource)

{
  int counter;
  
                    // Patiently waits for other process to finish with resources, before locking it
  counter = 0;
  LOCK();
  if (*resource == 0) {
    *resource = 1;
  }
  else {
    counter = *resource;
  }
                    // Delay 10 seconds for every param1
  while (counter != 0) {
    delay_execution(10);
    counter = 0;
    LOCK();
    if (*resource == 0) {
      *resource = 1;
    }
    else {
      counter = *resource;
    }
  }
  return;
}



int __cdecl get_nearest_multiple(int x,uint y)

{
                    // Get nearest multiple of Y closest to X
                    // 
  return ((x + -1 + y) / y) * y;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool CheckDebuggerAndDbwinBuffer(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar1;
  undefined4 s28;
  undefined4 s24;
  undefined *s20;
  undefined4 s1c;
  undefined4 s18;
  undefined4 s14;
  undefined s10 [8];
  undefined4 s8;
  
  if (DAT_6624b464 == 0) {
    DAT_6624b464 = -1;
    bVar1 = CheckThreadDebuggerFlag();
    if (((int)(int3)extraout_var << 8) + bVar1 == 0) {
      RtlInitUnicodeString(s10,u_DBWIN_BUFFER_6621c984);
      if (_DAT_6624b2f8 != 2) {
        InitializeSystemInfoAndLocks((int *)&DAT_6624b2f8);
      }
      s24 = DAT_6624b450;
      s20 = s10;
      s28 = 0x18;
      s1c = 0x40;
      s18 = 0;
      s14 = 0;
      iVar1 = NtOpenSection(&s8,2,&s28);
      if (iVar1 < 0) goto LAB_662026ac;
      NtClose(s8);
    }
    DAT_6624b464 = 1;
    return true;
  }
LAB_662026ac:
  return 0 < DAT_6624b464;
}



void __fastcall AcquireCriticalSectionWithLock(int param_1)

{
  int *piVar1;
  undefined4 uVar1;
  
  piVar1 = (int *)(param_1 + 0x18);
  if ((*(int *)(param_1 + 0x18) != 2) &&
     (uVar1 = AcquireResourceLockWithRetry(piVar1), (char)uVar1 != '\0')) {
    RtlInitializeCriticalSection(param_1);
    LOCK();
    if (*piVar1 == 1) {
      *piVar1 = 2;
    }
  }
  RtlEnterCriticalSection(param_1);
  return;
}


/*
Unable to decompile 'FUN_66202700'
Cause: Exception while decompiling 66202700: Decompiler process died

*/

/*
Unable to decompile 'FUN_662027d0'
Cause: Exception while decompiling 662027d0: Decompiler process died

*/


// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint GetSystemInfoFlags(void)

{
  if (_DAT_6624b2f8 != 2) {
    InitializeSystemInfoAndLocks((int *)&DAT_6624b2f8);
  }
  return (DAT_6624b300 << 8) | _DAT_6624b304;
}



int __fastcall InitializeSystemInfoAndLocks(int *param_1)

{
  undefined uVar1;
  int iVar1;
  int *s8;
  
  s8 = param_1;
  iVar1 = AcquireResourceLockWithRetry(param_1);
  if ((char)iVar1 != '\0') {
    GetSystemVersionAndModulePath((int)param_1);
    FUN_6620d410(param_1 + 0x48,0,0x2c);
    NtQuerySystemInformation(0,param_1 + 0x48,0x2c,0);
    *(undefined8 *)(param_1 + 0x53) = 0;
    param_1[0x55] = 0;
    NtQuerySystemInformation(1,param_1 + 0x53,0xc,0);
    iVar1 = NtQueryInformationProcess(0xffffffff,0x1a,&s8,4,0);
    if ((iVar1 < 0) || (s8 == (int *)0x0)) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
    *(undefined *)(param_1 + 0x59) = uVar1;
    *(undefined *)((int)param_1 + 0x165) = uVar1;
    InitializeRestrictedDirectoryHandles((int)param_1);
    iVar1 = 1;
    LOCK();
    if (*param_1 == 1) {
      *param_1 = 2;
    }
    else {
      iVar1 = *param_1;
    }
  }
  return iVar1;
}



undefined * __cdecl getsafe_aligned_ptr(undefined *param_1)

{
  undefined auStack256 [248];
  undefined s8 [4];
  
                    // Check that param1 has higher address and within 1MiB
  if ((s8 < param_1) && ((uint)((int)param_1 - (int)s8) < 0x100000)) {
    return (undefined *)(((int)(int3)((uint)s8 >> 8) << 8) + 1);
  }
  return auStack256;
}



void __fastcall ReleaseCriticalSection(undefined4 param_1)

{
  RtlLeaveCriticalSection(param_1);
  return;
}



undefined4 __fastcall AcquireResourceLockWithRetry(int *param_1)

{
  int iVar1;
  undefined4 sc;
  undefined4 s8;
  
  iVar1 = 0;
  LOCK();
  if (*param_1 == 0) {
    *param_1 = 1;
  }
  else {
    iVar1 = *param_1;
  }
  while( true ) {
    if (iVar1 == 2) {
      return 0;
    }
    if (iVar1 == 0) break;
    sc = 0xffffd8f0;
    s8 = 0xffffffff;
    NtDelayExecution(0,&sc);
    iVar1 = 0;
    LOCK();
    if (*param_1 == 0) {
      *param_1 = 1;
    }
    else {
      iVar1 = *param_1;
    }
  }
  return 1;
}



int __thiscall GetRestrictedDirectoryHandle(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  if (*this != 2) {
    InitializeSystemInfoAndLocks((int *)this);
  }
  if (param_1 != 0) {
    if (param_1 != 4) {
      return 0;
    }
    return *(int *)((int)this + 0x15c);
  }
  return *(int *)((int)this + 0x158);
}



// WARNING: Could not reconcile some variable overlaps

void __cdecl FUN_66202a80(undefined4 param_1,uint param_2)

{
  undefined8 sc;
  
  if (param_2 == 0xffffffff) {
    NtWaitForSingleObject(param_1,0,0);
    return;
  }
  sc = __allmul(param_2,0,0xffffd8f0,0xffffffff);
  NtWaitForSingleObject(param_1,0,&sc);
  return;
}



undefined4 __fastcall GetNtdllHandleOrTerminate(int param_1)

{
  int iVar1;
  undefined sc [8];
  
  if (*(int *)(param_1 + 0x160) == 0) {
    RtlInitUnicodeString(sc,u_ntdll_dll_6621c904);
    iVar1 = LdrGetDllHandle(1,0,sc,(undefined4 *)(param_1 + 0x160));
    if (iVar1 < 0) {
      DisplayHardErrorAndTerminate(s_BasicUtil_cpp_6621c918,0x1ab,(short *)0x0);
    }
  }
  return *(undefined4 *)(param_1 + 0x160);
}



void __fastcall InitializeRestrictedDirectoryHandles(int param_1)

{
  undefined4 uVar1;
  int iVar1;
  undefined4 *in_FS_OFFSET;
  void *se0 [44];
  int s30;
  undefined4 s2c;
  undefined4 s28;
  undefined4 *s24;
  undefined4 s20;
  undefined4 s1c;
  undefined4 s18;
  undefined4 s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b4db;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  reset_flags_clean_memory(se0);
  s8 = 0;
  FUN_662027d0(se0,0);
  s24 = PrepareUnicodeStringBuffer(se0);
  s2c = 0x18;
  s28 = 0;
  s20 = 0x40;
  s1c = 0;
  s18 = 0;
  iVar1 = NtOpenDirectoryObject(&s14,0xf,&s2c);
  if (iVar1 < 0) {
    iVar1 = NtOpenDirectoryObject(&s14,3,&s2c);
    if (-1 < iVar1) {
      *(undefined4 *)(param_1 + 0x15c) = s14;
    }
    iVar1 = NtOpenDirectoryObject(&s14,2,&s2c);
    uVar1 = s14;
    if (iVar1 < 0) goto LAB_66202c5d;
    safeget_ctxblob(se0,u_Restricted_6621c928,-1);
    s24 = PrepareUnicodeStringBuffer(se0);
    s2c = 0x18;
    s28 = uVar1;
    s20 = 0x40;
    s1c = 0;
    s18 = 0;
    s30 = NtOpenDirectoryObject(&s14,0xf,&s2c);
    NtClose(uVar1);
    iVar1 = s30;
  }
  else {
    *(undefined4 *)(param_1 + 0x15c) = s14;
  }
  if (-1 < iVar1) {
    *(undefined4 *)(param_1 + 0x158) = s14;
  }
LAB_66202c5d:
  s8 = 0xffffffff;
  manage_memstate(se0);
  *in_FS_OFFSET = s10;
  return;
}



void __fastcall GetSystemVersionAndModulePath(int param_1)

{
  undefined4 *puVar1;
  short sVar1;
  int iVar1;
  short *psVar1;
  short *psVar2;
  int in_FS_OFFSET;
  
  puVar1 = (undefined4 *)(param_1 + 4);
  FUN_6620d410(puVar1,0,0x11c);
  *puVar1 = 0x11c;
  RtlGetVersion(puVar1);
  if ((*(int *)(param_1 + 8) == 5) && (*(int *)(param_1 + 0xc) == 0)) {
    iVar1 = *(int *)(*(int *)(in_FS_OFFSET + 0x18) + 0x30);
    psVar1 = *(short **)(iVar1 + 0x1e0);
    if ((psVar1 == (short *)0x0) || (*(short *)(iVar1 + 0x1dc) == 0)) {
      *(undefined2 *)(param_1 + 0x18) = 0;
      *(undefined *)(param_1 + 0x11f) = 0;
      return;
    }
    psVar2 = psVar1;
    do {
      sVar1 = *psVar2;
      psVar2 = psVar2 + 1;
    } while (sVar1 != 0);
    FUN_6620d5b0(param_1 + 0x18,psVar1,((((int)psVar2 - (int)(psVar1 + 1)) >> 1) * 2) + 2);
  }
  *(undefined *)(param_1 + 0x11f) = 0;
  return;
}



int __fastcall FUN_66202d10(int *param_1)

{
  int iVar1;
  
  iVar1 = 1;
  LOCK();
  if (*param_1 == 1) {
    *param_1 = 2;
  }
  else {
    iVar1 = *param_1;
  }
  return iVar1;
}



int __fastcall FUN_66202d20(int *param_1)

{
  int in_EAX;
  uint3 uVar1;
  
  if (*param_1 != 2) {
    in_EAX = InitializeSystemInfoAndLocks(param_1);
  }
  uVar1 = (uint3)((uint)in_EAX >> 8);
  if ((param_1[2] == 10) && (param_1[3] == 0)) {
    return ((int)(int3)uVar1 << 8) + 1;
  }
  return (uint)uVar1 << 8;
}



uint __fastcall FUN_66202d50(int *param_1)

{
  uint in_EAX;
  
  if (*param_1 != 2) {
    in_EAX = InitializeSystemInfoAndLocks(param_1);
  }
  return (in_EAX & 0xffffff00) | (uint)*(byte *)((int)param_1 + 0x165);
}



int __fastcall FUN_66202d70(int *param_1)

{
  uint uVar1;
  uint3 uVar2;
  
  if (*param_1 != 2) {
    InitializeSystemInfoAndLocks(param_1);
  }
  uVar1 = param_1[2];
  uVar2 = (uint3)(uVar1 >> 8);
  if ((uVar1 < 7) && ((uVar1 != 6 || ((uint)param_1[3] < 3)))) {
    return (uint)uVar2 << 8;
  }
  return ((int)(int3)uVar2 << 8) + 1;
}



bool __fastcall FUN_66202da0(int *param_1)

{
  if (*param_1 != 2) {
    InitializeSystemInfoAndLocks(param_1);
  }
  return (bool)('\x01' - ((uint)param_1[2] < 6));
}



uint __fastcall FUN_66202dc0(int *param_1)

{
  uint in_EAX;
  
  if (*param_1 != 2) {
    in_EAX = InitializeSystemInfoAndLocks(param_1);
  }
  return (in_EAX & 0xffffff00) | (uint)*(byte *)(param_1 + 0x59);
}



void * __thiscall FUN_66202de0(void *this,short *param_1,undefined4 *param_2)

{
  invoke_qhandler(this,'\x01',param_1,0,2,param_2);
  return this;
}



void __cdecl LogModuleLoadEvent(undefined4 param_1,undefined4 param_2,undefined *param_3)

{
  SelectDefaultOrProvidedPointer(param_3,(undefined *)0x0);
  ConditionalLogWithDebugCheck(u__link_cmd___reload__f__ls_0x_p___6621c9a0,(undefined1)param_1);
  return;
}



void __cdecl FUN_66202e30(undefined4 param_1,undefined param_2)

{
  bool bVar1;
  undefined4 *in_FS_OFFSET;
  undefined *sc4 [44];
  undefined *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b4fb;
  *in_FS_OFFSET = &s10;
  bVar1 = CheckDebuggerAndDbwinBuffer();
  if (bVar1 != false) {
    s14 = &param_2;
    reset_flags_clean_memory(sc4);
    s8 = 0;
    FUN_66202700(5,sc4,param_1,&s14);
    LogUnicodeStringAsAnsiEvent(sc4[0]);
    s8 = 0xffffffff;
    manage_memstate(sc4);
  }
  *in_FS_OFFSET = s10;
  return;
}



void __cdecl ConditionalLogWithDebugCheck(undefined4 param_1,undefined param_2)

{
  bool bVar1;
  undefined4 *in_FS_OFFSET;
  undefined *sc4 [44];
  undefined *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b4fb;
  *in_FS_OFFSET = &s10;
  bVar1 = CheckDebuggerAndDbwinBuffer();
  if (bVar1 != false) {
    s14 = &param_2;
    reset_flags_clean_memory(sc4);
    s8 = 0;
    FUN_66202700(3,sc4,param_1,&s14);
    LogUnicodeStringAsAnsiEvent(sc4[0]);
    s8 = 0xffffffff;
    manage_memstate(sc4);
  }
  *in_FS_OFFSET = s10;
  return;
}



short ** __thiscall cleanup_ctxblob(void *this,short **param_1)

{
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 **)this = (undefined4 *)((int)this + 0x2c);
  *(undefined4 *)((int)this + 0xc) = 1;
  *(undefined4 *)((int)this + 8) = 64;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  if (*(int *)((int)this + 0x28) == 2) {
    manage_memory_state(*(void **)((int)this + 0x1c),*(undefined4 *)((int)this + 0x24));
    *(undefined4 *)((int)this + 0x1c) = 0;
    *(undefined4 *)((int)this + 0x24) = 0;
    *(undefined4 *)((int)this + 0x20) = 0;
    *(undefined4 *)((int)this + 0x28) = 0;
  }
  if ((short **)this != param_1) {
    if (*param_1 == (short *)0x0) {
      safe_mem_access((void **)this);
      return (short **)this;
    }
    invoke_qhandler(this,'\0',*param_1,(int)param_1[1],0,(undefined4 *)0x0);
  }
  return (short **)this;
}



undefined4 * __thiscall FUN_66202ff0(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 **)this = (undefined4 *)((int)this + 0x2c);
  *(undefined4 *)((int)this + 0xc) = 1;
  *(undefined4 *)((int)this + 8) = 0x40;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  if (*(int *)((int)this + 0x28) == 2) {
    manage_memory_state(*(void **)((int)this + 0x1c),*(undefined4 *)((int)this + 0x24));
    *(undefined4 *)((int)this + 0x1c) = 0;
    *(undefined4 *)((int)this + 0x24) = 0;
    *(undefined4 *)((int)this + 0x20) = 0;
    *(undefined4 *)((int)this + 0x28) = 0;
  }
  FUN_66203f60(param_1,param_2);
  return (undefined4 *)this;
}



undefined4 * __thiscall InitializeStringBufferObject(void *this,ushort *param_1)

{
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 **)this = (undefined4 *)((int)this + 0x2c);
  *(undefined4 *)((int)this + 0xc) = 1;
  *(undefined4 *)((int)this + 8) = 0x40;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  if (*(int *)((int)this + 0x28) == 2) {
    manage_memory_state(*(void **)((int)this + 0x1c),*(undefined4 *)((int)this + 0x24));
    *(undefined4 *)((int)this + 0x1c) = 0;
    *(undefined4 *)((int)this + 0x24) = 0;
    *(undefined4 *)((int)this + 0x20) = 0;
    *(undefined4 *)((int)this + 0x28) = 0;
  }
  AllocateAndConvertWideStringBuffer(this,param_1);
  return (undefined4 *)this;
}



void ** __thiscall pass_context_to_handler(void *this,short *func_hasoffset,int q_function)

{
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 **)this = (undefined4 *)((int)this + 0x2c);
  *(undefined4 *)((int)this + 0xc) = 1;
  *(undefined4 *)((int)this + 8) = 0x40;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  if (*(int *)((int)this + 0x28) == 2) {
    manage_memory_state(*(void **)((int)this + 0x1c),*(undefined4 *)((int)this + 0x24));
    *(undefined4 *)((int)this + 0x1c) = 0;
    *(undefined4 *)((int)this + 0x24) = 0;
    *(undefined4 *)((int)this + 0x20) = 0;
    *(undefined4 *)((int)this + 0x28) = 0;
  }
                    // Safely get object context
  if ((func_hasoffset == (short *)0) && (q_function == -1)) {
    safe_mem_access((void **)this);
    return (void **)this;
  }
                    // Q is not a function, we'll call it a context sensitive blob
  invoke_qhandler(this,'\0',func_hasoffset,q_function,0,(undefined4 *)0x0);
  return (void **)this;
}



undefined4 * __fastcall reset_flags_clean_memory(undefined4 *param_1)

{
                    // Reset fields 1, 4, 7, 8, 9, 10, and 11
  param_1[10] = 0;
  param_1[4] = 0;
                    // First 11 items are a Header
  *param_1 = param_1 + 11;
  param_1[3] = 1;
  param_1[2] = 64;
  param_1[1] = 0;
  param_1[11] = 0;
                    // Cleanup old memory state
  if (param_1[10] == 2) {
    manage_memory_state((void *)param_1[7],param_1[9]);
    param_1[7] = 0;
    param_1[9] = 0;
    param_1[8] = 0;
    param_1[10] = 0;
  }
  return param_1;
}



void __fastcall manage_memstate(void **memory_ctx)

{
  init_mem_state_managing(memory_ctx);
  memory_ctx[10] = (void *)0x0;
  return;
}



undefined * __thiscall
allocate_object_wfallbacks(void *this,uint *allocation_type,undefined4 *status,char use_slowpath)

{
  undefined *object_aligned_ptr;
  int procdata;
  undefined4 *thread_info_block;
  undefined4 TIB;
  undefined *puStack12;
  undefined4 s8;
  uint alloctype;
  
  TIB = *thread_info_block;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b518;
  *thread_info_block = &TIB;
  alloctype = *allocation_type;
  if (alloctype == 0x40) {
    if (use_slowpath != 0) {
      *status = 1;
      *thread_info_block = TIB;
      return (undefined *)((int)this + 0x2c);
    }
  }
  else if (alloctype != 390) goto LAB_662032b7;
  object_aligned_ptr = getsafe_aligned_ptr((undefined *)this);
  if ((char)object_aligned_ptr != 0) {
    object_aligned_ptr = (undefined *)alloc_from_virtual_pool();
    if (object_aligned_ptr != (undefined *)0x0) {
      *status = 2;
      *allocation_type = 390;
      *thread_info_block = TIB;
      return object_aligned_ptr;
    }
  }
LAB_662032b7:
  procdata = get_process_data();
  s8 = 0;
  object_aligned_ptr =
       (undefined *)
       Wsafe_malloc(-(uint)((int)(((ulonglong)alloctype * 2) >> 0x20) != 0) |
                    (uint)((ulonglong)alloctype * 2));
  if (object_aligned_ptr == (undefined *)0x0) {
    *status = 0;
    object_aligned_ptr = (undefined *)0x0;
  }
  else {
    *status = 3;
  }
  s8 = 0xffffffff;
  runtimeproc_info(procdata);
  *thread_info_block = TIB;
  return object_aligned_ptr;
}



uint __thiscall
ConvertMultiByteToWideCharWithFallback
          (void *this,undefined4 param_1,uint param_2,undefined4 param_3,uint param_4)

{
  uint uVar1;
  int iVar1;
  uint uVar2;
  
  uVar1 = param_4;
  uVar2 = param_4 * 2;
  if ((param_4 <= uVar2) && (uVar2 != 0xffffffff)) {
    if (*(int *)((int)this + 0x10) == 0) {
      iVar1 = RtlMultiByteToUnicodeN(param_3,uVar2,&param_2,param_1,param_2);
      if (-1 < iVar1) {
        return param_2 >> 1;
      }
    }
    else if ((DAT_6624b474 != (code *)0x0) || (iVar1 = ResolveStringConversionAPIs(), -1 < iVar1)) {
      uVar2 = (*DAT_6624b474)(*(undefined4 *)((int)this + 0x10),0,param_1,param_2,param_3,uVar1);
      if ((int)uVar2 < 1) {
        uVar2 = 0;
      }
      return uVar2;
    }
  }
  return 0;
}



// WARNING: Could not reconcile some variable overlaps

void __thiscall
invoke_qhandler(void *this,char has_offset,short *q_function,int qfunction_offsetted,int state,
               undefined4 *sanity_check_parameter)

{
  int proc_data;
  undefined4 *thread_info_b;
  uint allocation_type;
  undefined4 statuscode;
  undefined4 usevirtualmem;
  undefined4 s24;
  undefined *object_ptr;
  int further_offset;
  int q_offsetted;
  char one;
  undefined4 thread_info_ptr;
  undefined *puStack12;
  undefined4 errnocode;
  int mem_offset;
  short *o1_qfunction;
  char q_function_character;
  short q_function_ptr;
  uint virtualmemuse;
  
  errnocode = 0xffffffff;
  puStack12 = &LAB_6621b538;
  thread_info_ptr = *thread_info_b;
  *thread_info_b = &thread_info_ptr;
  proc_data = get_process_data();
  errnocode = 0;
  if (has_offset == 0) {
    further_offset = 0;
  }
  else {
    further_offset = *(int *)((int)this + 4);
  }
  one = 1;
  switch(state) {
  case 0:
    if (qfunction_offsetted == -1) {
                    // Something went wrong, reset flags
      if (q_function == (short *)0) {
        qfunction_offsetted = 0;
        q_function_character = 0;
        break;
      }
      o1_qfunction = q_function + 1;
      do {
        q_function_ptr = *q_function;
        q_function = q_function + 1;
      } while (q_function_ptr != 0);
      qfunction_offsetted = ((int)q_function - (int)o1_qfunction) >> 1;
    }
    q_function_character = '\0';
    break;
  case 1:
    q_function_character = '\0';
    break;
  case 2:
    qfunction_offsetted = sanitycheck_parameter((int)q_function,*sanity_check_parameter);
    q_function_character = one;
    q_offsetted = qfunction_offsetted;
    if (qfunction_offsetted < 0) goto switchD_662033f6_caseD_4;
    break;
  case 3:
    if (qfunction_offsetted == -1) {
      if (q_function == (short *)0x0) {
        qfunction_offsetted = 0;
      }
      else {
        mem_offset = (int)q_function + 1;
        do {
          q_function_character = *(char *)q_function;
          q_function = (short *)((int)q_function + 1);
        } while (q_function_character != '\0');
        qfunction_offsetted = (int)q_function - mem_offset;
      }
    }
    q_function_character = 1;
    break;
  default:
    goto switchD_662033f6_caseD_4;
  }
  if (has_offset != '\0') {
    q_function_character = '\0';
  }
  q_offsetted = qfunction_offsetted;
  allocation_type = align_thresholds(qfunction_offsetted + further_offset + 2);
  virtualmemuse = usevirtualmem;
  usevirtualmem = ((int)(int3)usevirtualmem._1_3_ << 8) + 1;
  if ((allocation_type < *(uint *)((int)this + 8)) || (allocation_type == *(uint *)((int)this + 8)))
  {
    if ((q_function_character != '\0') && (*(int *)((int)this + 0xc) == 1)) {
                    // Zero-out lowest byte of s28
      usevirtualmem = virtualmemuse & 0xffffff00;
    }
  }
  else {
    q_function_character = '\x01';
  }
  statuscode = *(undefined4 *)((int)this + 0xc);
                    // WARNING: Load size is inaccurate
  object_ptr = *this;
  if (q_function_character != '\0') {
    s24 = statuscode;
    object_ptr = allocate_object_wfallbacks(this,&allocation_type,&statuscode,(char)usevirtualmem);
    if (object_ptr == (undefined *)0x0) {
switchD_662033f6_caseD_4:
      errnocode = 0xffffffff;
      runtimeproc_info(proc_data);
      *thread_info_b = thread_info_ptr;
      return;
    }
                    // WARNING: Load size is inaccurate
    FUN_6620d5b0(object_ptr,*this,further_offset * 2);
  }
                    // WARNING: Could not recover jumptable at 0x66203513. Too many branches
                    // WARNING: Treating indirect jump as call
  s24 = statuscode;
  (*(code *)(&PTR_LAB_66203650)[state])();
  return;
}



undefined4 __thiscall CompareAndProcessObjects(void *this,undefined4 *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if ((undefined4 *)this == param_1) {
    return 0;
  }
                    // WARNING: Load size is inaccurate
  uVar1 = FUN_66203690(*this,*(undefined4 *)((int)this + 4),*param_1,param_1[1],param_2);
  return uVar1;
}


/*
Unable to decompile 'FUN_66203690'
Cause: Exception while decompiling 66203690: Decompiler process died

*/


int __fastcall find_backslash(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  short *psVar1;
  
  iVar1 = *param_1;
  if ((iVar1 != 0) && (iVar2 = param_1[1], iVar2 != 0)) {
    psVar1 = (short *)(iVar1 + ((iVar2 + -1) * 2));
    do {
      iVar3 = iVar2 + -1;
      if ((*psVar1 == L'\\') || (*psVar1 == L'/')) {
        if (iVar3 == -1) {
          return iVar1;
        }
        return iVar1 + (iVar2 * 2);
      }
      psVar1 = psVar1 + -1;
      iVar2 = iVar3;
    } while (iVar3 != 0);
  }
  return iVar1;
}



void __fastcall init_mem_state_managing(void **disputed_memDATA)

{
  manage_memory_state(*disputed_memDATA,disputed_memDATA[3]);
  disputed_memDATA[3] = (void *)0x1;
  *disputed_memDATA = disputed_memDATA + 0xb;
  disputed_memDATA[2] = (void *)0x40;
  disputed_memDATA[1] = (void *)0x0;
  disputed_memDATA[0xb] = (void *)0x0;
  if (disputed_memDATA[10] == (void *)0x2) {
    manage_memory_state(disputed_memDATA[7],disputed_memDATA[9]);
    disputed_memDATA[7] = (void *)0x0;
    disputed_memDATA[9] = (void *)0x0;
    disputed_memDATA[8] = (void *)0x0;
    disputed_memDATA[10] = (void *)0x0;
  }
  return;
}



void manage_memory_state(void *disputed_memory_index,undefined4 index_is_free)

{
  int proc_data;
  undefined4 *TEB_pointer;
  undefined4 TEB;
  undefined *exception_handle;
  undefined4 s8;
  
  TEB = *TEB_pointer;
  s8 = 0xffffffff;
  exception_handle = &LAB_6621b558;
  *TEB_pointer = &TEB;
  switch(index_is_free) {
  case 2:
    mark_index_as_used((int)disputed_memory_index);
    *TEB_pointer = TEB;
    return;
  case 3:
    proc_data = get_process_data();
    s8 = 0;
    FID_conflict__free(disputed_memory_index);
    s8 = 0xffffffff;
    runtimeproc_info(proc_data);
  }
  *TEB_pointer = TEB;
  return;
}



int __thiscall FUN_66203900(void *this,int param_1,uint param_2,int *param_3)

{
  int x;
  bool bVar1;
  int iVar1;
  int iVar2;
  
  if (param_1 == -1) {
                    // WARNING: Load size is inaccurate
    if (*this == 0) {
      return 0;
    }
  }
  else {
    bVar1 = dynamic_memory_context_alloc(this,(void *)((param_1 + param_2) >> 1),(undefined *)0x1);
    if (bVar1 == false) {
      return 0;
    }
  }
                    // WARNING: Load size is inaccurate
  x = *this;
  iVar1 = get_nearest_multiple(x,param_2);
  iVar2 = *(int *)((int)this + 8);
  if (iVar2 != 0) {
    iVar2 = iVar2 + -2;
  }
  FUN_6620d410(x,0,iVar2 * 2);
  if (param_3 != (int *)0x0) {
    *param_3 = ((iVar2 * 2) - iVar1) + x;
  }
  return iVar1;
}



int alloc_from_virtual_pool(void)

{
  byte *pbVar1;
  int block_address;
  int dword_index;
  uint block_id;
  undefined4 *in_FS_OFFSET;
  bool block_available;
  undefined4 regionsize;
  int baseaddress;
  undefined4 TIB;
  undefined *puStack12;
  undefined4 s8;
  int index;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b578;
  TIB = *in_FS_OFFSET;
  *in_FS_OFFSET = &TIB;
  acquire_lock(&disputed_resource);
  s8 = 0;
  if (heap_base == 0) {
    regionsize = 0x3ffc;
    baseaddress = heap_base;
    block_address = NtAllocateVirtualMemory(0xffffffff,&baseaddress,0,&regionsize,0x1000,4);
    if (block_address < 0) goto LAB_66203a10;
    heap_base = baseaddress;
    block_bitmap = 0xffffffff;
  }
  block_address = heap_base;
  dword_index = 0;
  do {
    index = 0;
    block_available = (&block_bitmap)[dword_index] != 0;
    if (block_available) {
      for (; (((uint)(&block_bitmap)[dword_index] >> index) & 1) == 0; index = index + 1) {
      }
    }
    if (block_available) {
      block_id = (dword_index * 0x20) + index;
      if ((block_id < 0x15) && (block_id != 0xffffffff)) {
        pbVar1 = (byte *)((int)&block_bitmap + ((int)(block_id & 31) >> 3) + ((block_id >> 5) * 4));
        *pbVar1 = *pbVar1 & ~('\x01' << (block_id & 7));
        block_address = (block_id * 780) + block_address;
        goto LAB_66203a12;
      }
      break;
    }
    dword_index = dword_index + 1;
  } while (dword_index == 0);
LAB_66203a10:
  block_address = 0;
LAB_66203a12:
  LOCK();
  if (disputed_resource == 1) {
    disputed_resource = 0;
  }
  *in_FS_OFFSET = TIB;
  return block_address;
}



int ResolveStringConversionAPIs(void)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined s2c [8];
  undefined s24 [8];
  undefined4 *s1c;
  int s18;
  undefined4 s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b578;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s1c = &disputed_resource;
  acquire_lock(&disputed_resource);
  s8 = 0;
  RtlInitUnicodeString(s24,u_kernel32_dll_6621ca24);
  iVar1 = LdrGetDllHandle(1,0,s24,&s14);
  if (-1 < iVar1) {
    if (DAT_6624b470 == 0) {
      RtlInitAnsiString(s2c,s_WideCharToMultiByte_6621ca40);
      iVar1 = LdrGetProcedureAddress(s14,s2c,0,&s18);
      if (iVar1 < 0) goto LAB_66203b43;
      DAT_6624b470 = s18;
    }
    if (DAT_6624b474 == 0) {
      RtlInitAnsiString(s2c,s_MultiByteToWideChar_6621ca54);
      iVar1 = LdrGetProcedureAddress(s14,s2c,0,&s18);
      if (-1 < iVar1) {
        DAT_6624b474 = s18;
      }
    }
  }
LAB_66203b43:
  LOCK();
  if (disputed_resource == 1) {
    disputed_resource = 0;
  }
  *in_FS_OFFSET = s10;
  return iVar1;
}



void __fastcall clean_context_memory(int param_1)

{
  if (*(int *)(param_1 + 0x28) == 2) {
    manage_memory_state(*(void **)(param_1 + 0x1c),*(undefined4 *)(param_1 + 0x24));
    *(undefined4 *)(param_1 + 0x1c) = 0;
    *(undefined4 *)(param_1 + 0x24) = 0;
    *(undefined4 *)(param_1 + 0x20) = 0;
    *(undefined4 *)(param_1 + 0x28) = 0;
  }
  return;
}



int __cdecl mark_index_as_used(int param_1)

{
  byte *pbVar1;
  int resource_buffer;
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *exception_handle;
  undefined4 s8;
  uint blocksize;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  exception_handle = &exceptionhandler;
  *in_FS_OFFSET = &s10;
  blocksize = ((param_1 - heap_base) >> 1) / 0x186;
  acquire_lock(&disputed_resource);
  pbVar1 = (byte *)((int)&block_bitmap + ((int)(blocksize & 0x1f) >> 3) + ((blocksize >> 5) * 4));
  *pbVar1 = *pbVar1 | ('\x01' << (blocksize & 7));
  LOCK();
  resource_buffer = disputed_resource;
  if (disputed_resource == 1) {
    disputed_resource = 0;
    resource_buffer = 1;
  }
                    // Reset flag
                    // 
  *in_FS_OFFSET = s10;
  return resource_buffer;
}



int __cdecl align_thresholds(uint param_1)

{
  int iVar1;
  
  if (param_1 < 65) {
    return 64;
  }
  if (param_1 < 2048) {
    iVar1 = get_nearest_multiple(param_1,390);
    return iVar1;
  }
  if (param_1 < 524288) {
    iVar1 = get_nearest_multiple(param_1,2048);
    return iVar1;
  }
  iVar1 = get_nearest_multiple(param_1,524288);
  return iVar1;
}



undefined * __cdecl SelectDefaultOrProvidedPointer(undefined *param_1,undefined *param_2)

{
  if ((param_1 == (undefined *)0x0) && (param_1 = &DAT_6621ca68, param_2 != (undefined *)0x0)) {
    param_1 = param_2;
  }
  return param_1;
}



void __thiscall update_context(void *this,uint context_number)

{
  uint parameter_is_nil;
  
                    // WARNING: Load size is inaccurate
                    // If there is no context, grab it from qhandler
  if (*this == 0) {
    invoke_qhandler(this,'\0',(short *)0x0,0,0,(undefined4 *)0x0);
    return;
  }
  if (*(int *)((int)this + 8) == 0) {
    parameter_is_nil = 0;
  }
  else {
    parameter_is_nil = *(int *)((int)this + 8) - 2;
  }
  if (parameter_is_nil < context_number) {
    context_number = parameter_is_nil;
  }
  *(uint *)((int)this + 4) = context_number;
  *(undefined4 *)(*this + (context_number * 2)) = 0;
  if (*(int *)((int)this + 0x28) == 2) {
    manage_memory_state(*(void **)((int)this + 0x1c),*(undefined4 *)((int)this + 0x24));
    *(undefined4 *)((int)this + 0x1c) = 0;
    *(undefined4 *)((int)this + 0x24) = 0;
    *(undefined4 *)((int)this + 0x20) = 0;
    *(undefined4 *)((int)this + 0x28) = 0;
  }
  return;
}



void __fastcall safe_mem_access(void **mem_in_use)

{
  init_mem_state_managing(mem_in_use);
  *mem_in_use = (void *)0x0;
  mem_in_use[3] = (void *)0x0;
  mem_in_use[2] = (void *)0x0;
  mem_in_use[1] = (void *)0x0;
  if (mem_in_use[10] == (void *)0x2) {
    manage_memory_state(mem_in_use[7],mem_in_use[9]);
    mem_in_use[7] = (void *)0x0;
    mem_in_use[9] = (void *)0x0;
    mem_in_use[8] = (void *)0x0;
    mem_in_use[10] = (void *)0x0;
  }
  return;
}



int __cdecl
queryVar_allocatePolicy(undefined4 policy_pair_count,void *policy_paircount_ptr,undefined4 bool1)

{
  bool success;
  int environment_varZ;
  void *pvVar1;
  undefined4 *in_FS_OFFSET;
  short *context [2];
  void *sc8;
  undefined destination_string [8];
  ushort envvar_value;
  short s16;
  short *s14;
  undefined4 thread_info_block;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b5bb;
  thread_info_block = *in_FS_OFFSET;
  *in_FS_OFFSET = &thread_info_block;
  reset_flags_clean_memory(context);
  s8 = 0;
  dynamic_memory_context_alloc(context,(void *)65,(undefined *)0);
  RtlInitUnicodeString(destination_string,policy_pair_count);
  do {
    pvVar1 = sc8;
    if ((sc8 != (void *)0x0) && (pvVar1 = (void *)((int)sc8 + -2), (void *)0x7fff < pvVar1)) {
      pvVar1 = (void *)0x7fff;
    }
    envvar_value = 0;
    s16 = (short)pvVar1 * 2;
    s14 = context[0];
    environment_varZ = RtlQueryEnvironmentVariable_U(bool1,destination_string,&envvar_value);
    if (-1 < environment_varZ) {
      update_context(context,(uint)(envvar_value >> 1));
      if (policy_paircount_ptr != (void *)0x0) {
        WGetContext(policy_paircount_ptr,context);
      }
      environment_varZ = 0;
      goto LAB_66203e80;
    }
    if (environment_varZ != -0x3fffffdd) goto LAB_66203e80;
    if (((void *)0x7ffe < pvVar1) || ((void *)(uint)(envvar_value >> 1) <= pvVar1)) break;
    success = dynamic_memory_context_alloc
                        (context,(void *)(uint)(envvar_value >> 1),(undefined *)0x1);
  } while (success != false);
  environment_varZ = -0x3fffff66;
LAB_66203e80:
  s8 = 0xffffffff;
  init_mem_state_managing(context);
  *in_FS_OFFSET = thread_info_block;
  return environment_varZ;
}



int * __fastcall FindLastPathSeparatorAndUpdateContext(int *param_1)

{
  uint context_number;
  uint uVar1;
  short *psVar1;
  
  if ((*param_1 != 0) && (context_number = param_1[1], context_number != 0)) {
    psVar1 = (short *)(*param_1 + (context_number * 2));
    while( true ) {
      psVar1 = psVar1 + -1;
      uVar1 = context_number - 1;
      if ((*psVar1 == 0x5c) || (*psVar1 == 0x2f)) break;
      context_number = uVar1;
      if (uVar1 == 0) {
        return param_1;
      }
    }
    if (uVar1 != 0xffffffff) {
      update_context(param_1,context_number);
    }
  }
  return param_1;
}



// Library Function - Single Match
//  public: __cdecl Concurrency::SchedulerPolicy::SchedulerPolicy(unsigned int,...)
// 
// Library: Visual Studio 2015 Release

unsigned_int __thiscall
Concurrency::SchedulerPolicy::SchedulerPolicy(SchedulerPolicy *this,unsigned_int param_1,...)

{
  short *in_stack_00000008;
  undefined *s8;
  
  s8 = &stack0x0000000c;
  FUN_66202de0((void *)param_1,in_stack_00000008,&s8);
  return param_1;
}



short ** __thiscall get_context(void *this,short **context_blob)

{
  if ((short **)this != context_blob) {
    if (*context_blob == (short *)0x0) {
      safe_mem_access((void **)this);
      return (short **)this;
    }
    invoke_qhandler(this,0,*context_blob,(int)context_blob[1],0,(undefined4 *)0x0);
  }
  return (short **)this;
}


/*
Unable to decompile 'FUN_66203f60'
Cause: Exception while decompiling 66203f60: Decompiler process died

*/


// WARNING: Could not reconcile some variable overlaps

void ** __thiscall AllocateAndConvertWideStringBuffer(void *this,ushort *param_1)

{
  char cVar1;
  uint uVar1;
  int iVar1;
  uint uVar2;
  ushort *puVar1;
  undefined4 *in_FS_OFFSET;
  uint s1c;
  undefined4 s18;
  undefined4 s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b5f8;
  *in_FS_OFFSET = &s10;
  if (param_1 == (ushort *)0x0) {
    uVar2 = 0;
    param_1 = (ushort *)0x0;
  }
  else {
    uVar2 = (uint)*param_1;
    param_1 = *(ushort **)(param_1 + 2);
  }
  iVar1 = get_process_data();
  s8 = 0;
  if (uVar2 == 0xffffffff) {
    if (param_1 == (ushort *)0x0) {
      uVar2 = 0;
    }
    else {
      puVar1 = param_1;
      do {
        cVar1 = *(char *)puVar1;
        puVar1 = (ushort *)((int)puVar1 + 1);
      } while (cVar1 != '\0');
      uVar2 = (int)puVar1 - ((int)param_1 + 1);
    }
  }
  s1c = align_thresholds(uVar2 + 2);
  uVar1 = (uint)s14;
  s14 = (undefined *)(((int)(int3)s14._1_3_ << 8) + 1);
  if (((s1c < *(uint *)((int)this + 8)) || (s1c == *(uint *)((int)this + 8))) &&
     (*(int *)((int)this + 0xc) == 1)) {
    s14 = (undefined *)(uVar1 & 0xffffff00);
  }
  s18 = *(undefined4 *)((int)this + 0xc);
  s14 = allocate_object_wfallbacks(this,&s1c,&s18,(char)s14);
  if (s14 != (undefined *)0x0) {
    if (uVar2 == 0) {
      uVar2 = 0;
    }
    else {
      uVar2 = ConvertMultiByteToWideCharWithFallback(this,param_1,uVar2,s14,uVar2);
      if (uVar2 == 0xffffffff) {
        manage_memory_state(s14,s18);
        goto LAB_6620417e;
      }
    }
    *(uint *)((int)this + 4) = uVar2;
    *(undefined4 *)(s14 + (uVar2 * 2)) = 0;
                    // WARNING: Load size is inaccurate
    manage_memory_state(*this,*(undefined4 *)((int)this + 0xc));
    *(undefined **)this = s14;
    *(undefined4 *)((int)this + 0xc) = s18;
    *(uint *)((int)this + 8) = s1c;
    clean_context_memory((int)this);
  }
LAB_6620417e:
  s8 = 0xffffffff;
  runtimeproc_info(iVar1);
  *in_FS_OFFSET = s10;
  return (void **)this;
}



void ** __thiscall safeget_ctxblob(void *this,short *has_offset,int context_blob)

{
  if ((has_offset == (short *)0x0) && (context_blob == -1)) {
    safe_mem_access((void **)this);
    return (void **)this;
  }
  invoke_qhandler(this,'\0',has_offset,context_blob,0,(undefined4 *)0x0);
  return (void **)this;
}



void ** __thiscall ProcessSubstringOperation(void *this,int *param_1,uint param_2,uint param_3)

{
  short *q_function;
  uint uVar1;
  
  uVar1 = param_1[1];
  if (uVar1 < param_2) {
    param_2 = uVar1;
  }
  if ((uVar1 - param_2) < param_3) {
    param_3 = uVar1 - param_2;
  }
  q_function = (short *)(*param_1 + (param_2 * 2));
  if ((q_function == (short *)0x0) && (param_3 == 0xffffffff)) {
    safe_mem_access((void **)this);
    return (void **)this;
  }
  invoke_qhandler(this,'\0',q_function,param_3,0,(undefined4 *)0x0);
  return (void **)this;
}



int __fastcall GetEffectiveStringLength(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 8);
  if (iVar1 == 0) {
    return iVar1;
  }
  return iVar1 + -2;
}



uint __thiscall
find_backslash_substring(void *this,short *backslash_position,uint param_2,uint param_3)

{
  short sVar1;
  int iVar1;
  uint uVar1;
  short *psVar1;
  
  if (param_3 == 0xffffffff) {
    if (backslash_position == (short *)0x0) {
      param_3 = 0;
    }
    else {
      psVar1 = backslash_position;
      do {
        sVar1 = *psVar1;
        psVar1 = psVar1 + 1;
      } while (sVar1 != 0);
      param_3 = ((int)psVar1 - (int)(backslash_position + 1)) >> 1;
    }
  }
  if (param_3 <= *(uint *)((int)this + 4)) {
    uVar1 = *(uint *)((int)this + 4) - param_3;
    if (param_2 <= uVar1) {
      do {
                    // WARNING: Load size is inaccurate
        iVar1 = FUN_66203690(*this + (param_2 * 2),param_3,backslash_position,param_3,0);
        if (iVar1 == 0) {
          return param_2;
        }
        param_2 = param_2 + 1;
      } while (param_2 <= uVar1);
    }
  }
  return 0xffffffff;
}



uint __thiscall search_array(void *this,short searchkey,uint index)

{
  short *arrayitem;
  
  if (index < *(uint *)((int)this + 4)) {
                    // WARNING: Load size is inaccurate
    arrayitem = (short *)(*this + (index * 2));
    do {
      if (*arrayitem == searchkey) {
        return index;
      }
      index = index + 1;
      arrayitem = arrayitem + 1;
    } while (index < *(uint *)((int)this + 4));
  }
  return 0xffffffff;
}



undefined4 * __fastcall PrepareUnicodeStringBuffer(undefined4 *param_1)

{
  int iVar1;
  
  if (0x7fff < (uint)param_1[1]) {
    param_1[6] = 0;
    *(undefined2 *)((int)param_1 + 0x16) = 0;
    *(undefined2 *)(param_1 + 5) = 0;
    return param_1 + 5;
  }
  iVar1 = param_1[2];
  param_1[6] = *param_1;
  *(short *)(param_1 + 5) = *(short *)(param_1 + 1) * 2;
  if (iVar1 != 0) {
    if (0x7ffe < (iVar1 - 2U)) {
      *(undefined2 *)((int)param_1 + 0x16) = 0xfffe;
      return param_1 + 5;
    }
    if (iVar1 != 0) {
      *(short *)((int)param_1 + 0x16) = ((short)iVar1 + -2) * 2;
      return param_1 + 5;
    }
  }
  *(undefined2 *)((int)param_1 + 0x16) = 0;
  return param_1 + 5;
}



void * __thiscall cleanupmemstate(void *this,void *param_1,short *param_2)

{
  short **mem_in_use;
  undefined4 *TIB_ptr;
  void *sc4 [44];
  undefined4 s14;
  undefined4 TIB;
  undefined *ctx_framehandler;
  uint s8;
  
  s8 = 0xffffffff;
  ctx_framehandler = &LAB_6621b634;
  TIB = *TIB_ptr;
  *TIB_ptr = &TIB;
  s14 = 0;
  if ((*(short **)((int)this + 4) <= param_2) && (param_2 != *(short **)((int)this + 4))) {
    param_2 = *(short **)((int)this + 4);
  }
  mem_in_use = (short **)reset_flags_clean_memory(sc4);
  s8 = 1;
                    // WARNING: Load size is inaccurate
  if ((*this == (short *)0x0) && (param_2 == (short *)0xffffffff)) {
    safe_mem_access(mem_in_use);
  }
  else {
    invoke_qhandler(mem_in_use,'\0',*this,(int)param_2,0,(undefined4 *)0x0);
  }
  cleanup_ctxblob(param_1,mem_in_use);
  s14 = 1;
  s8 = s8 & 0xffffff00;
  init_mem_state_managing(sc4);
  *TIB_ptr = TIB;
  return param_1;
}



bool __thiscall
dynamic_memory_context_alloc(void *this,void *alloc_type,undefined *safe_object_alloc)

{
  uint x;
  undefined *puVar1;
  void *pvVar1;
  void *s8;
  
  x = (int)alloc_type + 2;
  pvVar1 = alloc_type;
  if ((char)safe_object_alloc != '\0') {
    pvVar1 = (void *)0x0;
  }
  s8 = this;
  if (x < 0x41) {
    alloc_type = (void *)64;
  }
  else {
    if (x < 0x800) {
      alloc_type = (void *)get_nearest_multiple(x,390);
    }
    else if (x < 0x80000) {
      alloc_type = (void *)get_nearest_multiple(x,2048);
    }
    else {
      alloc_type = (void *)get_nearest_multiple(x,524288);
    }
  }
  if (alloc_type == *(void **)((int)this + 8)) {
    if ((char)safe_object_alloc != '\0') {
      update_context(this,0);
      return true;
    }
    if ((pvVar1 <= *(void **)((int)this + 4)) && (*(void **)((int)this + 4) != pvVar1)) {
      *(void **)((int)this + 4) = pvVar1;
      clean_context_memory((int)this);
      return true;
    }
  }
  else {
    safe_object_alloc = allocate_object_wfallbacks(this,(uint *)&alloc_type,&s8,'\x01');
    if (safe_object_alloc == (undefined *)0x0) {
      return (x < *(uint *)((int)this + 8)) || (x == *(uint *)((int)this + 8));
    }
    if ((pvVar1 <= *(void **)((int)this + 4)) && (*(void **)((int)this + 4) != pvVar1)) {
      *(void **)((int)this + 4) = pvVar1;
      clean_context_memory((int)this);
    }
    puVar1 = safe_object_alloc;
                    // WARNING: Load size is inaccurate
    FUN_6620d5b0(safe_object_alloc,*this,*(int *)((int)this + 4) * 2);
    *(undefined4 *)(puVar1 + (*(int *)((int)this + 4) * 2)) = 0;
                    // WARNING: Load size is inaccurate
    manage_memory_state(*this,*(undefined4 *)((int)this + 0xc));
    *(void **)((int)this + 0xc) = s8;
    *(undefined **)this = puVar1;
    *(void **)((int)this + 8) = alloc_type;
  }
  return true;
}



int __thiscall FindLastWCharOccurrence(void *this,short param_1,uint param_2)

{
  uint uVar1;
  short *psVar1;
  
  uVar1 = *(uint *)((int)this + 4);
  if (param_2 < uVar1) {
    uVar1 = param_2 + 1;
  }
  if (uVar1 != 0) {
                    // WARNING: Load size is inaccurate
    psVar1 = (short *)(*this + (uVar1 * 2));
    do {
      psVar1 = psVar1 + -1;
      if (*psVar1 == param_1) {
        return uVar1 - 1;
      }
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
  return -1;
}



// Library Function - Single Match
//  public: __cdecl Concurrency::SchedulerPolicy::SchedulerPolicy(unsigned int,...)
// 
// Library: Visual Studio 2015 Release

unsigned_int __thiscall
Concurrency::SchedulerPolicy::SchedulerPolicy(SchedulerPolicy *this,unsigned_int param_1,...)

{
  ushort *in_stack_00000008;
  int *s8;
  
  s8 = (int *)&stack0x0000000c;
  SafeConvertAndStoreWideString((void *)param_1,in_stack_00000008,&s8);
  return param_1;
}



// WARNING: Could not reconcile some variable overlaps

char ** __thiscall SafeConvertAndStoreWideString(void *this,ushort *param_1,int **param_2)

{
  uint uVar1;
  int iVar1;
  uint uVar2;
  char *disputed_memory_index;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  uint s1c;
  undefined4 s18;
  undefined4 s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b648;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  iVar1 = get_process_data();
  s8 = 0;
  uVar2 = sanitycheck_parameter((int)param_1,*param_2);
  if ((int)uVar2 < 0) {
    s8 = 0xffffffff;
    runtimeproc_info(iVar1);
    *in_FS_OFFSET = s10;
    return (char **)this;
  }
  s1c = align_thresholds(uVar2 + 2);
  uVar1 = s18;
  s18 = ((int)(int3)s18._1_3_ << 8) + 1;
  if (((s1c < *(uint *)((int)this + 8)) || (s1c == *(uint *)((int)this + 8))) &&
     (*(int *)((int)this + 0xc) == 1)) {
    s18 = uVar1 & 0xffffff00;
  }
  s14 = *(undefined4 *)((int)this + 0xc);
  disputed_memory_index = allocate_object_wfallbacks(this,&s1c,&s14,(char)s18);
  if (disputed_memory_index != (char *)0x0) {
    iVar2 = FUN_6620e249(disputed_memory_index,uVar2,param_1,(int **)*param_2);
    if ((iVar2 < 0) || (iVar2 == -1)) {
      manage_memory_state(disputed_memory_index,s14);
    }
    else {
      *(int *)((int)this + 4) = iVar2;
      *(undefined4 *)(disputed_memory_index + (iVar2 * 2)) = 0;
                    // WARNING: Load size is inaccurate
      manage_memory_state(*this,*(undefined4 *)((int)this + 0xc));
      *(undefined4 *)((int)this + 0xc) = s14;
      *(char **)this = disputed_memory_index;
      *(uint *)((int)this + 8) = s1c;
      clean_context_memory((int)this);
    }
  }
  s8 = 0xffffffff;
  runtimeproc_info(iVar1);
  *in_FS_OFFSET = s10;
  return (char **)this;
}



int __cdecl CompareWideCharBuffers(ushort *param_1,ushort *param_2,int param_3)

{
  if (param_3 != 0) {
    do {
      if (*param_1 != *param_2) {
        return (-(uint)(*param_1 < *param_2) & 0xfffffffe) + 1;
      }
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  return 0;
}


/*
Unable to decompile '_wmemset'
Cause: Exception while decompiling 66204730: Decompiler process died

*/


uint __thiscall CheckWideStringCapacityAndFindEntry(void *this,short *param_1)

{
  short *psVar1;
  uint uVar1;
  
  psVar1 = (short *)(((uint)*(ushort *)((int)this + 10) * 0x10) + 0x16);
  if (psVar1 <= param_1) {
    psVar1 = (short *)CalculateWideStringCapacity(this,(uint)param_1);
    if ((char)psVar1 != '\0') {
      uVar1 = FindWideStringTableEntry(this,param_1);
      return (uVar1 & 0xffffff00) | (uint)((char)uVar1 != '\0');
    }
  }
  return (uint)psVar1 & 0xffffff00;
}



uint __thiscall FindWideStringTableEntry(void *this,short *param_1)

{
  short *psVar1;
  int iVar1;
  ushort uVar1;
  short *psVar2;
  uint3 uVar2;
  ushort uVar3;
  uint uVar4;
  
  uVar1 = *(ushort *)((int)this + ((uint)*(ushort *)((int)this + 10) * 0x10) + 0x12);
  psVar2 = (short *)(uint)uVar1;
  uVar2 = (uint3)(byte)(uVar1 >> 8);
  if (uVar1 == 0) {
    return ((int)(int3)uVar2 << 8) + 1;
  }
  if (param_1 < (psVar2 + 1)) {
    return (uint)uVar2 << 8;
  }
  uVar1 = *(ushort *)((int)psVar2 + (int)this);
  iVar1 = (int)psVar2 + (int)this;
  if (uVar1 != 0) {
    psVar2 = psVar2 + 1 + ((uint)uVar1 * 3);
    if (psVar2 <= param_1) {
      uVar4 = (uint)((int)param_1 - (int)psVar2) >> 1;
      if (uVar4 != 0) {
        psVar2 = (short *)((int)this + (int)psVar2 + ((uVar4 - 1) * 2));
        do {
          if (*psVar2 == 0) {
            psVar1 = (short *)(uVar4 - 1);
            if (psVar1 != (short *)0xffffffff) {
              psVar2 = (short *)0x0;
              uVar3 = 0;
              if (uVar1 != 0) goto LAB_66204820;
              goto LAB_66204841;
            }
            break;
          }
          psVar2 = psVar2 + -1;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
      }
    }
LAB_66204801:
    return (uint)psVar2 & 0xffffff00;
  }
LAB_66204841:
  return ((int)(int3)((uint)psVar2 >> 8) << 8) + 1;
  while (uVar3 = uVar3 + 1, uVar3 < uVar1) {
LAB_66204820:
    psVar2 = (short *)(uint)*(ushort *)(((uint)uVar3 * 2) + 2 + iVar1);
    if ((psVar1 < psVar2) ||
       (psVar2 = (short *)(uint)*(ushort *)(iVar1 + 2 + (((uint)uVar1 + ((uint)uVar3 * 2)) * 2)),
       psVar1 < psVar2)) goto LAB_66204801;
  }
  goto LAB_66204841;
}



uint __thiscall CalculateWideStringCapacity(void *this,uint param_1)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  int iVar1;
  
  uVar1 = *(ushort *)((int)this + (((*(ushort *)((int)this + 10)) + 1) * 0x10));
  uVar2 = (uint)uVar1;
  if (uVar1 != 0) {
    if (uVar2 < param_1) {
      uVar3 = (param_1 - uVar2) >> 1;
      if (uVar1 == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = (int)this + uVar2;
      }
      uVar2 = 0;
      if (uVar3 != 0) {
        while (*(short *)(iVar1 + (uVar2 * 2)) != 0) {
          uVar2 = uVar2 + 1;
          if (uVar3 <= uVar2) {
            return uVar2 & 0xffffff00;
          }
        }
        if (uVar2 < uVar3) goto LAB_66204868;
      }
    }
    return uVar2 & 0xffffff00;
  }
LAB_66204868:
  return ((int)(int3)(uVar2 >> 8) << 8) + 1;
}



ushort * __thiscall FUN_662048b0(void *this,undefined4 param_1)

{
  ushort uVar1;
  ushort *puVar1;
  int iVar1;
  uint uVar2;
  ushort uVar3;
  
  uVar3 = 0;
  while( true ) {
    uVar1 = *(ushort *)((int)this + ((uint)*(ushort *)((int)this + 10) * 0x10) + 0x12);
    if (uVar1 == 0) {
      return (ushort *)0x0;
    }
    puVar1 = (ushort *)((uint)uVar1 + (int)this);
    uVar2 = (uint)*puVar1;
    if (*puVar1 <= uVar3) {
      return (ushort *)0x0;
    }
    uVar1 = puVar1[uVar2 + ((uint)uVar3 * 2) + 1];
    if (puVar1 + (uVar2 * 3) + (uVar1) + 1 == (ushort *)0x0) {
      return (ushort *)0x0;
    }
    iVar1 = FUN_66203690(puVar1 + (uVar2 * 3) + (puVar1[(uVar3) + 1]) + 1,0xffffffff,param_1,
                         0xffffffff,0);
    if (iVar1 == 0) break;
    uVar3 = uVar3 + 1;
    if (uVar3 == 0xffff) {
      return (ushort *)0x0;
    }
  }
  return puVar1 + (uVar2 * 3) + (uVar1) + 1;
}



bool __fastcall IsValidThinAppSignature(int *param_1)

{
  return *param_1 == 0x6e696874;
}



int __fastcall GetExtendedHeaderOffset(int param_1)

{
  ushort uVar1;
  
  uVar1 = *(ushort *)(param_1 + (((*(ushort *)(param_1 + 10)) + 1) * 0x10));
  if (uVar1 != 0) {
    return (uint)uVar1 + param_1;
  }
  return 0;
}



bool __fastcall CheckExtendedHeaderFlag(int param_1)

{
  return *(short *)(param_1 + (((*(ushort *)(param_1 + 10)) + 1) * 0x10)) != 0;
}



// WARNING: Could not reconcile some variable overlaps

undefined4 * __fastcall InitializeExtendedObjectState(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b684;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  reset_flags_clean_memory(param_1);
  s8 = 0;
  reset_flags_clean_memory(param_1 + 0x2c);
  s8 = ((int)(int3)s8._1_3_ << 8) + 1;
  param_1[0x58] = 0;
  param_1[0x5a] = 0;
  param_1[0x5b] = 0;
  param_1[0x5c] = 0;
  param_1[0x5d] = 0;
  InitializeObjectWithDefaults(param_1 + 0x5e,0);
  param_1[0x62] = 0;
  *(undefined *)(param_1 + 99) = 0;
  *in_FS_OFFSET = s10;
  return param_1;
}



// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_66204a40(void **param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b684;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s8 = 2;
  ResetFileHandleState((int)param_1);
  safe_mem_access(param_1);
  safe_mem_access(param_1 + 0x2c);
  CleanupAndResetProcessInfo(param_1 + 0x5e);
  s8._0_1_ = 1;
  FUN_66207460(param_1 + 0x5e);
  s8 = (uint)s8._1_3_ << 8;
  manage_memstate(param_1 + 0x2c);
  s8 = 0xffffffff;
  manage_memstate(param_1);
  *in_FS_OFFSET = s10;
  return;
}



void __fastcall FUN_66204ad0(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *_Memory;
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b69b;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  puVar1 = (undefined4 *)(param_1 + 0x10);
  _Memory = (undefined4 *)*puVar1;
  while (_Memory != puVar1) {
    puVar2 = (undefined4 *)*_Memory;
    s8 = 0xffffffff;
    manage_memstate((void **)(_Memory + 2));
    FID_conflict__free(_Memory);
    _Memory = puVar2;
  }
  *(undefined4 **)(param_1 + 0x14) = puVar1;
  *puVar1 = puVar1;
  *in_FS_OFFSET = s10;
  return;
}



void __fastcall ResetFileHandleState(int param_1)

{
  *(undefined4 *)(param_1 + 0x160) = 0;
  *(undefined4 *)(param_1 + 0x168) = 0;
  *(undefined4 *)(param_1 + 0x16c) = 0;
  *(undefined *)(param_1 + 0x18c) = 0;
  if (*(int *)(param_1 + 0x170) != 0) {
    NtClose(*(int *)(param_1 + 0x170));
    *(undefined4 *)(param_1 + 0x170) = 0;
  }
  if (*(int *)(param_1 + 0x174) != 0) {
    NtClose(*(int *)(param_1 + 0x174));
    *(undefined4 *)(param_1 + 0x174) = 0;
  }
  return;
}



void __fastcall FUN_66204b90(void **param_1)

{
  ResetFileHandleState((int)param_1);
  safe_mem_access(param_1);
  safe_mem_access(param_1 + 0x2c);
  CleanupAndResetProcessInfo(param_1 + 0x5e);
  return;
}



int __cdecl
FUN_66204bc0(byte *param_1,uint param_2,int param_3,undefined4 *param_4,int *param_5,int *param_6,
            char param_7)

{
  bool bVar1;
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined s1a8 [80];
  int s158;
  int *s88 [24];
  int s28;
  undefined4 s24;
  undefined4 s20;
  undefined4 s1c;
  undefined4 s18;
  int s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b6bb;
  *in_FS_OFFSET = &s10;
  if ((param_1 == (byte *)0x0) || (bVar1 = true, param_3 != -1)) {
    bVar1 = false;
  }
  FUN_66207c60(s88,-1,1);
  s8 = 0;
  if (bVar1) {
    iVar1 = FUN_66208a40(param_1,(int)param_1 >> 0x1f,0,s1a8,param_2,0);
    if (iVar1 < 0) goto LAB_66204d61;
    FUN_66208c20((int)s1a8);
    param_3 = s158;
  }
  s20 = 0x40;
  if (param_7 != '\0') {
    s20 = 4;
  }
  s24 = 0;
  s28 = param_3;
  iVar1 = NtCreateSection(&s18,0xf,0,&s28,s20,0x8000000,0);
  if (iVar1 < 0) goto LAB_66204d61;
  s14 = 0;
  s1c = 0;
  iVar1 = NtMapViewOfSection(s18,0xffffffff,&s14,1,0,0,&s1c,2,0x100000,s20);
  if (iVar1 < 0) {
LAB_66204cf4:
    NtClose(s18);
  }
  else {
    if (bVar1) {
      iVar1 = FUN_662086a0((int)s1a8,(int)param_1,param_2,s14);
      if (iVar1 < 0) {
        NtUnmapViewOfSection(0xffffffff,s14);
        goto LAB_66204cf4;
      }
    }
    else if (param_1 != (byte *)0x0) {
      if (param_2 == 0) {
        FUN_6620d5b0(s14,param_1);
      }
      else {
        FUN_6620b470(param_1,param_2,s14,param_3);
      }
    }
    if (param_4 == (undefined4 *)0x0) {
      NtClose(s18);
    }
    else {
      *param_4 = s18;
    }
    if (param_5 == (int *)0x0) {
      NtUnmapViewOfSection(0xffffffff,s14);
    }
    else {
      *param_5 = s14;
    }
    if (param_6 != (int *)0x0) {
      *param_6 = param_3;
    }
    iVar1 = 0;
  }
LAB_66204d61:
  s8 = 0xffffffff;
  FUN_66207e40(s88);
  *in_FS_OFFSET = s10;
  return iVar1;
}



int __thiscall FUN_66204d90(void *this,undefined4 *param_1,int *param_2,int param_3,int *param_4)

{
  int iVar1;
  byte *pbVar1;
  uint uVar1;
  uint uVar2;
  uint *puVar1;
  undefined4 *in_FS_OFFSET;
  void *scc [44];
  uint s1c;
  uint s18;
  int s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b6db;
  *in_FS_OFFSET = &s10;
  puVar1 = (uint *)(((param_3 + 1) * 0x10) + *(int *)((int)this + 0x178));
  if (puVar1[2] == 0) {
    *in_FS_OFFSET = s10;
    return -0x3ffffff1;
  }
  iVar1 = SynchronizedFileReadOperation(this,*puVar1,puVar1[1],&s1c,0xc,0);
  if (-1 < iVar1) {
    reset_flags_clean_memory(scc);
    s8 = 0;
    pbVar1 = (byte *)FUN_66203900(scc,s18,1,(int *)0x0);
    if (pbVar1 == (byte *)0x0) {
      iVar1 = -0x3fffff66;
    }
    else {
      iVar1 = SynchronizedFileReadOperation
                        (this,*puVar1 + 0xc,puVar1[1] + (uint)(0xfffffff3 < *puVar1),pbVar1,s18,0);
      if (-1 < iVar1) {
        uVar1 = s18;
        if (s14 != 0) {
          uVar1 = s1c;
        }
        uVar2 = 0;
        if (s14 != 0) {
          uVar2 = s18;
        }
        iVar1 = FUN_66204bc0(pbVar1,uVar2,uVar1,param_1,param_2,param_4,'\0');
        if (-1 < iVar1) {
          iVar1 = 0;
        }
      }
    }
    s8 = 0xffffffff;
    manage_memstate(scc);
  }
  *in_FS_OFFSET = s10;
  return iVar1;
}



// WARNING: Could not reconcile some variable overlaps

int __thiscall FUN_66204eb0(void *this,ushort *param_1,int **param_2)

{
  int **ppiVar1;
  int *piVar1;
  int iVar1;
  int **_Memory;
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  short *sc4 [44];
  void *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b727;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s14 = this;
  InitializeStringBufferObject(sc4,param_1);
  s8 = 0;
  ppiVar1 = (int **)((int)this + 0x10);
  for (_Memory = (int **)*ppiVar1; _Memory != ppiVar1; _Memory = (int **)*_Memory) {
    iVar1 = CompareAndProcessObjects(sc4,_Memory + 2,1);
    if (iVar1 == 0) goto LAB_66204fdb;
  }
  _Memory = (int **)safe_malloc(0x1e0);
  s8._0_1_ = 1;
  if (_Memory == (int **)0x0) {
    _Memory = (int **)0x0;
  }
  else {
    reset_flags_clean_memory(_Memory + 2);
  }
  s8 = (uint)s8._1_3_ << 8;
  if (_Memory == (int **)0x0) {
    iVar1 = -0x3fffff66;
  }
  else {
    get_context(_Memory + 2,sc4);
    puVar1 = PrepareUnicodeStringBuffer(_Memory + 2);
    iVar1 = LdrLoadDll(0,0,puVar1,_Memory + 0x2e);
    if (-1 < iVar1) {
      iVar1 = FUN_66208a40(_Memory[0x2e],(int)_Memory[0x2e] >> 0x1f,1,_Memory + 0x30,0xffffffff,
                           0xffffffff);
      if (-1 < iVar1) {
        piVar1 = *ppiVar1;
        *_Memory = piVar1;
        _Memory[1] = (int *)ppiVar1;
        piVar1[1] = (int)_Memory;
        *ppiVar1 = (int *)_Memory;
LAB_66204fdb:
        iVar1 = 0;
        *param_2 = (int *)_Memory;
        goto LAB_66204fe2;
      }
      LdrUnloadDll(_Memory[0x2e]);
    }
    s8 = s8 & 0xffffff00;
    manage_memstate(_Memory + 2);
    FID_conflict__free(_Memory);
  }
LAB_66204fe2:
  s8 = 0xffffffff;
  manage_memstate(sc4);
  *in_FS_OFFSET = s10;
  return iVar1;
}



uint __cdecl FUN_66205010(char param_1,short *param_2,short **param_3)

{
  wchar_t *pwVar1;
  int iVar1;
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  uint *in_FS_OFFSET;
  void *s110 [44];
  undefined s60 [40];
  uint s38;
  uint s34;
  undefined4 s28;
  undefined4 s24;
  undefined4 *s20;
  undefined4 s1c;
  undefined4 s18;
  undefined4 s14;
  uint s10;
  undefined *puStack12;
  undefined4 s8;
  
  uVar1 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b74b;
  *in_FS_OFFSET = (uint)&s10;
  uVar3 = 0;
  s10 = uVar1;
  do {
    if (uVar3 == 0) {
      if (param_2 != (short *)0x0) {
        safeget_ctxblob(param_3,param_2,-1);
        FindLastPathSeparatorAndUpdateContext((int *)param_3);
LAB_66205077:
        pwVar1 = u_nt0_dll64_dll_6621cab4;
        if (param_1 == '\0') {
          pwVar1 = u_nt0_dll_dll_6621cad0;
        }
        FUN_6620ad30((int *)param_3,(undefined *)pwVar1);
        reset_flags_clean_memory(s110);
        s8 = 0;
        ProcessPathTypeAndBuildOutput(*param_3,s110);
        s20 = PrepareUnicodeStringBuffer(s110);
        s28 = 0x18;
        s24 = 0;
        s1c = 0x40;
        s18 = 0;
        s14 = 0;
        iVar1 = NtQueryFullAttributesFile(&s28,s60);
        if (-1 < iVar1) {
          if ((s38 | s34) == 0) {
            s8 = 0xffffffff;
            uVar1 = manage_memstate(s110);
            *in_FS_OFFSET = s10;
            return uVar1 & 0xffffff00;
          }
          s8 = 0xffffffff;
          uVar2 = manage_memstate(s110);
          *in_FS_OFFSET = s10;
          return ((int)(int3)((uint)uVar2 >> 8) << 8) + 1;
        }
        s8 = 0xffffffff;
        uVar1 = manage_memstate(s110);
      }
    }
    else {
      uVar1 = queryVar_allocatePolicy(u_THINSTALL_BIN_6621ca98,param_3,0);
      if (-1 < (int)uVar1) goto LAB_66205077;
    }
    uVar3 = uVar3 + 1;
    if (1 < uVar3) {
      *in_FS_OFFSET = s10;
      return uVar1 & 0xffffff00;
    }
  } while( true );
}


/*
Unable to decompile 'FUN_66205180'
Cause: Exception while decompiling 66205180: Decompiler process died

*/

/*
Unable to decompile 'FUN_66205330'
Cause: Exception while decompiling 66205330: Decompiler process died

*/


int __thiscall
InitializeAndValidateThinAppPackage(void *this,char param_1,char param_2,short *param_3)

{
  bool bVar1;
  uint uVar1;
  int iVar1;
  short *q_function;
  int *this_00;
  undefined4 *in_FS_OFFSET;
  void *sfc [44];
  undefined s4c [8];
  undefined4 s44;
  undefined4 s40;
  undefined s34 [8];
  undefined4 s2c;
  undefined4 s28;
  undefined4 *s24;
  undefined4 s20;
  undefined4 s1c;
  undefined4 s18;
  int s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b79b;
  *in_FS_OFFSET = &s10;
  CleanupAndResetProcessInfo((void **)((int)this + 0x178));
  if (*(int *)((int)this + 0x160) == 0) {
    if (*(int *)((int)this + 4) != 0) {
      reset_flags_clean_memory(sfc);
      s8 = 0;
                    // WARNING: Load size is inaccurate
      ProcessPathTypeAndBuildOutput(*this,sfc);
      s24 = PrepareUnicodeStringBuffer(sfc);
      s2c = 0x18;
      uVar1 = 0x20;
      s28 = 0;
      if (*(char *)((int)this + 0x18c) != '\0') {
        uVar1 = 0;
      }
      s20 = 0x40;
      s1c = 0;
      s18 = 0;
      s14 = NtOpenFile((undefined4 *)((int)this + 0x170),*(undefined4 *)((int)this + 0x188),&s2c,s34
                       ,1,uVar1 | 0x40);
      if (s14 < 0) {
        *(undefined4 *)((int)this + 0x170) = 0;
        s8 = 0xffffffff;
        manage_memstate(sfc);
        *in_FS_OFFSET = s10;
        return s14;
      }
      s8 = 0xffffffff;
      manage_memstate(sfc);
    }
    iVar1 = NtQueryInformationFile(*(undefined4 *)((int)this + 0x170),s34,s4c,0x18,5);
    if (iVar1 < 0) goto LAB_662057ff;
    *(undefined4 *)((int)this + 0x168) = s44;
    *(undefined4 *)((int)this + 0x16c) = s40;
  }
  iVar1 = ValidateAndLoadThinAppHeader(this);
  if (iVar1 < 0) {
    CleanupAndResetProcessInfo((void **)((int)this + 0x178));
    ResetFileHandleState((int)this);
    *in_FS_OFFSET = s10;
    return iVar1;
  }
  if (param_1 == '\0') {
    iVar1 = *(int *)((int)this + 0x178);
    bVar1 = CheckExtendedHeaderFlag(iVar1);
    if ((bVar1 != false) && (param_2 != '\0')) {
      *(undefined4 *)((int)this + 0x174) = *(undefined4 *)((int)this + 0x170);
      *(undefined4 *)((int)this + 0x170) = 0;
      if (param_3 == (short *)0x0) {
        q_function = (short *)GetExtendedHeaderOffset(iVar1);
        this_00 = FindLastPathSeparatorAndUpdateContext((int *)this);
        invoke_qhandler(this_00,'\x01',q_function,-1,0,(undefined4 *)0x0);
      }
      else {
        safeget_ctxblob(this,param_3,-1);
      }
      iVar1 = InitializeAndValidateThinAppPackage(this,'\x01','\0',(short *)0x0);
LAB_662057ff:
      *in_FS_OFFSET = s10;
      return iVar1;
    }
  }
  *in_FS_OFFSET = s10;
  return 0;
}



int __thiscall
LoadAndVerifyThinAppPackage(void *this,short *param_1,char param_2,void *param_3,short *param_4)

{
  int iVar1;
  int iVar2;
  
  ResetFileHandleState((int)this);
  safe_mem_access((void **)this);
  safe_mem_access((void **)((int)this + 0xb0));
  CleanupAndResetProcessInfo((void **)((int)this + 0x178));
  safeget_ctxblob(this,param_1,-1);
  safeget_ctxblob((void *)((int)this + 0xb0),param_1,-1);
  *(void **)((int)this + 0x188) = param_3;
  iVar1 = InitializeAndValidateThinAppPackage(this,'\0',param_2,param_4);
  iVar2 = 0;
  if (iVar1 < 0) {
    iVar2 = iVar1;
  }
  return iVar2;
}



int __thiscall
SynchronizedFileReadOperation
          (void *this,uint param_1,int param_2,undefined4 param_3,uint param_4,int param_5)

{
  uint uVar1;
  int iVar1;
  int iVar2;
  uint uVar2;
  int sc;
  uint s8;
  
  uVar2 = param_5;
  uVar1 = param_4;
  iVar1 = param_2 + (uint)CARRY4(param_4,param_1);
  iVar2 = *(int *)((int)this + 0x16c);
  if (((*(int *)((int)this + 0x16c) == iVar1) || (iVar2 < iVar1)) &&
     ((iVar2 < iVar1 || (*(uint *)((int)this + 0x168) < (param_4 + param_1))))) {
    return -0x3fffff85;
  }
  if (*(int *)((int)this + 0x160) != 0) {
    FUN_6620d5b0(param_3,*(int *)((int)this + 0x160) + param_1,param_4);
    return 0;
  }
  if (*(int *)((int)this + 0x170) == 0) {
    return -0x3ffffff8;
  }
  param_4 = 0;
  if (*(char *)((int)this + 0x18c) == '\0') {
    uVar2 = 0;
  }
  else {
    if (param_5 == 0) {
      iVar2 = NtCreateEvent(&param_4,0x100002,0,0,0);
      uVar2 = param_4;
    }
    else {
      iVar2 = NtClearEvent(param_5);
    }
    if (iVar2 < 0) {
      return iVar2;
    }
  }
  iVar2 = NtReadFile(*(undefined4 *)((int)this + 0x170),uVar2,0,0,&sc,param_3,uVar1,&param_1,0);
  if (iVar2 == 0x103) {
    iVar1 = NtWaitForSingleObject(uVar2,0,0);
    iVar2 = sc;
    if (iVar1 != 0) {
      if (-1 < iVar1) {
        iVar1 = -0x3fffffff;
      }
      goto LAB_6620599b;
    }
  }
  iVar1 = iVar2;
  if ((-1 < iVar1) && (s8 != uVar1)) {
    iVar1 = -0x3fffff85;
  }
LAB_6620599b:
  if (param_4 != 0) {
    NtClose(param_4);
  }
  return iVar1;
}



int __fastcall ValidateAndLoadThinAppHeader(void *param_1)

{
  int *this;
  bool bVar1;
  int iVar1;
  int iVar2;
  void *pvVar1;
  uint uVar1;
  undefined4 *in_FS_OFFSET;
  uint s28;
  int s24;
  uint s20;
  void *s18;
  undefined *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b7b0;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s14 = &stack0xffffffcc;
  s18 = param_1;
  iVar1 = SynchronizedFileReadOperation(param_1,0x40,0,&s28,0x10,0);
  if (-1 < iVar1) {
    iVar2 = s24 + (uint)CARRY4(s20,s28);
    iVar1 = *(int *)((int)param_1 + 0x16c);
    if ((((iVar2 <= iVar1) &&
         ((((*(int *)((int)param_1 + 0x16c) != iVar2) && (iVar2 <= iVar1) ||
           ((s20 + s28) <= *(uint *)((int)param_1 + 0x168))) && (0xf < s20)))) &&
        (*(uint *)((int)param_1 + 0x16c) < 0x80000000)) &&
       ((0 < (int)*(uint *)((int)param_1 + 0x16c) || (s20 <= *(uint *)((int)param_1 + 0x168))))) {
      s8 = 0;
      pvVar1 = (void *)Wsafe_malloc(s20);
      UpdateAndResetObjectState((void *)((int)param_1 + 0x178),pvVar1);
      s8 = 0xffffffff;
      if (*(int *)((int)param_1 + 0x178) != 0) {
        *(uint *)((int)param_1 + 0x180) = s20;
        iVar1 = SynchronizedFileReadOperation(param_1,s28,s24,*(int *)((int)param_1 + 0x178),s20,0);
        if (iVar1 < 0) goto LAB_66205afa;
        this = *(int **)((int)param_1 + 0x178);
        bVar1 = IsValidThinAppSignature(this);
        if (bVar1 != false) {
          uVar1 = CheckWideStringCapacityAndFindEntry(this,*(short **)((int)param_1 + 0x180));
          iVar1 = 0;
          if ((char)uVar1 == '\0') {
            iVar1 = -0x3fffff85;
          }
          *in_FS_OFFSET = s10;
          return iVar1;
        }
      }
    }
    iVar1 = -0x3fffff85;
  }
LAB_66205afa:
  *in_FS_OFFSET = s10;
  return iVar1;
}



int __cdecl FUN_66205b10(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  iVar1 = *param_1;
  if (*param_2 == 0) {
    if (iVar1 != 0) {
      iVar1 = LdrUnloadDll(iVar1);
      *param_1 = 0;
      return iVar1;
    }
  }
  else {
    if (iVar1 != 0) {
      iVar2 = NtUnmapViewOfSection(0xffffffff,iVar1);
      *param_1 = 0;
    }
    iVar1 = NtClose(*param_2);
    if (-1 < iVar2) {
      iVar2 = iVar1;
    }
  }
  return iVar2;
}



int __cdecl FUN_66205b60(void *param_1,int param_2,undefined4 param_3)

{
  int ***pppiVar1;
  int iVar1;
  int iVar2;
  int ***_Memory;
  undefined4 *in_FS_OFFSET;
  void *s30;
  int s2c;
  undefined4 s28;
  undefined4 s24;
  int ***s20;
  int ***s1c;
  undefined4 s18;
  undefined s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b7d3;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s28 = param_3;
  s18 = *(undefined4 *)((int)param_1 + 0x4c);
  s20 = (int ***)&s20;
  s30 = param_1;
  s2c = param_2;
  s24 = 0;
  s14 = 0;
  s8 = 0;
  s1c = s20;
  iVar1 = FUN_66208310(param_1,param_2,FUN_66205c30,FUN_66205cb0,&s30);
  iVar2 = 0;
  if (iVar1 < 0) {
    iVar2 = iVar1;
  }
  _Memory = s20;
  if ((int ****)s20 != &s20) {
    do {
      pppiVar1 = (int ***)*_Memory;
      s8 = 0xffffffff;
      manage_memstate(_Memory + 2);
      FID_conflict__free(_Memory);
      _Memory = pppiVar1;
    } while ((int ****)pppiVar1 != &s20);
  }
  *in_FS_OFFSET = s10;
  return iVar2;
}



int __cdecl FUN_66205c30(int *param_1,undefined4 param_2,undefined4 param_3,int *param_4)

{
  char cVar1;
  int *piVar1;
  int iVar1;
  int *piVar2;
  ushort s18;
  ushort s16;
  int *s14;
  int *s10;
  int *sc;
  char s6;
  char s5;
  
  FUN_66206fc0(param_1,&s10,&sc,&s6,&s5);
  piVar1 = param_4;
  if ((s5 == '\0') || (piVar2 = (int *)param_4[2], piVar2 == (int *)0x0)) {
    piVar2 = param_1;
    do {
      cVar1 = *(char *)piVar2;
      piVar2 = (int *)((int)piVar2 + 1);
    } while (cVar1 != '\0');
    s18 = (short)piVar2 - ((short)param_1 + 1);
    s14 = param_1;
    s16 = s18;
    iVar1 = FUN_66204eb0(param_4,&s18,&param_4);
    if (iVar1 < 0) {
      return iVar1;
    }
    piVar2 = param_4 + 0x30;
  }
  piVar1[3] = (int)piVar2;
  return -0x3ffffd8f;
}



int __cdecl
FUN_66205cb0(undefined4 param_1,int *param_2,undefined4 param_3,undefined4 param_4,uint param_5,
            int *param_6,int *param_7,undefined4 param_8,undefined4 param_9,void **param_10)

{
  void **this;
  int iVar1;
  uint uVar1;
  int *piVar1;
  int *piVar2;
  undefined4 *in_FS_OFFSET;
  void *s30 [4];
  uint s20;
  uint s1c;
  ushort s18;
  ushort s16;
  void *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  this = param_10;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b7e8;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  piVar2 = (int *)param_10[3];
  InitializeObjectWithDefaults(s30,0);
  s8 = 0;
  piVar1 = param_2;
  while( true ) {
    if (piVar1 == (int *)0x0) {
      piVar1 = (int *)(param_5 & 0xffff);
    }
    iVar1 = FUN_662087e0(*this,(int)piVar2,(char *)piVar1,&s20,(char *)((int)&param_10 + 3));
    if (iVar1 < 0) break;
    if (param_10._3_1_ == '\0') {
      iVar1 = FUN_6620a370(*this,param_6,param_7,(int)&s20,(uint)this[6],0,'\0');
      if (-1 < iVar1) {
        iVar1 = -0x3ffffd8f;
      }
      goto LAB_66205de5;
    }
    iVar1 = FUN_66209110(*this,s20,s1c,s30,(uint *)0x0);
    if (iVar1 < 0) goto LAB_66205de5;
    iVar1 = FUN_6620e410(s30[0],0x2e);
    if (iVar1 == 0) {
      iVar1 = -0x3fffff85;
      goto LAB_66205de5;
    }
    piVar1 = (int *)(iVar1 + 1);
    if (*(char *)(iVar1 + 1) == '#') {
      uVar1 = FUN_6620e7e9((byte *)(iVar1 + 2),(byte **)0x0,10);
      param_5 = uVar1 & 0xffff;
      piVar1 = (int *)0x0;
    }
    s18 = (short)iVar1 - (short)s30[0];
    s14 = s30[0];
    s16 = s18;
    iVar1 = FUN_66204eb0(this,&s18,&param_2);
    if (iVar1 < 0) goto LAB_66205de5;
    piVar2 = param_2 + 0x30;
  }
  if ((iVar1 != -0x3fffff86) || (*(char *)(this + 7) == '\0')) {
    DisplayHardErrorAndTerminate(s_RuntimeUtil_cpp_6621ca88,0x19e,(short *)0x0);
  }
LAB_66205de5:
  s8 = 0xffffffff;
  FUN_66207460(s30);
  *in_FS_OFFSET = s10;
  return iVar1;
}



int __cdecl FUN_66205e10(void *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 sc;
  undefined2 s8;
  
  s8 = 0xb;
  sc = 0x50001;
  iVar1 = FUN_662080a0(param_1,param_2,(int)&sc,3);
  iVar2 = 0;
  if (iVar1 < 0) {
    iVar2 = iVar1;
  }
  return iVar2;
}



undefined4 __fastcall FUN_66205e50(int param_1)

{
  FUN_66208c20(param_1);
  return *(undefined4 *)(param_1 + 0x50);
}



uint __cdecl DynamicBufferCallbackHandler(undefined *param_1,undefined4 *param_2,undefined4 param_3)

{
  bool bVar1;
  int iVar1;
  uint context_number;
  uint uVar1;
  uint extraout_EAX;
  undefined4 uVar2;
  undefined *safe_object_alloc;
  
  dynamic_memory_context_alloc(param_2,(void *)0x104,(undefined *)0x1);
  uVar2 = *param_2;
  iVar1 = GetEffectiveStringLength((int)param_2);
  context_number = (*(code *)param_1)(param_3,uVar2,iVar1);
  while( true ) {
    if (context_number == 0) {
      return 0;
    }
    uVar1 = GetEffectiveStringLength((int)param_2);
    if (context_number < uVar1) break;
    safe_object_alloc = (undefined *)0x1;
    iVar1 = GetEffectiveStringLength((int)param_2);
    bVar1 = dynamic_memory_context_alloc(param_2,(void *)(iVar1 + 0x104),safe_object_alloc);
    if (bVar1 == false) {
      SetLastError(8);
      return extraout_EAX & 0xffffff00;
    }
    uVar2 = *param_2;
    iVar1 = GetEffectiveStringLength((int)param_2);
    context_number = (*(code *)param_1)(param_3,uVar2,iVar1);
  }
  uVar2 = update_context(param_2,context_number);
  return ((int)(int3)((uint)uVar2 >> 8) << 8) + 1;
}


/*
Unable to decompile 'FUN_66205ef0'
Cause: Exception while decompiling 66205ef0: Decompiler process died

*/


void __cdecl
ConfigureAndExecuteWithFlags(undefined4 param_1,undefined4 param_2,int param_3,char param_4)

{
  uint uVar1;
  
  uVar1 = 0x1200;
  if (param_4 != '\0') {
    uVar1 = 0x40001200;
  }
  if (param_3 != 0) {
    uVar1 = uVar1 | 0x800;
  }
  FUN_66205ef0(param_1,uVar1,param_3,param_2,0,0);
  return;
}



// WARNING: Could not reconcile some variable overlaps

int __cdecl
DisplayConfigurableMessageBox
          (LPCWSTR param_1,int param_2,short *param_3,undefined4 param_4,UINT param_5)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  short *s170;
  int s16c;
  LPCWSTR sc0 [44];
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b816;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  reset_flags_clean_memory(sc0);
  s8 = 0;
  if (param_3 == (short *)0x0) {
    safeget_ctxblob(sc0,u_Unknown_error__6621ccbc,-1);
  }
  else {
    invoke_qhandler(sc0,'\x01',param_3,0,2,&param_4);
  }
  if (param_2 != 0) {
    reset_flags_clean_memory(&s170);
    s8 = ((int)(int3)s8._1_3_ << 8) + 1;
    ConfigureAndExecuteWithFlags(&s170,param_2,0,'\0');
    if (s16c != 0) {
      invoke_qhandler(sc0,'\x01',u__6621ccdc,-1,0,(undefined4 *)0x0);
      invoke_qhandler(sc0,'\x01',s170,s16c,0,(undefined4 *)0x0);
    }
    s8 = s8 & 0xffffff00;
    manage_memstate(&s170);
  }
  iVar1 = MessageBoxW((HWND)0x0,sc0[0],param_1,param_5);
  s8 = 0xffffffff;
  manage_memstate(sc0);
  *in_FS_OFFSET = s10;
  return iVar1;
}



// WARNING: Could not reconcile some variable overlaps

void __cdecl
FUN_662061f0(undefined4 param_1,short **param_2,short **param_3,short **param_4,uint param_5,
            uint *param_6,char param_7,int param_8)

{
  short *q_function;
  ushort *puVar1;
  bool bVar1;
  ushort uVar1;
  int iVar1;
  undefined4 *puVar2;
  int iVar2;
  uint uVar2;
  ushort *puVar3;
  undefined4 *in_FS_OFFSET;
  short s504 [260];
  void *s2fc [44];
  void *s24c [44];
  void *s19c;
  undefined4 s198;
  short *sec [44];
  undefined4 s3c;
  undefined4 s38;
  undefined4 *s34;
  undefined4 s30;
  undefined4 s2c;
  undefined4 s28;
  undefined s24 [8];
  int s1c;
  undefined4 s18;
  undefined s11;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b84c;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  reset_flags_clean_memory(s2fc);
  s8 = 0;
  iVar1 = FUN_66203900(s2fc,0x252,8,(int *)0x0);
  s1c = iVar1;
  cleanup_ctxblob(s24c,param_3);
  s8 = ((int)(int3)s8._1_3_ << 8) + 1;
  invoke_qhandler(s24c,'\x01',(short *)&DAT_6621cce8,-1,0,(undefined4 *)0x0);
  puVar2 = PrepareUnicodeStringBuffer(s24c);
  iVar2 = NtQueryDirectoryFile(param_1,0,0,0,s24,iVar1,0x250,1,1,puVar2,1);
  do {
    if (iVar2 < 0) {
      s8 = s8 & 0xffffff00;
      manage_memstate(s24c);
      s8 = 0xffffffff;
      manage_memstate(s2fc);
      *in_FS_OFFSET = s10;
      return;
    }
    if ((*(byte *)(iVar1 + 0x38) & 0x10) == 0) {
      *(undefined2 *)(iVar1 + 0x40 + (*(uint *)(iVar1 + 0x3c) & 0xfffffffe)) = 0;
      puVar1 = (ushort *)(iVar1 + (((int)param_3[1] + 0x21) * 2));
      if (puVar1 != (ushort *)0x0) {
        uVar1 = *puVar1;
        puVar3 = puVar1;
        if (uVar1 == 0) {
LAB_662062ed:
          bVar1 = false;
        }
        else {
          do {
            if ((uVar1 < 0x30) || (0x39 < uVar1)) goto LAB_662062ed;
            uVar1 = puVar3[1];
            puVar3 = puVar3 + 1;
          } while (uVar1 != 0);
          bVar1 = true;
        }
        if (bVar1) {
          cleanup_ctxblob(&s19c,param_2);
          s8 = ((int)(int3)s8._1_3_ << 8) + 2;
          invoke_qhandler(&s19c,'\x01',(short *)&DAT_6621ccf0,-1,0,(undefined4 *)0x0);
          q_function = (short *)(iVar1 + 0x40);
          invoke_qhandler(&s19c,'\x01',q_function,-1,0,(undefined4 *)0x0);
          if ((param_8 == 0) || (iVar2 = FUN_66203690(s19c,s198,param_8,0xffffffff,0), iVar2 != 0))
          {
            uVar2 = Wwide_char_to_integer(puVar1);
            cleanup_ctxblob(sec,param_2);
            s8 = ((int)(int3)s8._1_3_ << 8) + 3;
            bVar1 = false;
            if (*param_6 < uVar2) {
              if ((param_7 != '\0') && (*param_6 != param_5)) {
                invoke_qhandler(sec,'\x01',(short *)&DAT_6621ccf0,-1,0,(undefined4 *)0x0);
                invoke_qhandler(sec,'\x01',*param_4,(int)param_4[1],0,(undefined4 *)0x0);
                bVar1 = true;
              }
              *param_6 = uVar2;
              FUN_6620e91d(s504,0x104,q_function,-1);
              safeget_ctxblob(param_4,s504,-1);
            }
            else if ((param_7 != '\0') && (uVar2 != param_5)) {
              invoke_qhandler(sec,'\x01',(short *)&DAT_6621ccf0,-1,0,(undefined4 *)0x0);
              invoke_qhandler(sec,'\x01',q_function,-1,0,(undefined4 *)0x0);
              bVar1 = true;
            }
            if (bVar1) {
              ProcessPathTypeAndBuildOutput(sec[0],sec);
              s34 = PrepareUnicodeStringBuffer(sec);
              s3c = 0x18;
              s38 = 0;
              s30 = 0x40;
              s2c = 0;
              s28 = 0;
              iVar1 = NtOpenFile(&s18,0x40110000,&s3c,s24,0,0x60);
              if (-1 < iVar1) {
                s11 = 1;
                NtSetInformationFile(s18,s24,&s11,1,0xd);
                NtClose(s18);
              }
            }
            s8 = ((int)(int3)s8._1_3_ << 8) + 2;
            manage_memstate(sec);
            iVar1 = s1c;
          }
          s8 = ((int)(int3)s8._1_3_ << 8) + 1;
          manage_memstate(&s19c);
        }
      }
    }
    puVar2 = PrepareUnicodeStringBuffer(s24c);
    iVar2 = NtQueryDirectoryFile(param_1,0,0,0,s24,iVar1,0x250,1,1,puVar2,0);
  } while( true );
}



// WARNING: Could not reconcile some variable overlaps

uint __cdecl
FUN_66206550(ushort **param_1,ushort *param_2,undefined4 param_3,ushort **param_4,int param_5)

{
  ushort uVar1;
  int iVar1;
  short **this;
  uint uVar2;
  ushort *puVar1;
  ushort *extraout_EDX;
  bool bVar1;
  ushort *puVar2;
  ushort *puVar3;
  undefined4 *in_FS_OFFSET;
  char cVar1;
  ushort *s5b8 [44];
  void *s508 [44];
  short *s458 [44];
  ushort *s3a8 [44];
  short *s2f8 [44];
  short *s248 [44];
  short *s198;
  int s194;
  short *se8 [44];
  undefined s38 [8];
  undefined4 s30;
  undefined4 s2c;
  undefined4 *s28;
  undefined4 s24;
  undefined4 s20;
  undefined4 s1c;
  ushort *s18;
  undefined4 s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b8b8;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  iVar1 = FindLastWCharOccurrence(param_1,0x5c,0xffffffff);
  pass_context_to_handler(s5b8,(short *)*param_1,iVar1);
  s8 = 0;
  reset_flags_clean_memory(se8);
  s8._0_1_ = 1;
  ProcessSubstringOperation(se8,(int *)param_1,iVar1 + 1,0xffffffff);
  puVar2 = param_2;
  if (param_2 != (ushort *)0x0) {
    s5b8[0] = param_2;
  }
  pass_context_to_handler(s248,(short *)s5b8[0],-1);
  s8._0_1_ = 2;
  reset_flags_clean_memory(s508);
  s8._0_1_ = 3;
  ProcessPathTypeAndBuildOutput(s248[0],s508);
  s28 = PrepareUnicodeStringBuffer(s508);
  s30 = 0x18;
  s2c = 0;
  s24 = 0x40;
  s20 = 0;
  s1c = 0;
  iVar1 = NtOpenFile(&s14,0x100001,&s30,s38,7,0x4021);
  if (iVar1 < 0) {
    bVar1 = false;
    goto LAB_66206849;
  }
  uVar2 = FindLastWCharOccurrence(se8,0x2e,0xffffffff);
  reset_flags_clean_memory(s2f8);
  s8._0_1_ = 4;
  reset_flags_clean_memory(s3a8);
  s8 = ((int)(int3)s8._1_3_ << 8) + 5;
  puVar3 = (ushort *)0x0;
  if (uVar2 == 0xffffffff) {
    get_context(s2f8,se8);
    param_2 = (ushort *)(((int)'\x01' << 0x18) + param_2._0_3_);
  }
  else {
    ProcessSubstringOperation(s2f8,(int *)se8,0,uVar2);
    ProcessSubstringOperation(s3a8,(int *)se8,uVar2 + 1,0xffffffff);
    uVar1 = FUN_662068a0(s3a8[0]);
    param_2 = (ushort *)(((uint)param_2 & 0xffffff) | ((uint)(byte)uVar1 << 0x18));
    puVar1 = extraout_EDX;
    if (puVar2 != (ushort *)0x0) {
      puVar1 = puVar2;
      do {
        uVar1 = *puVar1;
        puVar1 = puVar1 + 1;
      } while (uVar1 != 0);
      iVar1 = FUN_6620e9db(*param_1,puVar2,((int)puVar1 - (int)(puVar2 + 1)) >> 1);
      puVar1 = s3a8[0];
      if (iVar1 != 0) goto LAB_66206711;
    }
    puVar3 = (ushort *)Wwide_char_to_integer(puVar1);
  }
LAB_66206711:
  reset_flags_clean_memory(&s198);
  iVar1 = param_5;
  s8._0_1_ = 6;
  cVar1 = (char)param_3;
  s18 = puVar3;
  FUN_662061f0(s14,s248,s2f8,&s198,(uint)puVar3,(uint *)&s18,cVar1,param_5);
  puVar2 = s18;
  if (param_2._3_1_ == '\0') {
    reset_flags_clean_memory(s458);
    s8 = ((int)(int3)s8._1_3_ << 8) + 7;
    param_2 = puVar3;
    FUN_662061f0(s14,s248,se8,s458,(uint)puVar3,(uint *)&param_2,cVar1,iVar1);
    puVar1 = param_2;
    puVar2 = s18;
    if (s18 <= param_2) {
      get_context(&s198,s458);
      puVar2 = puVar1;
    }
    s8._0_1_ = 6;
    manage_memstate(s458);
  }
  NtClose(s14);
  if (param_4 != (ushort **)0x0) {
    *param_4 = puVar2;
  }
  bVar1 = puVar3 < puVar2;
  if (bVar1) {
    this = get_context(param_1,s248);
    invoke_qhandler(this,'\x01',(short *)&DAT_6621ccf0,-1,0,(undefined4 *)0x0);
    invoke_qhandler(this,'\x01',s198,s194,0,(undefined4 *)0x0);
  }
  s8._0_1_ = 5;
  manage_memstate(&s198);
  s8._0_1_ = 4;
  manage_memstate(s3a8);
  s8._0_1_ = 3;
  manage_memstate(s2f8);
LAB_66206849:
  s8._0_1_ = 2;
  manage_memstate(s508);
  s8._0_1_ = 1;
  manage_memstate(s248);
  s8 = (uint)s8._1_3_ << 8;
  manage_memstate(se8);
  s8 = 0xffffffff;
  uVar2 = manage_memstate(s5b8);
  *in_FS_OFFSET = s10;
  return (uVar2 & 0xffffff00) | (uint)bVar1;
}



ushort __cdecl FUN_662068a0(ushort *param_1)

{
  ushort uVar1;
  
  uVar1 = *param_1;
  if (uVar1 != 0) {
    while ((0x2f < uVar1 && (uVar1 < 0x3a))) {
      uVar1 = param_1[1];
      param_1 = param_1 + 1;
      if (uVar1 == 0) {
        return 1;
      }
    }
  }
  return uVar1 & 0xff00;
}



int __fastcall FUN_662068d0(int *param_1)

{
  undefined4 uVar1;
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined s60 [44];
  undefined4 s34;
  int s30;
  undefined *s2c;
  undefined4 s28;
  undefined *s24;
  undefined4 s20;
  undefined s1c [8];
  int s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b8d8;
  *in_FS_OFFSET = &s10;
  uVar1 = AcquireResourceLockWithRetry(param_1);
  if ((char)uVar1 != '\0') {
    FUN_6620b5b0((undefined (*) [16])s60);
    s8 = 0;
    iVar1 = FUN_6620b600(s60,0x120001,0x1f0001);
    if (-1 < iVar1) {
      RtlInitUnicodeString(s1c,u_DBWinMutex_6621ccf4);
      s30 = GetRestrictedDirectoryHandle(&DAT_6624b2f8,0);
      s2c = s1c;
      s24 = s60;
      s34 = 0x18;
      s28 = 0xc2;
      s20 = 0;
      iVar1 = NtCreateMutant(&s14,0x120001,&s34,0);
      if (-1 < iVar1) {
        param_1[1] = s14;
      }
    }
    FUN_66202d10(param_1);
    s8 = 0xffffffff;
    thunk_FUN_6620b7a0((undefined (*) [16])s60);
  }
  iVar1 = param_1[1];
  *in_FS_OFFSET = s10;
  return iVar1;
}



undefined4 get_process_data(void)

{
  int in_FS_OFFSET;
  
  return *(undefined4 *)(*(int *)(in_FS_OFFSET + 0x18) + 0x34);
}



undefined4 FUN_662069c0(void)

{
  int in_FS_OFFSET;
  
  return *(undefined4 *)(*(int *)(*(int *)(in_FS_OFFSET + 0x18) + 0x30) + 0x18);
}



bool CheckThreadDebuggerFlag(void)

{
  int in_FS_OFFSET;
  
  return *(char *)(*(int *)(*(int *)(in_FS_OFFSET + 0x18) + 0x30) + 2) != '\0';
}



void LogNullTerminatedStringEvent(char *param_1)

{
  char cVar1;
  undefined4 *in_FS_OFFSET;
  char *s50;
  char *s4c;
  undefined *s1c;
  undefined4 s14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &DAT_662234a8;
  puStack16 = &LAB_6620ebb8;
  s14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s14;
  s1c = &stack0xffffff8c;
  s4c = &DAT_6621cd0a;
  if (param_1 != (char *)0x0) {
    s4c = param_1;
  }
  s50 = s4c;
  do {
    cVar1 = *s50;
    s50 = s50 + 1;
  } while (cVar1 != '\0');
  s50 = s50 + (1 - (int)(s4c + 1));
  s8 = 0;
  FUN_66206d50(0x40010006,0,2,&s50);
  *in_FS_OFFSET = s14;
  return;
}



void LogUnicodeStringAsAnsiEvent(undefined *param_1)

{
  undefined *puVar1;
  int iVar1;
  char *pcVar1;
  undefined s14 [4];
  char *s10;
  short sc [4];
  
  puVar1 = SelectDefaultOrProvidedPointer(param_1,(undefined *)0x0);
  RtlInitUnicodeString(sc,puVar1);
  sc[0] = sc[0] + 2;
  iVar1 = RtlUnicodeStringToAnsiString(s14,sc,1);
  pcVar1 = &DAT_6621cd0a;
  if (-1 < iVar1) {
    pcVar1 = s10;
  }
  s10 = pcVar1;
  LogNullTerminatedStringEvent(pcVar1);
  if (-1 < iVar1) {
    RtlFreeAnsiString(s14);
  }
  return;
}


/*
Unable to decompile 'FUN_66206d50'
Cause: Exception while decompiling 66206d50: Decompiler process died

*/


void runtimeproc_info(int param_1)

{
  int thread_env_block;
  
  if (*(int *)(*(int *)(thread_env_block + 0x18) + 0x34) != param_1) {
    *(int *)(*(int *)(thread_env_block + 0x18) + 0x34) = param_1;
  }
  return;
}



// WARNING: Could not reconcile some variable overlaps

void delay_execution(uint param_1)

{
  undefined8 delay;
  
  if (param_1 == 0xffffffff) {
    delay._0_4_ = 0;
    delay._4_4_ = 0x80000000;
    NtDelayExecution(0,&delay);
    return;
  }
  delay = __allmul(param_1,0,0xffffd8f0,0xffffffff);
  NtDelayExecution(0,&delay);
  return;
}



undefined4 __cdecl FUN_66206e40(undefined4 param_1,undefined *param_2)

{
  uint uVar1;
  int iVar1;
  int sc;
  undefined4 s8;
  
  uVar1 = FUN_66202d50((int *)&DAT_6624b2f8);
  if ((char)uVar1 == '\0') {
    *param_2 = 0;
    return 0;
  }
  iVar1 = NtQueryInformationProcess(param_1,0x1a,&sc,4,0);
  if (iVar1 == -0x3fffffde) {
    iVar1 = NtDuplicateObject(0xffffffff,param_1,0xffffffff,&s8,0x400,0,0);
    if (-1 < iVar1) {
      iVar1 = NtQueryInformationProcess(s8,0x1a,&sc,4,0);
      NtClose(s8);
      if (iVar1 != -0x3fffffde) goto LAB_66206ecc;
    }
    return 0xc0000022;
  }
LAB_66206ecc:
  if (-1 < iVar1) {
    *param_2 = sc == 0;
    return 0;
  }
  *param_2 = 0;
  return 0;
}



int __cdecl FUN_66206ef0(int param_1,undefined4 param_2)

{
  int iVar1;
  int in_FS_OFFSET;
  int s8;
  
  iVar1 = FUN_66206f30(param_1,&s8);
  if (-1 < iVar1) {
    *(bool *)param_2 = s8 != *(int *)(*(int *)(in_FS_OFFSET + 0x18) + 0x20);
    iVar1 = 0;
  }
  return iVar1;
}



int __cdecl FUN_66206f30(int param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  int in_FS_OFFSET;
  undefined s1c [16];
  undefined4 sc;
  
  iVar2 = param_1;
  if (param_1 == -1) {
    *param_2 = *(undefined4 *)(*(int *)(in_FS_OFFSET + 0x18) + 0x20);
    return 0;
  }
  iVar1 = NtQueryInformationProcess(param_1,0,s1c,0x18,0);
  if (iVar1 == -0x3fffffde) {
    iVar2 = NtDuplicateObject(0xffffffff,iVar2,0xffffffff,&param_1,0x400,0,0);
    if (iVar2 < 0) {
      return -0x3fffffde;
    }
    iVar1 = NtQueryInformationProcess(param_1,0,s1c,0x18,0);
    NtClose(param_1);
  }
  if (-1 < iVar1) {
    *param_2 = sc;
  }
  return iVar1;
}



void __cdecl FUN_66206fc0(int *param_1,int **param_2,int **param_3,char *param_4,undefined *param_5)

{
  uint uVar1;
  int *piVar1;
  uint uVar2;
  char cVar1;
  
  *param_2 = param_1;
  piVar1 = param_1;
  do {
    cVar1 = *(char *)piVar1;
    piVar1 = (int *)((int)piVar1 + 1);
  } while (cVar1 != '\0');
  uVar2 = (int)piVar1 - ((int)param_1 + 1);
  cVar1 = '\x01';
  piVar1 = (int *)(uVar2 + (int)param_1);
  uVar1 = uVar2;
  do {
    uVar1 = uVar1 - 1;
    if (uVar2 <= uVar1) goto LAB_6620700c;
  } while (*(char *)(uVar1 + (int)param_1) != '.');
  if ((uVar1 < uVar2) &&
     ((piVar1 = (int *)(uVar1 + (int)param_1), uVar2 - uVar1 != 4 || (*piVar1 != 0x6c6c642e)))) {
    cVar1 = '\0';
  }
LAB_6620700c:
  if (param_3 != (int **)0x0) {
    *param_3 = piVar1;
  }
  if (param_4 != (char *)0x0) {
    *param_4 = cVar1;
  }
  if (param_5 != (undefined *)0x0) {
    if ((((cVar1 != '\0') && ((int)piVar1 - (int)param_1 == 5)) && (*param_1 == 0x6c64746e)) &&
       (*(char *)(param_1 + 1) == 'l')) {
      *param_5 = 1;
      return;
    }
    *param_5 = 0;
  }
  return;
}



void __cdecl DisplayHardErrorAndTerminate(char *param_1,undefined4 param_2,short *param_3)

{
  char cVar1;
  wchar_t wVar1;
  short sVar1;
  code *pcVar1;
  bool bVar1;
  undefined3 extraout_var;
  uint uVar1;
  int iVar1;
  wchar_t *pwVar1;
  uint uVar2;
  short *psVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  undefined2 *puVar1;
  wchar_t *pwVar2;
  int iVar2;
  undefined4 *puVar2;
  int in_FS_OFFSET;
  undefined4 s828;
  undefined4 auStack2084 [511];
  int s28;
  undefined4 *s24;
  int s20;
  uint s1c;
  short s18;
  short s16;
  undefined4 *s14;
  short *s10;
  uint sc;
  char s5;
  
  bVar1 = CheckThreadDebuggerFlag();
  s5 = ((int)(int3)extraout_var << 8) + bVar1 != 0;
  pwVar1 = u_Nt0SafeUtil__RaiseHardError_PID__6621cd58;
  if (!(bool)s5) {
    pwVar1 = u_ThinApp_has_encountered_an_unexp_6621cda0;
  }
  pwVar2 = pwVar1;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  iVar2 = ((int)pwVar2 - (int)(pwVar1 + 1)) >> 1;
  iVar1 = iVar2 * 2;
  FUN_6620d5b0(&s828,pwVar1,iVar1);
  iVar1 = (int)&s828 + iVar1;
  uVar1 = FUN_662073b0(iVar1,*(undefined4 *)(*(int *)(in_FS_OFFSET + 0x18) + 0x20),0,10);
  iVar2 = (0x400 - iVar2) - uVar1;
  puVar2 = (undefined4 *)(iVar1 + (uVar1 * 2));
  if (param_1 != (char *)0x0) {
    *puVar2 = DAT_6621ced0;
    iVar1 = FUN_6620ece0(param_1,0x5c);
    if (iVar1 != 0) {
      param_1 = (char *)(iVar1 + 1);
    }
    pcVar2 = param_1;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    uVar3 = (int)pcVar2 - (int)(param_1 + 1);
    uVar1 = 0;
    if (uVar3 != 0) {
      do {
        *(short *)((int)puVar2 + (uVar1 * 2) + 4) = (short)param_1[uVar1];
        uVar1 = uVar1 + 1;
      } while (uVar1 < uVar3);
    }
    puVar1 = (undefined2 *)((int)puVar2 + (uVar3 * 2) + 4);
    *puVar1 = DAT_6621ced8;
    puVar1 = puVar1 + 1;
    uVar1 = FUN_662073b0((int)puVar1,param_2,0,10);
    iVar2 = ((iVar2 - uVar3) + -3) - uVar1;
    puVar2 = (undefined4 *)(puVar1 + uVar1);
  }
  if (param_3 != (short *)0x0) {
    *puVar2 = DAT_6621ced0;
    psVar1 = param_3;
    do {
      sVar1 = *psVar1;
      psVar1 = psVar1 + 1;
    } while (sVar1 != 0);
    uVar1 = ((int)psVar1 - (int)(param_3 + 1)) >> 1;
    if ((iVar2 - 2U) < uVar1) {
      uVar1 = iVar2 - 2U;
    }
    FUN_6620d5b0(puVar2 + 1,param_3,uVar1 * 2);
    puVar2 = (undefined4 *)((int)(puVar2 + 1) + (uVar1 * 2));
  }
  uVar1 = ((int)puVar2 - (int)&s828) >> 1;
  iVar1 = NtQueryInformationProcess(0xffffffff,0xc,&sc,4,0);
  bVar1 = -1 < iVar1;
  if (bVar1) {
    s1c = sc | 1;
    if (s1c == sc) {
      bVar1 = false;
    }
    else {
      iVar1 = NtSetInformationProcess(0xffffffff,0xc,&s1c,4);
      bVar1 = -1 < iVar1;
    }
  }
  s18 = (short)uVar1 * 2;
  s14 = &s828;
  s10 = &s18;
  s16 = s18;
  iVar1 = NtRaiseHardError(0x40000015,1,1,&s10,0,&s20);
  if (bVar1) {
    NtSetInformationProcess(0xffffffff,0xc,&sc,4);
  }
  if (s5 != '\0') {
    uVar3 = 0;
    if (uVar1 != 0) {
      do {
        *(undefined *)((int)&s828 + uVar3) = *(undefined *)((int)&s828 + (uVar3 * 2));
        uVar3 = uVar3 + 1;
      } while (uVar3 < uVar1);
    }
    psVar1 = (short *)PTR_DAT_6621c818;
    do {
      sVar1 = *psVar1;
      psVar1 = psVar1 + 1;
    } while (sVar1 != 0);
    uVar3 = ((int)psVar1 - (int)(PTR_DAT_6621c818 + 2)) >> 1;
    psVar1 = (short *)PTR_DAT_6621c81c;
    do {
      sVar1 = *psVar1;
      psVar1 = psVar1 + 1;
    } while (sVar1 != 0);
    uVar4 = ((int)psVar1 - (int)(PTR_DAT_6621c81c + 2)) >> 1;
    FUN_6620dc00((int)&s828 + uVar4 + uVar3,&s828,uVar1);
    uVar2 = 0;
    if (uVar3 != 0) {
      do {
        *(undefined *)((int)&s828 + uVar2) = PTR_DAT_6621c818[uVar2 * 2];
        uVar2 = uVar2 + 1;
      } while (uVar2 < uVar3);
    }
    uVar2 = 0;
    if (uVar4 != 0) {
      do {
        *(undefined *)((int)&s828 + uVar2 + uVar3) = PTR_DAT_6621c81c[uVar2 * 2];
        uVar2 = uVar2 + 1;
      } while (uVar2 < uVar4);
    }
    iVar2 = uVar1 + uVar4 + uVar3;
    psVar1 = (short *)PTR_DAT_6621c820;
    do {
      sVar1 = *psVar1;
      psVar1 = psVar1 + 1;
    } while (sVar1 != 0);
    uVar3 = 0;
    uVar1 = ((int)psVar1 - (int)(PTR_DAT_6621c820 + 2)) >> 1;
    if (uVar1 != 0) {
      do {
        *(undefined *)((int)&s828 + uVar3 + iVar2) = PTR_DAT_6621c820[uVar3 * 2];
        uVar3 = uVar3 + 1;
      } while (uVar3 < uVar1);
    }
    iVar2 = iVar2 + uVar1;
    s28 = iVar2 + 1;
    *(undefined *)((int)&s828 + iVar2) = 10;
    s24 = &s828;
    FUN_66206d50(0x40010006,0,2,&s28);
  }
  if ((iVar1 < 0) || (s20 == 2)) {
    NtTerminateProcess(0xffffffff,0xc0000001);
  }
  else if (s20 == 7) {
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  return;
}



void __cdecl FUN_66207380(int param_1,int param_2,char *param_3)

{
  char cVar1;
  int iVar1;
  
  if (param_2 != 0) {
    iVar1 = param_1 - (int)param_3;
    do {
      cVar1 = param_3[iVar1];
      if ((byte)(cVar1 + 0xbfU) < 0x1a) {
        cVar1 = cVar1 + ' ';
      }
      *param_3 = cVar1;
      param_3 = param_3 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return;
}



uint __cdecl FUN_662073b0(int param_1,undefined4 param_2,undefined4 param_3,uint param_4)

{
  undefined2 uVar1;
  short sVar1;
  uint extraout_ECX;
  uint uVar2;
  uint uVar3;
  undefined2 *puVar1;
  longlong lVar1;
  
  if (0x22 < (param_4 - 2)) {
    return 0;
  }
  lVar1 = ((longlong)(int)param_3 << 0x20) + param_2;
  uVar3 = 0;
  do {
    lVar1 = __aulldvrm((uint)lVar1,(uint)((ulonglong)lVar1 >> 0x20),param_4,0);
    sVar1 = (short)extraout_ECX + 0x30;
    if (9 < extraout_ECX) {
      sVar1 = (short)extraout_ECX + 0x57;
    }
    *(short *)(param_1 + (uVar3 * 2)) = sVar1;
    uVar3 = uVar3 + 1;
  } while (lVar1 != 0);
  uVar2 = 0;
  if (uVar3 >> 1 != 0) {
    puVar1 = (undefined2 *)(param_1 + -2 + (uVar3 * 2));
    do {
      uVar1 = *(undefined2 *)(param_1 + (uVar2 * 2));
      *(undefined2 *)(param_1 + (uVar2 * 2)) = *puVar1;
      uVar2 = uVar2 + 1;
      *puVar1 = uVar1;
      puVar1 = puVar1 + -1;
    } while (uVar2 < (uVar3 >> 1));
  }
  return uVar3;
}



undefined4 * __thiscall InitializeObjectWithDefaults(void *this,undefined4 param_1)

{
  *(undefined4 *)this = param_1;
  *(undefined *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  return (undefined4 *)this;
}



void __fastcall FUN_66207460(void **param_1)

{
  int iVar1;
  
  if ((*(char *)(param_1 + 1) == '\0') && (*param_1 != (void *)0x0)) {
    iVar1 = get_process_data();
    FID_conflict__free(*param_1);
    runtimeproc_info(iVar1);
  }
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  *(undefined *)(param_1 + 1) = 0;
  return;
}



void ** __thiscall UpdateAndResetObjectState(void *this,void *param_1)

{
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  if ((*(char *)((int)this + 4) == '\0') && (*this != 0)) {
    iVar1 = get_process_data();
                    // WARNING: Load size is inaccurate
    FID_conflict__free(*this);
    runtimeproc_info(iVar1);
  }
  *(void **)this = param_1;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined *)((int)this + 4) = 0;
  return (void **)this;
}



void __thiscall FUN_66207510(void *this,void **param_1)

{
  void *pvVar1;
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  if ((*(char *)((int)this + 4) == '\0') && (*this != 0)) {
    iVar1 = get_process_data();
                    // WARNING: Load size is inaccurate
    FID_conflict__free(*this);
    runtimeproc_info(iVar1);
  }
  *(void **)((int)this + 8) = param_1[2];
  *(void **)((int)this + 0xc) = param_1[3];
  *(undefined *)((int)this + 4) = *(undefined *)(param_1 + 1);
  pvVar1 = *param_1;
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  *(undefined *)(param_1 + 1) = 0;
  *(void **)this = pvVar1;
  return;
}



undefined4 __fastcall CleanupAndResetProcessInfo(void **param_1)

{
  int iVar1;
  
  if ((*(char *)(param_1 + 1) == '\0') && (*param_1 != (void *)0x0)) {
    iVar1 = get_process_data();
    FID_conflict__free(*param_1);
    runtimeproc_info(iVar1);
  }
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  *(undefined *)(param_1 + 1) = 0;
  return 0;
}



undefined4 * FUN_662075c0(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b8f0;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  puVar1 = FUN_6620a670(param_1,param_2);
  s8 = 0;
  CopyMemoryDWord(puVar1 + 2,param_3);
  *in_FS_OFFSET = s10;
  return puVar1;
}



undefined4 * __thiscall FUN_66207640(void *this,undefined4 param_1,int *param_2)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b900;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  puVar1 = FUN_6620a710((undefined4 *)this);
  *(undefined2 *)(puVar1 + 3) = 0;
  s8 = 0;
  FUN_66207bf0(puVar1 + 4,param_1,param_2);
  *in_FS_OFFSET = s10;
  return puVar1;
}



void __thiscall
FUN_662076c0(void *this,int **param_1,char param_2,int **param_3,undefined4 param_4,int *param_5)

{
  char cVar1;
  int **ppiVar1;
  int iVar1;
  code *pcVar1;
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int **ppiVar2;
  
  if (0x7fffffd < *(uint *)((int)this + 4)) {
    FID_conflict__free(param_5);
    FUN_6620c903(s_map_set_T__too_long_6621cedc);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  *(uint *)((int)this + 4) = *(uint *)((int)this + 4) + 1;
  param_5[1] = (int)param_3;
                    // WARNING: Load size is inaccurate
  if (param_3 == *this) {
    (*this)[1] = param_5;
                    // WARNING: Load size is inaccurate
    **this = param_5;
                    // WARNING: Load size is inaccurate
    *(int **)(*this + 8) = param_5;
  }
  else if (param_2 == '\0') {
    param_3[2] = param_5;
                    // WARNING: Load size is inaccurate
    if (param_3 == *(int ***)(*this + 8)) {
      *(int **)(*this + 8) = param_5;
    }
  }
  else {
    *param_3 = param_5;
                    // WARNING: Load size is inaccurate
    if (param_3 == (int **)**this) {
      **this = param_5;
    }
  }
  cVar1 = *(char *)(param_5[1] + 0xc);
  piVar1 = param_5;
  do {
    if (cVar1 != '\0') {
                    // WARNING: Load size is inaccurate
      *(undefined *)(*(int *)(*this + 4) + 0xc) = 1;
      *param_1 = param_5;
      return;
    }
    piVar3 = (int *)piVar1[1];
    piVar2 = *(int **)piVar3[1];
    if (piVar3 == piVar2) {
      piVar2 = ((int **)piVar3[1])[2];
      if (*(char *)(piVar2 + 3) != '\0') {
        if (piVar1 == (int *)piVar3[2]) {
          ppiVar2 = (int **)piVar3[2];
          piVar3[2] = (int)*ppiVar2;
          if (*(char *)((int)*ppiVar2 + 0xd) == '\0') {
            (*ppiVar2)[1] = (int)piVar3;
          }
          ppiVar2[1] = (int *)piVar3[1];
                    // WARNING: Load size is inaccurate
          if (piVar3 == *(int **)(*this + 4)) {
            *(int ***)(*this + 4) = ppiVar2;
          }
          else {
            ppiVar1 = (int **)piVar3[1];
            if (piVar3 == *ppiVar1) {
              *ppiVar1 = (int *)ppiVar2;
            }
            else {
              ppiVar1[2] = (int *)ppiVar2;
            }
          }
          *ppiVar2 = piVar3;
          piVar3[1] = (int)ppiVar2;
          piVar1 = piVar3;
        }
        *(undefined *)(piVar1[1] + 0xc) = 1;
        *(undefined *)(*(int *)(piVar1[1] + 4) + 0xc) = 0;
        piVar3 = *(int **)(piVar1[1] + 4);
        ppiVar2 = (int **)*piVar3;
        *piVar3 = (int)ppiVar2[2];
        if (*(char *)((int)ppiVar2[2] + 0xd) == '\0') {
          *(int **)((int)ppiVar2[2] + 4) = piVar3;
        }
        ppiVar2[1] = (int *)piVar3[1];
                    // WARNING: Load size is inaccurate
        if (piVar3 == *(int **)(*this + 4)) {
          *(int ***)(*this + 4) = ppiVar2;
          ppiVar2[2] = piVar3;
        }
        else {
          piVar2 = (int *)piVar3[1];
          if (piVar3 == (int *)piVar2[2]) {
            piVar2[2] = (int)ppiVar2;
            ppiVar2[2] = piVar3;
          }
          else {
            *piVar2 = (int)ppiVar2;
            ppiVar2[2] = piVar3;
          }
        }
        goto LAB_6620788f;
      }
LAB_662077e6:
      *(undefined *)(piVar3 + 3) = 1;
      *(undefined *)(piVar2 + 3) = 1;
      *(undefined *)(*(int *)(piVar1[1] + 4) + 0xc) = 0;
      piVar1 = *(int **)(piVar1[1] + 4);
    }
    else {
      if (*(char *)(piVar2 + 3) == '\0') goto LAB_662077e6;
      if (piVar1 == (int *)*piVar3) {
        iVar1 = *piVar3;
        *piVar3 = *(int *)(iVar1 + 8);
        if (*(char *)(*(int *)(iVar1 + 8) + 0xd) == '\0') {
          *(int **)(*(int *)(iVar1 + 8) + 4) = piVar3;
        }
        *(int *)(iVar1 + 4) = piVar3[1];
                    // WARNING: Load size is inaccurate
        if (piVar3 == *(int **)(*this + 4)) {
          *(int *)(*this + 4) = iVar1;
        }
        else {
          piVar1 = (int *)piVar3[1];
          if (piVar3 == (int *)piVar1[2]) {
            piVar1[2] = iVar1;
          }
          else {
            *piVar1 = iVar1;
          }
        }
        *(int **)(iVar1 + 8) = piVar3;
        piVar3[1] = iVar1;
        piVar1 = piVar3;
      }
      *(undefined *)(piVar1[1] + 0xc) = 1;
      *(undefined *)(*(int *)(piVar1[1] + 4) + 0xc) = 0;
      piVar3 = *(int **)(piVar1[1] + 4);
      ppiVar2 = (int **)piVar3[2];
      piVar3[2] = (int)*ppiVar2;
      if (*(char *)((int)*ppiVar2 + 0xd) == '\0') {
        (*ppiVar2)[1] = (int)piVar3;
      }
      ppiVar2[1] = (int *)piVar3[1];
                    // WARNING: Load size is inaccurate
      if (piVar3 == *(int **)(*this + 4)) {
        *(int ***)(*this + 4) = ppiVar2;
      }
      else {
        ppiVar1 = (int **)piVar3[1];
        if (piVar3 == *ppiVar1) {
          *ppiVar1 = (int *)ppiVar2;
        }
        else {
          ppiVar1[2] = (int *)ppiVar2;
        }
      }
      *ppiVar2 = piVar3;
LAB_6620788f:
      piVar3[1] = (int)ppiVar2;
    }
    cVar1 = *(char *)(piVar1[1] + 0xc);
  } while( true );
}



int ** __thiscall FUN_662078d0(void *this,int **param_1,int **param_2,uint *param_3,int *param_4)

{
  uint uVar1;
  int **ppiVar1;
  undefined4 *in_FS_OFFSET;
  char cVar1;
  int **ppiVar2;
  int *s24;
  int **s20;
  void *s1c;
  undefined *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b910;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s14 = &stack0xffffffd0;
  s8 = 0;
  s1c = this;
  if (*(int *)((int)this + 4) == 0) {
                    // WARNING: Load size is inaccurate
    ppiVar2 = *this;
    s14 = &stack0xffffffd0;
  }
  else {
                    // WARNING: Load size is inaccurate
    ppiVar1 = *this;
    if (param_2 != (int **)*ppiVar1) {
      if (param_2 != ppiVar1) {
        uVar1 = FUN_66207ff0(param_3,(uint *)(param_2 + 4));
        if ((char)uVar1 != '\0') {
          s20 = param_2;
          FUN_66207f90((int **)&s20);
          ppiVar2 = s20;
          uVar1 = FUN_66207ff0((uint *)(s20 + 4),param_3);
          if ((char)uVar1 != '\0') {
            this = s1c;
            if (*(char *)((int)ppiVar2[2] + 0xd) == '\0') {
              cVar1 = '\x01';
              ppiVar2 = param_2;
            }
            else {
              cVar1 = '\0';
            }
            goto LAB_6620790f;
          }
        }
        uVar1 = FUN_66207ff0((uint *)(param_2 + 4),param_3);
        this = s1c;
        if ((char)uVar1 != '\0') {
          s20 = param_2;
          FUN_66207f40((int **)&s20);
          ppiVar2 = s20;
          if ((s20 == ppiVar1) ||
             (uVar1 = FUN_66207ff0(param_3,(uint *)(s20 + 4)), this = s1c, (char)uVar1 != '\0')) {
            this = s1c;
            if (*(char *)((int)param_2[2] + 0xd) == '\0') {
              cVar1 = '\x01';
            }
            else {
              cVar1 = '\0';
              ppiVar2 = param_2;
            }
            goto LAB_6620790f;
          }
        }
LAB_66207a32:
        s8 = 0xffffffff;
        ppiVar1 = (int **)FUN_66207a80(this,&s24,(int **)0x0,param_3,param_4);
        *param_1 = *ppiVar1;
        *in_FS_OFFSET = s10;
        return param_1;
      }
      ppiVar2 = (int **)ppiVar1[2];
      s14 = &stack0xffffffd0;
      uVar1 = FUN_66207ff0((uint *)(ppiVar2 + 4),param_3);
      if ((char)uVar1 == '\0') goto LAB_66207a32;
      cVar1 = '\0';
      goto LAB_6620790f;
    }
    s14 = &stack0xffffffd0;
    uVar1 = FUN_66207ff0(param_3,(uint *)(param_2 + 4));
    ppiVar2 = param_2;
    if ((char)uVar1 == '\0') goto LAB_66207a32;
  }
  cVar1 = '\x01';
LAB_6620790f:
  FUN_662076c0(this,param_1,cVar1,ppiVar2,param_3,param_4);
  *in_FS_OFFSET = s10;
  return param_1;
}



// WARNING: Could not reconcile some variable overlaps

void __thiscall FUN_66207a80(void *this,int **param_1,int **param_2,uint *param_3,int *param_4)

{
  uint *puVar1;
  uint uVar1;
  int **ppiVar1;
  int **ppiVar2;
  undefined4 *in_FS_OFFSET;
  uint s18;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puVar1 = param_3;
  puStack12 = &LAB_6621b920;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s8 = 0;
                    // WARNING: Load size is inaccurate
  uVar1 = 1;
  s18 = 1;
  ppiVar1 = (int **)(*this)[1];
  ppiVar2 = *this;
  while (*(char *)((int)ppiVar1 + 0xd) == '\0') {
    if ((char)param_2 == '\0') {
      uVar1 = FUN_66207ff0(puVar1,(uint *)(ppiVar1 + 4));
    }
    else {
      uVar1 = FUN_66207ff0((uint *)(ppiVar1 + 4),puVar1);
      uVar1 = (uint)((char)uVar1 == '\0');
    }
    s18 = uVar1 & 0xff;
    ppiVar2 = ppiVar1;
    if ((char)uVar1 == '\0') {
      ppiVar1 = (int **)ppiVar1[2];
    }
    else {
      ppiVar1 = (int **)*ppiVar1;
    }
  }
  param_2 = ppiVar2;
  if ((char)uVar1 != '\0') {
                    // WARNING: Load size is inaccurate
    if (ppiVar2 == (int **)**this) {
      s18._0_1_ = '\x01';
      goto LAB_66207b0a;
    }
    FUN_66207f90((int **)&param_2);
  }
  ppiVar1 = param_2;
  uVar1 = FUN_66207ff0((uint *)(param_2 + 4),puVar1);
  if ((char)uVar1 == '\0') {
    FID_conflict__free(param_4);
    *param_1 = (int *)ppiVar1;
    *(undefined *)(param_1 + 1) = 0;
    *in_FS_OFFSET = s10;
    return;
  }
LAB_66207b0a:
  ppiVar1 = (int **)FUN_662076c0(this,(int **)&param_2,(char)s18,ppiVar2,puVar1,param_4);
  *param_1 = *ppiVar1;
  *(undefined *)(param_1 + 1) = 1;
  *in_FS_OFFSET = s10;
  return;
}



void CopyMemoryDWord(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined s10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = s10;
  if (param_1 != (undefined4 *)0x0) {
    *param_1 = *param_2;
  }
  *in_FS_OFFSET = uVar1;
  return;
}



void FUN_66207bf0(undefined4 *param_1,undefined4 param_2,int *param_3)

{
  undefined4 uVar1;
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined s10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = s10;
  if (param_1 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*param_3;
    *param_1 = *puVar1;
    param_1[1] = puVar1[1];
    param_1[2] = 0;
  }
  *in_FS_OFFSET = uVar1;
  return;
}



void FUN_66207c50(void)

{
  return;
}



int __thiscall FUN_66207c60(void *this,int param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b9c8;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  *(int *)((int)this + 0x28) = param_1;
  iVar1 = (int)this + 8;
  *(undefined4 *)((int)this + 0x30) = 0;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x38) = 0;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(void **)((int)this + 4) = this;
  *(void **)this = this;
  *(int *)((int)this + 0xc) = iVar1;
  *(int *)iVar1 = iVar1;
  s8 = 0;
  *(undefined *)((int)this + 0x5a) = (undefined)param_2;
  *(int *)((int)this + 0x48) = param_1;
  *(undefined4 *)((int)this + 0x4c) = 0;
  *(undefined4 *)((int)this + 0x50) = 0;
  *(undefined4 *)((int)this + 0x54) = 0;
  *(undefined2 *)((int)this + 0x58) = 0;
  iVar1 = FUN_66206ef0(param_1,(int)&param_1 + 3);
  if ((-1 < iVar1) && (param_1._3_1_ == '\0')) {
    *(undefined *)((int)this + 0x58) = 1;
  }
  if (*(char *)((int)this + 0x58) == '\0') {
    iVar1 = FUN_66206e40(*(undefined4 *)((int)this + 0x48),(undefined *)((int)&param_2 + 3));
    if (iVar1 < 0) {
      param_2._3_1_ = 0;
    }
    *(undefined *)((int)this + 0x59) = param_2._3_1_;
  }
  *(uint *)((int)this + 0x4c) = ((uint)(*(char *)((int)this + 0x59) != '\0') * 4) + 4;
  *in_FS_OFFSET = s10;
  return (int)this;
}



void __fastcall FUN_66207d50(int **param_1)

{
  undefined4 *in_FS_OFFSET;
  int *s18;
  int **s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b968;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s8 = 0;
  s14 = param_1;
  FUN_6620a9a0(param_1,&s18,(int **)**param_1,(int **)*param_1);
  s8 = 0xffffffff;
  FID_conflict__free(*param_1);
  *in_FS_OFFSET = s10;
  return;
}



void __fastcall FUN_66207dc0(void **param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b988;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s8 = 0xffffffff;
  FID_conflict__free(*param_1);
  *in_FS_OFFSET = s10;
  return;
}



void __fastcall FUN_66207e00(void **param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b9b0;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s8 = 0xffffffff;
  FID_conflict__free(*param_1);
  *in_FS_OFFSET = s10;
  return;
}



void __fastcall FUN_66207e40(int **param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621b9c8;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s8 = 0;
  FUN_66209870(param_1);
  s8 = 0xffffffff;
  FUN_66209870(param_1);
  *in_FS_OFFSET = s10;
  return;
}



int ** __thiscall FUN_66207ea0(void *this,int **param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  int *piVar1;
  int **ppiVar4;
  bool bVar1;
  int **s8;
  
                    // WARNING: Load size is inaccurate
  ppiVar1 = *this;
  ppiVar4 = ppiVar1;
  if (*(char *)((int)ppiVar1[1] + 0xd) == '\0') {
    piVar1 = param_1[1];
    ppiVar2 = (int **)ppiVar1[1];
    do {
      bVar1 = piVar1 <= ppiVar2[5];
      if ((bVar1 && (ppiVar2[5] != piVar1)) || ((bVar1 && (*param_1 <= ppiVar2[4])))) {
        ppiVar3 = (int **)*ppiVar2;
        ppiVar4 = ppiVar2;
      }
      else {
        ppiVar3 = (int **)ppiVar2[2];
      }
      ppiVar2 = ppiVar3;
    } while (*(char *)((int)ppiVar3 + 0xd) == '\0');
  }
  if ((ppiVar4 != ppiVar1) &&
     ((piVar1 = param_1[1], bVar1 = ppiVar4[5] <= piVar1, bVar1 && (piVar1 != ppiVar4[5]) ||
      ((bVar1 && (ppiVar4[4] <= *param_1)))))) {
    return ppiVar4 + 6;
  }
  s8 = param_1;
  piVar1 = FUN_66207640(this,&DAT_6624b4bb,(int *)&s8);
  FUN_662078d0(this,(int **)&param_1,ppiVar4,(uint *)(piVar1 + 4),piVar1);
  return param_1 + 6;
}



int ** __fastcall FUN_66207f40(int **param_1)

{
  char cVar1;
  int *piVar1;
  int **ppiVar1;
  int **ppiVar2;
  
  piVar1 = *param_1;
  if (*(char *)((int)piVar1 + 0xd) == '\0') {
    ppiVar1 = (int **)piVar1[2];
    if (*(char *)((int)ppiVar1 + 0xd) == '\0') {
      cVar1 = *(char *)((int)*ppiVar1 + 0xd);
      ppiVar2 = (int **)*ppiVar1;
      while (cVar1 == '\0') {
        cVar1 = *(char *)((int)*ppiVar2 + 0xd);
        ppiVar1 = ppiVar2;
        ppiVar2 = (int **)*ppiVar2;
      }
      *param_1 = (int *)ppiVar1;
      return param_1;
    }
    piVar1 = (int *)piVar1[1];
    cVar1 = *(char *)((int)piVar1 + 0xd);
    while ((cVar1 == '\0' && (*param_1 == (int *)piVar1[2]))) {
      *param_1 = piVar1;
      piVar1 = (int *)piVar1[1];
      cVar1 = *(char *)((int)piVar1 + 0xd);
    }
    *param_1 = piVar1;
  }
  return param_1;
}



int ** __fastcall FUN_66207f90(int **param_1)

{
  char cVar1;
  int **ppiVar1;
  int *piVar1;
  int *piVar2;
  int **ppiVar2;
  
  ppiVar1 = (int **)*param_1;
  if (*(char *)((int)ppiVar1 + 0xd) != '\0') {
    *param_1 = ppiVar1[2];
    return param_1;
  }
  ppiVar2 = (int **)*ppiVar1;
  if (*(char *)((int)ppiVar2 + 0xd) == '\0') {
    piVar1 = ppiVar2[2];
    if (*(char *)((int)ppiVar2[2] + 0xd) == '\0') {
      do {
        piVar2 = piVar1;
        piVar1 = (int *)piVar2[2];
      } while (*(char *)((int)piVar1 + 0xd) == '\0');
      *param_1 = piVar2;
      return param_1;
    }
  }
  else {
    ppiVar2 = (int **)ppiVar1[1];
    cVar1 = *(char *)((int)ppiVar2 + 0xd);
    while ((cVar1 == '\0' && (*param_1 == *ppiVar2))) {
      *param_1 = (int *)ppiVar2;
      ppiVar2 = (int **)ppiVar2[1];
      cVar1 = *(char *)((int)ppiVar2 + 0xd);
    }
    if (*(char *)((int)*param_1 + 0xd) != '\0') {
      return param_1;
    }
  }
  *param_1 = (int *)ppiVar2;
  return param_1;
}



uint FUN_66207ff0(uint *param_1,uint *param_2)

{
  uint uVar1;
  bool bVar1;
  
  uVar1 = param_1[1];
  bVar1 = uVar1 < param_2[1];
  if ((bVar1 || (uVar1 == param_2[1])) && ((bVar1 || (uVar1 = *param_1, uVar1 < *param_2)))) {
    return ((int)(int3)(uVar1 >> 8) << 8) + 1;
  }
  return uVar1 & 0xffffff00;
}



// WARNING: Could not reconcile some variable overlaps

int __thiscall FUN_66208020(void *this,uint param_1,uint param_2,char *param_3,undefined *param_4)

{
  int iVar1;
  char cVar1;
  uint uVar1;
  undefined4 uStack8;
  
  cVar1 = *param_3;
  uVar1 = 0;
  uStack8 = this;
  iVar1 = FUN_66208e70(this,param_1,param_2,(int)&uStack8 + 3,1,0);
  if (-1 < iVar1) {
    while (cVar1 == uStack8._3_1_) {
      if (cVar1 == '\0') {
        *param_4 = 1;
        return 0;
      }
      uVar1 = uVar1 + 1;
      cVar1 = param_3[uVar1];
      iVar1 = FUN_66208e70(this,uVar1 + param_1,param_2 + (CARRY4(uVar1,param_1)),(int)&uStack8 + 3,
                           1,0);
      if (iVar1 < 0) {
        return iVar1;
      }
    }
    *param_4 = 0;
    iVar1 = 0;
  }
  return iVar1;
}



// WARNING: Could not reconcile some variable overlaps

int __thiscall FUN_662080a0(void *this,int param_1,int param_2,uint param_3)

{
  ushort uVar1;
  int iVar1;
  int *piVar1;
  void *pvVar1;
  uint uVar2;
  int *piVar2;
  uint uVar3;
  bool bVar1;
  undefined s2c [16];
  undefined4 s1c;
  undefined8 s18;
  uint s10;
  undefined8 sc;
  
  s10 = 0;
  if (param_3 != 0) {
    do {
      uVar3 = (uint)*(ushort *)(param_2 + (s10 * 2));
      iVar1 = FUN_66202d70((int *)&DAT_6624b2f8);
      if (((char)iVar1 == '\0') || (uVar3 != 10)) {
        uVar1 = *(ushort *)(param_1 + 0x14);
        if (uVar3 == 1) {
          sc = 0;
          if ((uVar1 < 2) || (*(short *)(param_1 + 0x18) != 0x10b)) {
            uVar3 = *(uint *)(param_1 + 0x84);
          }
          else {
            uVar3 = *(uint *)(param_1 + 0x74);
          }
          if (1 < uVar3) {
            if ((uVar1 < 2) || (iVar1 = param_1 + 0x78, *(short *)(param_1 + 0x18) != 0x10b)) {
              iVar1 = param_1 + 0x88;
            }
            if (((uint *)(iVar1 + 8) != (uint *)0x0) && (uVar3 = *(uint *)(iVar1 + 8), uVar3 != 0))
            {
              iVar1 = FUN_66209da0(this,param_1,uVar3,(int *)&sc);
              if (iVar1 < 0) {
                return iVar1;
              }
              if (((uint)(int *)sc | (uint)sc._4_4_) != 0) {
                s2c = ZEXT816(0);
                s1c = 0;
                if ((*(char *)((int)this + 0x5a) != '\0') &&
                   (iVar1 = FUN_66209f90(this,(int *)sc,sc._4_4_,0x14,0,'\0'), iVar1 < 0)) {
                  return iVar1;
                }
                if (*(char *)((int)this + 0x58) == '\0') {
                  pvVar1 = (void *)FUN_66208ab0();
                  if ((pvVar1 != (void *)0x0) && (*(char *)((int)pvVar1 + 0x20) != '\0')) {
                    FUN_6620a420(pvVar1,*(undefined4 *)((int)this + 0x48),(uint)(int *)sc,
                                 (uint)sc._4_4_,(int)s2c,0x14,0);
                  }
                  iVar1 = FUN_6620bf70(&DAT_6624b500,*(undefined4 *)((int)this + 0x48),
                                       (uint)(int *)sc,(uint)sc._4_4_,s2c,0x14,0);
                  goto joined_r0x662082e3;
                }
                FUN_6620dc00((int *)sc,s2c,0x14);
              }
              goto LAB_662082f0;
            }
          }
          iVar1 = -0x3fffff86;
LAB_662082ec:
          if (iVar1 < 0) {
            return iVar1;
          }
        }
        else {
          if ((uVar1 < 2) || (*(short *)(param_1 + 0x18) != 0x10b)) {
            uVar2 = *(uint *)(param_1 + 0x84);
          }
          else {
            uVar2 = *(uint *)(param_1 + 0x74);
          }
          if (uVar3 < uVar2) {
            if ((uVar1 < 2) || (*(short *)(param_1 + 0x18) != 0x10b)) {
              bVar1 = 0xffffff77 < *(uint *)(param_1 + 0x108);
              uVar2 = *(uint *)(param_1 + 0x108) + 0x88;
            }
            else {
              bVar1 = 0xffffff87 < *(uint *)(param_1 + 0x108);
              uVar2 = *(uint *)(param_1 + 0x108) + 0x78;
            }
            piVar1 = (int *)((uVar3 * 8) + uVar2);
            piVar2 = (int *)(*(int *)(param_1 + 0x10c) + (uint)bVar1 + (uint)CARRY4(uVar3 * 8,uVar2)
                            );
            sc = (sc & 0xffffffff) | (ZEXT48(piVar2) << 0x20);
            if (((uint)piVar1 | (uint)piVar2) != 0) {
              s18 = 0;
              if ((*(char *)((int)this + 0x5a) != '\0') &&
                 (iVar1 = FUN_66209f90(this,piVar1,piVar2,8,0,'\0'), iVar1 < 0)) {
                return iVar1;
              }
              if (*(char *)((int)this + 0x58) == '\0') {
                pvVar1 = (void *)FUN_66208ab0();
                if ((pvVar1 != (void *)0x0) && (*(char *)((int)pvVar1 + 0x20) != '\0')) {
                  FUN_6620a420(pvVar1,*(undefined4 *)((int)this + 0x48),(uint)piVar1,(uint)sc._4_4_,
                               (int)&s18,8,0);
                }
                iVar1 = FUN_6620bf70(&DAT_6624b500,*(undefined4 *)((int)this + 0x48),(uint)piVar1,
                                     (uint)sc._4_4_,&s18,8,0);
joined_r0x662082e3:
                if (iVar1 < 0) goto LAB_662082ec;
              }
              else {
                FUN_6620dc00(piVar1,&s18,8);
              }
            }
          }
        }
      }
LAB_662082f0:
      s10 = s10 + 1;
    } while (s10 < param_3);
  }
  return 0;
}



// WARNING: Could not reconcile some variable overlaps

int __thiscall
FUN_66208310(void *this,int param_1,undefined *param_2,undefined *param_3,undefined4 param_4)

{
  uint uVar1;
  int iVar1;
  undefined4 *in_FS_OFFSET;
  bool bVar1;
  uint sa4 [3];
  uint s98;
  uint s94;
  uint s90;
  int s8c;
  void *s88 [4];
  undefined8 s78;
  uint s70;
  int s6c;
  uint s68;
  uint s64;
  uint s60;
  uint s5c;
  uint s58;
  uint s54;
  uint s50;
  int s4c;
  uint s48;
  void *s44 [4];
  uint s34;
  int s30;
  uint s2c;
  uint s28;
  uint s24;
  undefined8 s20;
  void *s18;
  char s11;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621ba73;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s20 = 0;
  s18 = this;
  iVar1 = FUN_66209920(param_1,1,&s34,&s20);
  if (-1 < iVar1) {
    if ((*(ushort *)(param_1 + 0x14) < 2) || (s11 = '\x01', *(short *)(param_1 + 0x18) != 0x10b)) {
      s11 = '\0';
    }
    s2c = s20._4_4_;
    s24 = (uint)s20;
    iVar1 = FUN_66208e70(this,(uint)s20,s20._4_4_,(int)sa4,0x14,0);
    if (-1 < iVar1) {
LAB_662083a0:
      if (sa4[0] == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = FUN_66209da0(this,param_1,s98,(int *)&s58);
        if (-1 < iVar1) {
          InitializeObjectWithDefaults(s44,0);
          uVar1 = s54;
          s8 = 0;
          iVar1 = FUN_66209110(this,s58,s54,s44,&s60);
          if (iVar1 < 0) goto LAB_6620865c;
          FUN_66207380((int)s44[0],s60,(char *)s44[0]);
          if (param_2 == (undefined *)0x0) {
LAB_66208438:
            if (param_3 != (undefined *)0x0) {
              iVar1 = FUN_66209da0(this,param_1,sa4[0],(int *)&s70);
              if ((-1 < iVar1) && (iVar1 = FUN_66209da0(this,param_1,s94,(int *)&s90), -1 < iVar1))
              {
                s30 = 0;
                s34 = ((uint)(s11 == '\0') * 4) + 4;
                do {
                  s5c = s34 * s30;
                  s4c = 0;
                  s48 = s5c + s70;
                  s50 = s6c + (uint)CARRY4(s5c,s70);
                  iVar1 = FUN_66208e70(this,s48,s50,(int)&s20,s34,0);
                  if (iVar1 < 0) break;
                  if (s11 == '\0') {
                  }
                  else {
                    s20._4_4_ = 0;
                  }
                  if (((uint)s20 | s20._4_4_) == 0) goto LAB_6620860c;
                  InitializeObjectWithDefaults(s88,0);
                  s8._0_1_ = 1;
                  s78 = 0;
                  if (s11 == '\0') {
                    if ((s20 & 0x8000000000000000) != 0) goto LAB_66208515;
LAB_6620859e:
                    iVar1 = FUN_66209da0(this,param_1,(uint)s20,(int *)&s68);
                    s78._4_4_ = s64;
                    uVar1 = s68;
                    if ((-1 < iVar1) &&
                       (iVar1 = FUN_66208e70(s18,s68,s64,(int)&s28,2,0), -1 < iVar1)) {
                      s78._0_4_ = uVar1 + 2;
                      s78._4_4_ = s78._4_4_ + ((0xfffffffd < uVar1));
                      iVar1 = FUN_66209110(s18,(uint)s78,s78._4_4_,s88,(uint *)0x0);
                      if (iVar1 < 0) goto LAB_6620864d;
                      goto LAB_66208521;
                    }
LAB_6620864d:
                    s8 = (uint)s8._1_3_ << 8;
                    FUN_66207460(s88);
                    break;
                  }
                  if (-1 < (int)(uint)s20) goto LAB_6620859e;
LAB_66208515:
                  s78._4_4_ = 0;
                  s78._0_4_ = 0;
                  s28 = (uint)s20 & 0xffff;
LAB_66208521:
                  iVar1 = (*(code *)param_3)(s44[0],s88[0],(uint)s78,s78._4_4_,s28,s5c + s90,
                                             s4c + s8c + (uint)CARRY4(s5c,s90),s48,s50,param_4);
                  if (iVar1 == 0x4000000f) goto LAB_662085fa;
                  if (iVar1 != -0x3ffffd8f) goto LAB_6620864d;
                  s8 = (uint)s8._1_3_ << 8;
                  FUN_66207460(s88);
                  s30 = s30 + 1;
                  this = s18;
                } while( true );
              }
LAB_6620865c:
              s8 = 0xffffffff;
              FUN_66207460(s44);
              *in_FS_OFFSET = s10;
              return iVar1;
            }
          }
          else {
            iVar1 = (*(code *)param_2)(s44[0],s58,uVar1,param_4);
            if (iVar1 != 0x4000000f) {
              if (iVar1 != -0x3ffffd8f) goto LAB_6620865c;
              goto LAB_66208438;
            }
          }
          goto LAB_6620860c;
        }
      }
    }
  }
LAB_66208683:
  *in_FS_OFFSET = s10;
  return iVar1;
LAB_662085fa:
  s8 = (uint)s8._1_3_ << 8;
  FUN_66207460(s88);
  this = s18;
LAB_6620860c:
  s8 = 0xffffffff;
  FUN_66207460(s44);
  bVar1 = 0xffffffeb < s24;
  s24 = s24 + 0x14;
  s2c = s2c + (bVar1);
  iVar1 = FUN_66208e70(this,s24,s2c,(int)sa4,0x14,0);
  if (iVar1 < 0) goto LAB_66208683;
  goto LAB_662083a0;
}



undefined4 __cdecl FUN_662086a0(int param_1,int param_2,uint param_3,int param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ushort uVar5;
  int iVar1;
  
  uVar1 = *(uint *)(param_1 + 0x50);
  FUN_6620d410(param_4,0,uVar1);
  uVar4 = *(uint *)(param_1 + 0x54);
  if ((param_3 < uVar4) || (uVar1 < uVar4)) {
    return 0xc000007b;
  }
  FUN_6620d5b0(param_4,param_2,uVar4);
  uVar5 = 0;
  if (*(short *)(param_1 + 6) != 0) {
    do {
      iVar1 = ((uint)uVar5 * 0x28) + (uint)*(ushort *)(param_1 + 0x14) + *(int *)(param_1 + 0x108);
      uVar4 = *(uint *)(iVar1 + 0x28);
      uVar2 = *(uint *)(iVar1 + 0x2c);
      if (*(uint *)(iVar1 + 0x20) < uVar4) {
        uVar4 = *(uint *)(iVar1 + 0x20);
      }
      uVar3 = *(uint *)(iVar1 + 0x24);
      if (param_3 < uVar2) {
        return 0xc000007b;
      }
      if (uVar1 < uVar3) {
        return 0xc000007b;
      }
      if ((uVar2 + uVar4) < uVar4) {
        return 0xc000007b;
      }
      if (param_3 < (uVar2 + uVar4)) {
        return 0xc000007b;
      }
      if ((uVar3 + uVar4) < uVar4) {
        return 0xc000007b;
      }
      if (uVar1 < (uVar3 + uVar4)) {
        return 0xc000007b;
      }
      FUN_6620d5b0(param_4 + uVar3,uVar2 + param_2,uVar4);
      uVar5 = uVar5 + 1;
    } while (uVar5 < *(ushort *)(param_1 + 6));
  }
  return 0;
}



int __fastcall FUN_662087a0(int **param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_66209870(param_1);
  iVar2 = 0;
  if (iVar1 < 0) {
    iVar2 = iVar1;
  }
  return iVar2;
}



void __thiscall FUN_662087b0(void *this,void *param_1)

{
  void *pvVar1;
  
  pvVar1 = (void *)((int)this + 8);
  if (param_1 == pvVar1) {
    *(void **)((int)this + 0xc) = pvVar1;
    *(void **)pvVar1 = pvVar1;
    return;
  }
  FID_conflict__free(param_1);
  return;
}



// WARNING: Could not reconcile some variable overlaps

int __thiscall FUN_662087e0(void *this,int param_1,char *param_2,uint *param_3,char *param_4)

{
  char cVar1;
  int iVar1;
  uint uVar1;
  uint uVar2;
  undefined s58 [16];
  int s48;
  uint s44;
  uint s40;
  uint s3c;
  uint s38;
  uint s34;
  uint s30;
  uint s2c;
  uint s28;
  int s24;
  undefined8 s20;
  uint s18;
  uint s14;
  uint s10;
  uint sc;
  char s5;
  
  s20 = 0;
  iVar1 = FUN_66209920(param_1,0,&s18,&s20);
  if (iVar1 < 0) {
    return iVar1;
  }
  iVar1 = FUN_66208e70(this,(uint)s20,s20._4_4_,(int)s58,0x28,0);
  if (iVar1 < 0) {
    return iVar1;
  }
  sc = ((int)param_2 - s48) & 0xffff;
  if ((char *)0xffff < param_2) {
    iVar1 = FUN_66209da0(this,param_1,s38,(int *)&s28);
    if (iVar1 < 0) {
      return iVar1;
    }
    uVar2 = 0;
    if (s40 == 0) {
      return -0x3fffff86;
    }
    uVar1 = 0;
    do {
      iVar1 = FUN_66208e70(this,uVar1 + s28,s24 + (uint)CARRY4(uVar1,s28),(int)&s10,4,0);
      if (iVar1 < 0) {
        return iVar1;
      }
      if (s10 != 0) {
        iVar1 = FUN_66209da0(this,param_1,s10,(int *)&s30);
        if (iVar1 < 0) {
          return iVar1;
        }
        iVar1 = FUN_66208020(this,s30,s2c,param_2,&s5);
        if (iVar1 < 0) {
          return iVar1;
        }
        if (s5 != '\0') {
          if (s40 <= uVar2) {
            return -0x3fffff86;
          }
          iVar1 = FUN_66209da0(this,param_1,s34,(int *)&s30);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_66208e70(this,(uVar2 * 2) + s30,s2c + (CARRY4(uVar2 * 2,s30)),(int)&sc,2,0);
          if (iVar1 < 0) {
            return iVar1;
          }
          break;
        }
      }
      uVar2 = uVar2 + 1;
      uVar1 = uVar1 + 4;
      if (s40 <= uVar2) {
        return -0x3fffff86;
      }
    } while( true );
  }
  if (s44 <= (sc & 0xffff)) {
    return -0x3fffff86;
  }
  iVar1 = FUN_66209da0(this,param_1,s3c,(int *)&s30);
  if (iVar1 < 0) {
    return iVar1;
  }
  uVar2 = (sc & 0xffff) * 4;
  iVar1 = FUN_66208e70(this,uVar2 + s30,s2c + (CARRY4(uVar2,s30)),(int)&s14,4,0);
  if (iVar1 < 0) {
    return iVar1;
  }
  iVar1 = FUN_66209da0(this,param_1,s14,(int *)&s30);
  if (iVar1 < 0) {
    return iVar1;
  }
  if ((s20._4_4_ <= s2c) && ((s20._4_4_ < s2c || ((uint)s20 <= s30)))) {
    s20._4_4_ = s20._4_4_ + (CARRY4(s18,(uint)s20));
    if ((s2c <= s20._4_4_) && ((s2c < s20._4_4_ || (s30 < (s18 + (uint)s20))))) {
      cVar1 = '\x01';
      goto LAB_662089be;
    }
  }
  cVar1 = '\0';
LAB_662089be:
  if (param_4 == (char *)0x0) {
    if (cVar1 != '\0') {
      return -0x3ffffff3;
    }
  }
  else {
    *param_4 = cVar1;
  }
  *param_3 = s30;
  param_3[1] = s2c;
  return 0;
}



void __thiscall
FUN_662089f0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,char *param_4,
            uint *param_5,char *param_6)

{
  int iVar1;
  undefined s124 [288];
  
  iVar1 = FUN_66208a40(param_1,param_2,param_3,s124,0xffffffff,0xffffffff);
  if (-1 < iVar1) {
    FUN_662087e0(this,(int)s124,param_4,param_5,param_6);
  }
  return;
}


/*
Unable to decompile 'FUN_66208a40'
Cause: Exception while decompiling 66208a40: Decompiler process died

*/


undefined4 FUN_66208ab0(void)

{
  DWORD DVar1;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621ba88;
  *in_FS_OFFSET = &s10;
  if (DAT_66225008 == '\0') {
    *in_FS_OFFSET = s10;
    return 0;
  }
  AcquireCriticalSectionWithLock((int)&DAT_6624b4bc);
  s8 = 0;
  DVar1 = GetCurrentThreadId();
  puVar1 = (undefined4 *)DAT_6624b4d8[1];
  s14 = DAT_6624b4d8;
  if (*(char *)((int)puVar1 + 0xd) == '\0') {
    do {
      if ((uint)puVar1[4] < DVar1) {
        puVar2 = (undefined4 *)puVar1[2];
      }
      else {
        puVar2 = (undefined4 *)*puVar1;
        s14 = puVar1;
      }
      puVar1 = puVar2;
    } while (*(char *)((int)puVar2 + 0xd) == '\0');
    if ((s14 != DAT_6624b4d8) && ((uint)s14[4] <= DVar1)) goto LAB_66208b43;
  }
  s14 = DAT_6624b4d8;
LAB_66208b43:
  if (s14 == DAT_6624b4d8) {
    uVar1 = 0;
  }
  else {
    uVar1 = s14[5];
  }
  s8 = 0xffffffff;
  ReleaseCriticalSection(&DAT_6624b4bc);
  *in_FS_OFFSET = s10;
  return uVar1;
}



longlong __fastcall FUN_66208b80(int param_1)

{
  if ((1 < *(ushort *)(param_1 + 0x14)) && (*(short *)(param_1 + 0x18) == 0x10b)) {
    return (longlong)*(int *)(param_1 + 0x34);
  }
  return *(longlong *)(param_1 + 0x30);
}


/*
Unable to decompile 'FUN_66208ba0'
Cause: Exception while decompiling 66208ba0: Decompiler process died

*/


uint __fastcall FUN_66208c20(int param_1)

{
  uint in_EAX;
  
  if ((1 < *(ushort *)(param_1 + 0x14)) && (in_EAX = 0x10b, *(short *)(param_1 + 0x18) == 0x10b)) {
    return 0x101;
  }
  return in_EAX & 0xffffff00;
}



int __thiscall FUN_66208c40(void *this,uint param_1)

{
  ushort *puVar1;
  uint uVar1;
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  bool bVar1;
  undefined s44 [8];
  uint s3c;
  uint s38;
  undefined4 s20;
  uint s1c;
  undefined4 s18;
  uint s14;
  undefined4 s10;
  undefined sc [4];
  void *s8;
  
  uVar1 = param_1;
  if (*(char *)(param_1 + 0x118) == '\0') {
    return -0x3ffffff3;
  }
  s1c = *(uint *)(param_1 + 0x110);
  s18 = *(undefined4 *)(param_1 + 0x114);
  s14 = *(uint *)(param_1 + 0x54);
  s10 = 0;
  s8 = this;
  iVar1 = FUN_6620be50(&DAT_6624b500,*(undefined4 *)((int)this + 0x48),&s1c,&s14,2,sc);
  if (-1 < iVar1) {
    puVar1 = (ushort *)(param_1 + 0x14);
    param_1 = 0;
    uVar3 = (uint)*puVar1 + *(uint *)(uVar1 + 0x108);
    uVar4 = uVar3 + 0x18;
    uVar3 = *(int *)(uVar1 + 0x10c) + (uint)CARRY4((uint)*puVar1,*(uint *)(uVar1 + 0x108)) +
            (uint)(0xffffffe7 < uVar3);
    if (*(short *)(uVar1 + 6) != 0) {
      do {
        iVar1 = FUN_66208e70(s8,uVar4,uVar3,(int)s44,0x28,0);
        if (iVar1 < 0) {
          return iVar1;
        }
        iVar1 = FUN_66209da0(s8,uVar1,s38,(int *)&s1c);
        if (iVar1 < 0) {
          return iVar1;
        }
        uVar2 = FUN_66208ba0(s20);
        s14 = s3c;
        s10 = 0;
        iVar1 = FUN_6620be50(&DAT_6624b500,*(undefined4 *)((int)s8 + 0x48),&s1c,&s14,uVar2,sc);
        if (iVar1 < 0) {
          return iVar1;
        }
        param_1 = param_1 + 1;
        bVar1 = 0xffffffd7 < uVar4;
        uVar4 = uVar4 + 0x28;
        uVar3 = uVar3 + (bVar1);
      } while (param_1 < (*(ushort *)(uVar1 + 6)));
    }
    iVar1 = 0;
  }
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_66208d70(undefined4 param_1,uint param_2,uint param_3,undefined4 *param_4)

{
  bool bVar1;
  int iVar1;
  uint uVar1;
  undefined4 uStack52;
  undefined4 s30;
  undefined4 s2c;
  undefined4 s28;
  undefined4 s24;
  undefined4 s20;
  undefined4 s1c;
  
  bVar1 = FUN_6620b4b0();
  if (bVar1 == false) {
    uVar1 = param_3 + ((0xfffffffe < param_2));
    if (((param_3 <= uVar1) && (((param_3 < uVar1 || (param_2 <= (param_2 + 1))) && (uVar1 < 2))))
       && ((uVar1 == 0 || (param_2 == 0xffffffff)))) {
      iVar1 = NtQueryVirtualMemory(param_1,param_2,0,&uStack52,0x1c,0);
      if (iVar1 < 0) {
        return iVar1;
      }
      *param_4 = uStack52;
      param_4[2] = s30;
      param_4[4] = s2c;
      param_4[6] = s28;
      param_4[8] = s24;
      param_4[9] = s20;
      param_4[10] = s1c;
      param_4[1] = 0;
      param_4[3] = 0;
      param_4[7] = 0;
      return 0;
    }
    iVar1 = FUN_6620bef0((int *)&DAT_6624b500,(char)param_2,param_1,param_2,param_3,0,param_4,0,0x30
                         ,0,0);
    if (iVar1 < 0) {
      return iVar1;
    }
  }
  else {
    iVar1 = (*_DAT_66222868)(param_1,param_2,param_3,0,param_4,0x30,0,0);
    if (iVar1 < 0) {
      return iVar1;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __thiscall
FUN_66208e70(void *this,uint param_1,uint param_2,int param_3,uint param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar1;
  void *this_00;
  uint uVar3;
  bool bVar1;
  
  uVar2 = param_5;
  uVar1 = param_4;
  if ((param_4 | param_5) == 0) {
    return 0;
  }
  uVar3 = param_2 + param_5 + (uint)CARRY4(param_1,param_4);
  if ((uVar3 < param_2) ||
     ((((uVar3 <= param_2 && ((param_1 + param_4) < param_1)) || (1 < uVar3)) ||
      ((uVar3 != 0 && (param_1 + param_4 != 0)))))) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (*(char *)((int)this + 0x58) == '\0') {
    if (!bVar1) {
      this_00 = (void *)FUN_66208ab0();
      if ((this_00 == (void *)0x0) || (*(char *)((int)this_00 + 0x20) == '\0')) {
        iVar1 = NtReadVirtualMemory(*(undefined4 *)((int)this + 0x48),param_1,param_3,uVar1,&param_5
                                   );
      }
      else {
        iVar1 = FUN_66208f70(this_00,*(undefined4 *)((int)this + 0x48),param_1,param_2,param_3,uVar1
                             ,uVar2,(int *)&param_5);
      }
      if (iVar1 < 0) {
        return iVar1;
      }
      if (param_5 != uVar1) {
        return -0x3ffffffc;
      }
      bVar1 = uVar2 == 0;
      goto LAB_66208f4f;
    }
  }
  else if (!bVar1) {
    FUN_6620dc00(param_3,param_1,param_4);
    return 0;
  }
  iVar1 = (*_DAT_6622286c)(*(undefined4 *)((int)this + 0x48),param_1,param_2,param_3,param_4,param_5
                           ,&param_4);
  if (iVar1 < 0) {
    return iVar1;
  }
  if (param_4 != uVar1) {
    return -0x3ffffffc;
  }
  bVar1 = param_5 == uVar2;
LAB_66208f4f:
  if (!bVar1) {
    return -0x3ffffffc;
  }
  return 0;
}



undefined4 __thiscall
FUN_66208f70(void *this,undefined4 param_1,uint param_2,uint param_3,int param_4,uint param_5,
            int param_6,int *param_7)

{
  int iVar1;
  int *piVar1;
  uint uVar1;
  uint uVar2;
  int *s1c;
  uint s18;
  int s14;
  uint s10;
  uint sc;
  int *s8;
  
  uVar1 = param_3;
  param_3 = 0;
  s1c = (int *)((param_2 >> 0xc) | (uVar1 << 0x14));
  uVar1 = uVar1 >> 0xc;
  sc = param_2 + ((param_2 >> 0xc) * -0x1000);
  uVar2 = sc + param_5;
  s10 = param_5;
  iVar1 = param_6 + (uint)CARRY4(sc,param_5);
  while ((s18 = uVar1, s8 = s1c, iVar1 != 0 || (0x1000 < uVar2))) {
    uVar2 = 0x1000 - sc;
    FUN_6620acb0((void *)((int)this + 0x14),&s14,(uint *)&s1c);
    if (s14 == *(int *)((int)this + 0x14)) {
      if (*(int *)((int)this + 0x18) == *(int *)((int)this + 0x1c)) {
        FUN_66209f00(this,*(int *)((int)this + 4));
      }
      *(int *)((int)this + 0x28) = *(int *)((int)this + 0x28) + 1;
      piVar1 = FUN_66209e30(this,param_1,s8,uVar1);
    }
    else {
      *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + 1;
      piVar1 = *(int **)(s14 + 0x18);
    }
    if (piVar1 == (int *)0x0) goto LAB_662090f4;
    FUN_6620d5b0(param_4 + param_3,(int)piVar1 + sc,uVar2);
    param_3 = param_3 + uVar2;
    param_6 = param_6 - (uint)(s10 < uVar2);
    s1c = (int *)((int)s8 + 1);
    uVar1 = uVar1 + (((int *)0xfffffffe < s8));
    sc = 0;
    uVar2 = s10 - uVar2;
    s10 = uVar2;
    iVar1 = param_6;
  }
  FUN_6620acb0((void *)((int)this + 0x14),&param_6,(uint *)&s1c);
  if (param_6 == *(int *)((int)this + 0x14)) {
    if (*(int *)((int)this + 0x18) == *(int *)((int)this + 0x1c)) {
      FUN_66209f00(this,*(int *)((int)this + 4));
    }
    *(int *)((int)this + 0x28) = *(int *)((int)this + 0x28) + 1;
    piVar1 = FUN_66209e30(this,param_1,s8,uVar1);
  }
  else {
    *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + 1;
    piVar1 = *(int **)(param_6 + 0x18);
  }
  uVar1 = s10;
  if (piVar1 != (int *)0x0) {
    FUN_6620d5b0(param_4 + param_3,(int)piVar1 + sc,s10);
    *param_7 = uVar1 + param_3;
    return 0;
  }
LAB_662090f4:
  *param_7 = param_3;
  return 0;
}



int __thiscall FUN_66209110(void *this,uint param_1,uint param_2,void *param_3,uint *param_4)

{
  int iVar1;
  undefined4 uVar1;
  uint uVar2;
  undefined4 *in_FS_OFFSET;
  void *s24 [4];
  char s11;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621baa8;
  *in_FS_OFFSET = &s10;
  uVar2 = 0;
  iVar1 = FUN_66208e70(this,param_1,param_2,(int)&s11,1,0);
  if (-1 < iVar1) {
    while (s11 != '\0') {
      uVar2 = uVar2 + 1;
      iVar1 = FUN_66208e70(this,uVar2 + param_1,param_2 + (CARRY4(uVar2,param_1)),(int)&s11,1,0);
      if (iVar1 < 0) {
        *in_FS_OFFSET = s10;
        return iVar1;
      }
    }
    if (param_4 != (uint *)0x0) {
      *param_4 = uVar2;
    }
    if (param_3 != (void *)0x0) {
      uVar1 = Wsafe_malloc(uVar2 + 1);
      InitializeObjectWithDefaults(s24,uVar1);
      s8 = 0;
      iVar1 = FUN_66208e70(this,param_1,param_2,(int)s24[0],uVar2 + 1,0);
      if (iVar1 < 0) {
        s8 = 0xffffffff;
        FUN_66207460(s24);
        *in_FS_OFFSET = s10;
        return iVar1;
      }
      FUN_66207510(param_3,s24);
      s8 = 0xffffffff;
      FUN_66207460(s24);
    }
    iVar1 = 0;
  }
  *in_FS_OFFSET = s10;
  return iVar1;
}



void __thiscall FUN_66209220(void *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  if (*this != param_1) {
    if (*(int *)((int)this + 4) == param_1) {
      iVar1 = *(int *)(*(int *)((int)this + 4) + 0x1004);
      *(int *)((int)this + 4) = iVar1;
      *(undefined4 *)(iVar1 + 0x1000) = 0;
      return;
    }
    *(undefined4 *)(*(int *)(param_1 + 0x1004) + 0x1000) = *(undefined4 *)(param_1 + 0x1000);
    *(undefined4 *)(*(int *)(param_1 + 0x1000) + 0x1004) = *(undefined4 *)(param_1 + 0x1004);
    return;
  }
  iVar1 = *(int *)(*this + 0x1000);
  *(int *)this = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x1004) = 0;
    return;
  }
  *(undefined4 *)((int)this + 4) = 0;
  return;
}



// WARNING: Could not reconcile some variable overlaps

int FUN_662092a0(int param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  int *piVar1;
  int *piVar2;
  int iVar1;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  void *pvVar1;
  uint uVar6;
  uint uVar7;
  int *piVar3;
  uint uVar8;
  uint uVar9;
  int *piVar4;
  uint uVar10;
  undefined4 *in_FS_OFFSET;
  bool bVar1;
  bool bVar2;
  undefined8 s70;
  uint s68;
  uint s64;
  int s60;
  uint s5c;
  uint s58;
  uint s54;
  uint s50;
  undefined s49;
  uint s48;
  int s44;
  int s40;
  int s3c;
  uint s38;
  uint s34;
  uint s30;
  uint s2c;
  int *s28;
  char s22;
  char s21;
  void *s20;
  undefined *s1c;
  undefined4 s14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &DAT_662236f8;
  puStack16 = &LAB_6620ebb8;
  s14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s14;
  s1c = &stack0xffffff48;
  if (*(char *)(param_1 + 0x118) == '\0') {
    *in_FS_OFFSET = s14;
    return -0x3ffffff3;
  }
  if ((*(ushort *)(param_1 + 0x14) < 2) || (s22 = '\x01', *(short *)(param_1 + 0x18) != 0x10b)) {
    s22 = '\0';
  }
  if ((*(ushort *)(param_1 + 0x14) < 2) || (*(short *)(param_1 + 0x18) != 0x10b)) {
    bVar2 = false;
  }
  else {
    bVar2 = true;
  }
  s21 = '\0';
  s8 = 0;
  s70 = FUN_66208b80(param_1);
  pvVar1 = s20;
  s5c = *(uint *)(param_1 + 0x110) - (uint)s70;
  s58 = (*(int *)(param_1 + 0x114) - (int)((ulonglong)s70 >> 0x20)) -
        (uint)(*(uint *)(param_1 + 0x110) < (uint)s70);
  if ((s5c | s58) != 0) {
    s70 = s70 + ((longlong)(int)s58 << 0x20) + s5c;
    s54 = s58;
    s2c = s5c;
    if ((char)param_2 != '\0') {
      uVar8 = *(uint *)(param_1 + 0x108);
      if (s22 == '\0') {
        bVar1 = 0xffffffcf < uVar8;
        piVar2 = (int *)(uVar8 + 0x30);
      }
      else {
        bVar1 = 0xffffffcb < uVar8;
        piVar2 = (int *)(uVar8 + 0x34);
      }
      iVar1 = FUN_6620a370(s20,piVar2,(int *)(*(int *)(param_1 + 0x10c) + (uint)bVar1),(int)&s70,
                           ((uint)!bVar2 * 4) + 4,0,'\0');
      if (iVar1 < 0) goto LAB_6620967b;
    }
    if ((*(ushort *)(param_1 + 0x16) & 1) != 0) {
      *in_FS_OFFSET = s14;
      return -0x3ffffd97;
    }
    iVar1 = FUN_66209920(param_1,5,&param_2,&s34);
    uVar8 = s34;
    if (iVar1 != -0x3fffff86) {
      if (-1 < iVar1) {
        if (param_2 == 0) goto LAB_6620936c;
        uVar3 = param_2 + s34;
        s38 = s30;
        uVar6 = s30 + (CARRY4(param_2,s34));
        uVar4 = FUN_66205e50(param_1);
        uVar7 = s2c >> 0x10;
        uVar5 = s2c & 0xffff;
        uVar10 = s30;
        while( true ) {
          if ((uVar6 < uVar10) || ((uVar6 <= uVar10 && (uVar3 <= uVar8)))) {
            iVar1 = 0;
            if (s21 != '\0') {
              iVar1 = -0x3ffffff3;
            }
            *in_FS_OFFSET = s14;
            return iVar1;
          }
          iVar1 = FUN_66208e70(pvVar1,uVar8,uVar10,(int)&s5c,8,0);
          if (iVar1 < 0) break;
          if (((s58 < 8) || ((s58 & 1) != 0)) || (uVar4 <= (s5c + 0x1000))) {
            *in_FS_OFFSET = s14;
            return -0x3fffff85;
          }
          piVar3 = (int *)(s5c + *(uint *)(param_1 + 0x110));
          piVar2 = (int *)(*(int *)(param_1 + 0x114) + (uint)CARRY4(s5c,*(uint *)(param_1 + 0x110)))
          ;
          iVar1 = FUN_66209f90(pvVar1,piVar3,piVar2,0x1000,0,'\x01');
          if (iVar1 < 0) break;
          s68 = uVar8 + 8;
          s50 = s38 + ((0xfffffff7 < uVar8));
          uVar1 = s58 - 8;
          bVar2 = CARRY4(uVar8,s58);
          uVar8 = uVar8 + s58;
          s38 = s38 + (bVar2);
          for (uVar9 = 0; uVar10 = s38, uVar9 < (uVar1 >> 1); uVar9 = uVar9 + 1) {
            iVar1 = FUN_66208e70(pvVar1,s68,s50,(int)&param_2,2,0);
            if (iVar1 < 0) goto LAB_6620967b;
            uVar10 = (param_2 >> 0xc) & 0xf;
            piVar4 = (int *)((param_2 & 0xfff) + (int)piVar3);
            s28 = (int *)((int)piVar2 + (uint)CARRY4(param_2 & 0xfff,(uint)piVar3));
            switch(uVar10) {
            case 0:
              break;
            case 1:
            case 2:
              iVar1 = FUN_66208e70(s20,(uint)piVar4,(uint)s28,(int)&s64,2,0);
              piVar1 = s28;
              if (iVar1 < 0) goto LAB_6620967b;
              uVar2 = uVar5;
              if (uVar10 == 1) {
                uVar2 = uVar7;
              }
              s64 = (uVar2 + s64) & 0xffff;
              s3c = 0;
              s48 = s64;
              if (*(char *)((int)s20 + 0x5a) != '\0') {
                iVar1 = FUN_66209f90(s20,piVar4,s28,2,0,'\0');
                s3c = iVar1;
                if (iVar1 < 0) goto LAB_6620967b;
              }
              if (*(char *)((int)s20 + 0x58) == '\0') {
                pvVar1 = (void *)FUN_66208ab0();
                if ((pvVar1 != (void *)0x0) && (*(char *)((int)pvVar1 + 0x20) != '\0')) {
                  FUN_6620a420(pvVar1,*(undefined4 *)((int)s20 + 0x48),(uint)piVar4,(uint)piVar1,
                               (int)&s48,2,0);
                }
                iVar1 = FUN_6620bf70(&DAT_6624b500,*(undefined4 *)((int)s20 + 0x48),(uint)piVar4,
                                     (uint)piVar1,&s48,2,0);
                s3c = iVar1;
                if (iVar1 < 0) goto LAB_6620967b;
              }
              else {
                FUN_6620dc00(piVar4,&s48,2);
                s3c = 0;
              }
              break;
            case 3:
              iVar1 = FUN_66208e70(s20,(uint)piVar4,(uint)s28,(int)&s60,4,0);
              piVar1 = s28;
              if (iVar1 < 0) goto LAB_6620967b;
              s60 = s60 + s2c;
              s44 = 0;
              s40 = s60;
              if (*(char *)((int)s20 + 0x5a) != '\0') {
                iVar1 = FUN_66209f90(s20,piVar4,s28,4,0,'\0');
                s44 = iVar1;
                if (iVar1 < 0) goto LAB_6620967b;
              }
              if (*(char *)((int)s20 + 0x58) == '\0') {
                pvVar1 = (void *)FUN_66208ab0();
                if ((pvVar1 != (void *)0x0) && (*(char *)((int)pvVar1 + 0x20) != '\0')) {
                  FUN_6620a420(pvVar1,*(undefined4 *)((int)s20 + 0x48),(uint)piVar4,(uint)piVar1,
                               (int)&s40,4,0);
                }
                s44 = FUN_6620bf70(&DAT_6624b500,*(undefined4 *)((int)s20 + 0x48),(uint)piVar4,
                                   (uint)piVar1,&s40,4,0);
                if (s44 < 0) {
                  *in_FS_OFFSET = s14;
                  return s44;
                }
              }
              else {
                FUN_6620dc00(piVar4,&s40,4);
                s44 = 0;
              }
              break;
            default:
              s21 = '\x01';
              s49 = 1;
              break;
            case 10:
              iVar1 = FUN_66208e70(s20,(uint)piVar4,(uint)s28,(int)&s34,8,0);
              if (iVar1 < 0) goto LAB_6620967b;
              bVar2 = CARRY4(s34,s2c);
              s34 = s34 + s2c;
              s30 = s30 + s54 + (uint)bVar2;
              iVar1 = FUN_6620a370(s20,piVar4,s28,(int)&s34,8,0,'\0');
              if (iVar1 < 0) {
                *in_FS_OFFSET = s14;
                return iVar1;
              }
            }
            bVar2 = 0xfffffffd < s68;
            s68 = s68 + 2;
            s50 = s50 + (bVar2);
            pvVar1 = s20;
          }
        }
      }
LAB_6620967b:
      *in_FS_OFFSET = s14;
      return iVar1;
    }
  }
LAB_6620936c:
  *in_FS_OFFSET = s14;
  return 0;
}



int __fastcall FUN_66209870(int **param_1)

{
  int **ppiVar1;
  int **_Memory;
  int **ppiVar2;
  int *piVar1;
  int iVar1;
  int *sc;
  int s8;
  
  s8 = 0;
  iVar1 = 0;
  if ((int **)*param_1 != param_1) {
    ppiVar1 = param_1 + 2;
    do {
      _Memory = (int **)*param_1;
      ppiVar2 = (int **)_Memory[1];
      piVar1 = *_Memory;
      *ppiVar2 = piVar1;
      piVar1[1] = (int)ppiVar2;
      if (param_1[0x10] == (int *)0x1) {
        iVar1 = 0;
      }
      else {
        sc = _Memory[6];
        if (param_1[0x10] == (int *)0x2) {
          sc = (int *)0x20;
        }
        iVar1 = FUN_6620be50(&DAT_6624b500,param_1[10],(uint *)(_Memory + 2),(uint *)(_Memory + 4),
                             sc,&sc);
      }
      if (-1 < s8) {
        s8 = iVar1;
      }
      if (_Memory == ppiVar1) {
        param_1[3] = (int *)ppiVar1;
        *ppiVar1 = (int *)ppiVar1;
      }
      else {
        FID_conflict__free(_Memory);
      }
      iVar1 = s8;
    } while ((int **)*param_1 != param_1);
  }
  param_1[0xc] = (int *)0x0;
  param_1[0xd] = (int *)0x0;
  param_1[0xe] = (int *)0x0;
  param_1[0xf] = (int *)0x0;
  return iVar1;
}


/*
Unable to decompile 'FUN_66209920'
Cause: Exception while decompiling 66209920: Decompiler process died

*/


int __thiscall
FUN_662099b0(void *this,uint param_1,uint param_2,undefined param_3,uint *param_4,int param_5,
            uint param_6,uint param_7)

{
  uint uVar1;
  void *this_00;
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *in_FS_OFFSET;
  int s28;
  uint s24;
  void *s20;
  undefined *s1c;
  undefined4 s14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 s8;
  
  uVar3 = param_6;
  uVar2 = param_2;
  puStack12 = &DAT_662236e8;
  puStack16 = &LAB_6620ebb8;
  s14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s14;
  s1c = &stack0xffffffcc;
  if (((param_1 | param_2) == 0) ||
     (((param_1 == 0xffffffff && (param_2 == 0)) || ((param_1 & param_2) == 0xffffffff)))) {
    *in_FS_OFFSET = s14;
    return -0x3ffffff3;
  }
  if ((param_7 == 0) && (param_6 < 0x40)) {
    *in_FS_OFFSET = s14;
    return -0x3fffff85;
  }
  s8 = 0;
  s20 = this;
  iVar1 = FUN_66208e70(this,param_1,param_2,(int)&param_2,2,0);
  if (-1 < iVar1) {
    if ((short)param_2 != 0x5a4d) {
LAB_66209bbf:
      *in_FS_OFFSET = s14;
      return -0x3fffff85;
    }
    iVar1 = FUN_66208e70(s20,param_1 + 0x3c,uVar2 + ((0xffffffc3 < param_1)),(int)&s24,4,0);
    uVar1 = param_7;
    if (-1 < iVar1) {
      if (((param_7 == 0) && (uVar3 <= s24)) ||
         (((s24 + 0x18) < s24 ||
          (((param_7 = 0, uVar1 == 0 && (uVar3 <= (s24 + 0x18))) || (0xfffffff < s24))))))
      goto LAB_66209bbf;
      iVar1 = FUN_66208e70(s20,s24 + param_1,uVar2 + (CARRY4(s24,param_1)),(int)&s28,4,0);
      this_00 = s20;
      if (-1 < iVar1) {
        if (s28 != 0x4550) goto LAB_66209bbf;
        uVar3 = s24 + param_1;
        param_7 = uVar2 + (CARRY4(s24,param_1));
        if (param_4 != (uint *)0x0) {
          *param_4 = uVar3;
          param_4[1] = param_7;
        }
        if (param_5 == 0) {
LAB_66209b9a:
          *in_FS_OFFSET = s14;
          return 0;
        }
        *(uint *)(param_5 + 0x108) = uVar3;
        *(uint *)(param_5 + 0x10c) = param_7;
        *(uint *)(param_5 + 0x110) = param_1;
        *(uint *)(param_5 + 0x114) = uVar2;
        *(undefined *)(param_5 + 0x118) = param_3;
        iVar1 = FUN_66208e70(s20,uVar3,param_7,param_5,0x18,0);
        if (-1 < iVar1) {
          uVar2 = (uint)*(ushort *)(param_5 + 0x14);
          if (0xf0 < *(ushort *)(param_5 + 0x14)) {
            uVar2 = 0xf0;
          }
          iVar1 = FUN_66208e70(this_00,uVar3 + 0x18,param_7 + ((0xffffffe7 < uVar3)),param_5 + 0x18,
                               uVar2,0);
          if (-1 < iVar1) goto LAB_66209b9a;
        }
      }
    }
  }
  *in_FS_OFFSET = s14;
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __thiscall FUN_66209c00(void *this,int param_1,uint param_2,uint *param_3,undefined4 *param_4)

{
  int iVar1;
  void *this_00;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  bool bVar1;
  undefined4 s44;
  undefined4 uStack64;
  undefined4 uStack60;
  uint uStack56;
  int s34;
  undefined4 uStack48;
  undefined4 uStack44;
  undefined4 uStack40;
  undefined8 s24;
  int s1c;
  int s18;
  uint s14;
  uint s10;
  int sc;
  void *s8;
  
  s10 = 0;
  uVar2 = (uint)*(ushort *)(param_1 + 0x14) + *(uint *)(param_1 + 0x108);
  uVar1 = *(int *)(param_1 + 0x10c) +
          (uint)CARRY4((uint)*(ushort *)(param_1 + 0x14),*(uint *)(param_1 + 0x108)) +
          (uint)(0xffffffe7 < uVar2);
  uVar2 = uVar2 + 0x18;
  s8 = this;
  if (*(short *)(param_1 + 6) != 0) {
    do {
      uVar3 = uVar2 + 0x28;
      s14 = uVar1 + ((0xffffffd7 < uVar2));
      if ((s14 < uVar1) ||
         ((((s14 <= uVar1 && (uVar3 < uVar2)) || (1 < s14)) || ((s14 != 0 && (uVar3 != 0)))))) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
      if (*(char *)((int)s8 + 0x58) == '\0') {
        if (bVar1) goto LAB_66209c8a;
        this_00 = (void *)FUN_66208ab0();
        if ((this_00 == (void *)0x0) || (*(char *)((int)this_00 + 0x20) == '\0')) {
          iVar1 = NtReadVirtualMemory(*(undefined4 *)((int)s8 + 0x48),uVar2,&s44,0x28,&sc);
        }
        else {
          iVar1 = FUN_66208f70(this_00,*(undefined4 *)((int)s8 + 0x48),uVar2,uVar1,(int)&s44,0x28,0,
                               &sc);
        }
        if (iVar1 < 0) {
          return iVar1;
        }
        bVar1 = sc == 0x28;
LAB_66209d08:
        if (!bVar1) {
          return -0x3ffffffc;
        }
      }
      else {
        if (bVar1) {
LAB_66209c8a:
          iVar1 = (*_DAT_6622286c)(*(undefined4 *)((int)s8 + 0x48),uVar2,uVar1,&s44,0x28,0,&s1c);
          if (iVar1 < 0) {
            return iVar1;
          }
          if (s1c != 0x28) {
            return -0x3ffffffc;
          }
          bVar1 = s18 == 0;
          goto LAB_66209d08;
        }
        FUN_6620dc00(&s44,uVar2,0x28);
      }
      if ((uStack56 <= param_2) && (param_2 < (s34 + uStack56))) {
        if (param_3 != (uint *)0x0) {
          *param_3 = uVar2;
          param_3[1] = uVar1;
        }
        if (param_4 != (undefined4 *)0x0) {
          *param_4 = s44;
          param_4[1] = uStack64;
          param_4[2] = uStack60;
          param_4[3] = uStack56;
          param_4[4] = s34;
          param_4[5] = uStack48;
          param_4[6] = uStack44;
          param_4[7] = uStack40;
          *(undefined8 *)(param_4 + 8) = s24;
        }
        return 0;
      }
      s10 = s10 + 1;
      uVar1 = s14;
      uVar2 = uVar3;
    } while (s10 < (*(ushort *)(param_1 + 6)));
  }
  return -0x3fffff86;
}



int __thiscall FUN_66209da0(void *this,int param_1,uint param_2,int *param_3)

{
  uint uVar1;
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 s2c [3];
  uint s20;
  uint s18;
  
  if ((*(char *)(param_1 + 0x118) == '\0') && (*(uint *)(param_1 + 0x54) <= param_2)) {
    iVar1 = FUN_66209c00(this,param_1,param_2,(uint *)0x0,s2c);
    if (-1 < iVar1) {
      uVar1 = *(uint *)(param_1 + 0x110);
      uVar2 = uVar1 - s20;
      iVar1 = *(int *)(param_1 + 0x114);
      uVar3 = uVar2 + s18;
      *param_3 = uVar3 + param_2;
      param_3[1] = (iVar1 - (uint)(uVar1 < s20)) + (uint)CARRY4(uVar2,s18) +
                   (uint)CARRY4(uVar3,param_2);
      return 0;
    }
  }
  else {
    uVar1 = *(uint *)(param_1 + 0x110);
    iVar1 = *(int *)(param_1 + 0x114);
    *param_3 = param_2 + *(uint *)(param_1 + 0x110);
    param_3[1] = iVar1 + (uint)CARRY4(param_2,uVar1);
    iVar1 = 0;
  }
  return iVar1;
}



int * __thiscall FUN_66209e30(void *this,undefined4 param_1,int *param_2,uint param_3)

{
  int *piVar1;
  int *_Memory;
  int iVar1;
  int **ppiVar1;
  int *sc;
  uint s8;
  
  sc = param_2;
  piVar1 = *(int **)(**(int **)((int)this + 0xc) + 8);
  s8 = param_3;
  param_3 = (param_3 << 0xc) | ((uint)param_2 >> 0x14);
  iVar1 = NtReadVirtualMemory(param_1,(int)param_2 << 0xc,piVar1,0x1000,&param_3);
  if ((-1 < iVar1) && (param_3 == 0x1000)) {
    ppiVar1 = FUN_66207ea0((void *)((int)this + 0x14),&sc);
    *ppiVar1 = piVar1;
    piVar1[0x402] = (int)sc;
    piVar1[0x403] = s8;
    _Memory = **(int ***)((int)this + 0xc);
    *(int *)_Memory[1] = *_Memory;
    *(int *)(*_Memory + 4) = _Memory[1];
    *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + -1;
    FID_conflict__free(_Memory);
    piVar1[0x401] = 0;
                    // WARNING: Load size is inaccurate
    piVar1[0x400] = *this;
                    // WARNING: Load size is inaccurate
    if (*this != 0) {
      *(int **)(*this + 0x1004) = piVar1;
      *(int **)this = piVar1;
      return piVar1;
    }
    *(int **)((int)this + 4) = piVar1;
    *(int **)this = piVar1;
    return piVar1;
  }
  return (int *)0x0;
}



void __thiscall FUN_66209f00(void *this,int param_1)

{
  undefined4 *puVar1;
  code *pcVar1;
  int iVar1;
  undefined4 *puVar2;
  int **sc;
  int **s8;
  
  iVar1 = param_1;
  FUN_6620a7b0((void *)((int)this + 0x14),(int *)&sc,(uint *)(param_1 + 0x1008));
  FUN_6620a9a0((void *)((int)this + 0x14),(int **)&s8,sc,s8);
  FUN_66209220(this,iVar1);
  puVar1 = (undefined4 *)**(undefined4 **)((int)this + 0xc);
  puVar2 = FUN_662075c0(puVar1,(undefined4 *)puVar1[1],&param_1);
  if (*(int *)((int)this + 0x10) != 0x15555554) {
    *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + 1;
    puVar1[1] = puVar2;
    *(undefined4 **)puVar2[1] = puVar2;
    return;
  }
  FUN_6620c903(s_list_T__too_long_6621cef0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Type propagation algorithm not settling
// WARNING: Could not reconcile some variable overlaps

int __thiscall
FUN_66209f90(void *this,int *param_1,int *param_2,uint param_3,uint param_4,char param_5)

{
  int **ppiVar1;
  int *piVar1;
  undefined (*pauVar1) [16];
  int *piVar2;
  int iVar1;
  int *piVar3;
  uint uVar1;
  undefined (*pauVar2) [16];
  undefined4 uVar2;
  int *piStack148;
  int *s90;
  uint uStack132;
  uint uStack124;
  uint s78;
  uint uStack112;
  uint auStack100 [4];
  undefined8 s54;
  undefined8 uStack60;
  undefined (*pauStack52) [16];
  int *s30;
  int *s2c;
  uint s28;
  uint s24;
  int *s20;
  int *s1c;
  void *s18;
  
  if ((param_3 | param_4) == 0) {
LAB_6620a306:
    iVar1 = 0;
  }
  else {
    piVar3 = *(int **)((int)this + 0x30);
    piVar1 = *(int **)((int)this + 0x34);
    if (((uint)piVar3 | (uint)piVar1) != 0) {
      piVar2 = (int *)((int)piVar1 +
                      (uint)CARRY4(*(uint *)((int)this + 0x38),(uint)piVar3) +
                      *(int *)((int)this + 0x3c));
      if ((piVar1 <= param_2) &&
         ((((piVar1 < param_2 || (piVar3 <= param_1)) && (param_2 <= piVar2)) &&
          ((param_2 < piVar2 || (param_1 < (int *)(*(uint *)((int)this + 0x38) + (int)piVar3)))))))
      {
        piVar2 = (int *)((int)param_2 + (CARRY4((uint)param_1,param_3)) + param_4);
        if ((piVar1 < piVar2) || ((piVar1 <= piVar2 && (piVar3 <= (int *)((int)param_1 + param_3))))
           ) goto LAB_6620a306;
      }
    }
    s18 = this;
    iVar1 = FUN_66209870((int **)this);
    if (-1 < iVar1) {
      s2c = (int *)((int)param_1 + param_3);
      s54 = 0;
      s30 = (int *)((int)param_2 + (CARRY4((uint)param_1,param_3)) + param_4);
      uStack60 = 0;
      uStack60._4_4_ = (int *)0x0;
      uStack60._0_4_ = (int *)0x0;
      s20 = (int *)0x0;
      s1c = (int *)0x0;
LAB_6620a050:
      do {
        if (((uint)s1c | (uint)s20) == 0) {
          s24 = param_3;
          uStack60 = (uStack60 & 0xffffffff) | (ZEXT48(param_2) << 0x20);
          s28 = param_4;
          piVar3 = param_2;
          pauStack52 = (undefined (*) [16])param_1;
        }
        else {
          if ((s30 < uStack60._4_4_) || ((s30 <= uStack60._4_4_ && (s2c <= (int *)uStack60)))) {
            *(int **)((int)s18 + 0x30) = s1c;
            *(int **)((int)s18 + 0x34) = s20;
            *(int *)((int)s18 + 0x38) = (int)(int *)uStack60 - (int)s1c;
            *(uint *)((int)s18 + 0x3c) =
                 (int)uStack60._4_4_ + (-(uint)((int *)uStack60 < s1c) - (int)s20);
            goto LAB_6620a306;
          }
          s24 = (int)s2c - (int)(int *)uStack60;
          s28 = (int)s30 + (-(uint)(s2c < (int *)uStack60) - (int)uStack60._4_4_);
          uStack60 = (uStack60 & 0xffffffff) | (ZEXT48(uStack60._4_4_) << 0x20);
          piVar3 = uStack60._4_4_;
          pauStack52 = (undefined (*) [16])(int *)uStack60;
        }
        iVar1 = FUN_66208d70(*(undefined4 *)((int)s18 + 0x28),(uint)pauStack52,(uint)piVar3,
                             &piStack148);
        if (iVar1 < 0) {
          return iVar1;
        }
        s54 = (s54 & 0xffffffff00000000) | ZEXT48(piStack148);
        if ((((uint)s1c | (uint)s20) != 0) &&
           (((int *)uStack60 != piStack148 || (uStack60._4_4_ != s90)))) {
          return -0x3fffffc2;
        }
        uVar1 = 0;
        auStack100[0] = 0x40;
        auStack100[1] = 0x80;
        auStack100[2] = 4;
        auStack100[3] = 8;
        do {
          if ((auStack100[uVar1] & uStack112) != 0) {
            if (((uint)s1c | (uint)s20) == 0) {
              s1c = piStack148;
              s20 = s90;
            }
            uStack60._0_4_ = (int *)(uStack124 + (int)piStack148);
            uStack60._4_4_ = (int *)((int)s90 + (CARRY4(uStack124,(uint)piStack148)) + s78);
            goto LAB_6620a050;
          }
          uVar1 = uVar1 + 1;
        } while (uVar1 < 4);
        pauVar2 = (undefined (*) [16])((int)s18 + 8);
        if (*(undefined (**) [16])*pauVar2 != pauVar2) {
          pauVar2 = (undefined (*) [16])safe_malloc(0x20);
          if (pauVar2 == (undefined (*) [16])0x0) {
            pauVar2 = (undefined (*) [16])0x0;
          }
          else {
            *pauVar2 = ZEXT816(0);
            pauVar2[1] = ZEXT816(0);
          }
        }
        if (pauVar2 == (undefined (*) [16])0x0) {
          return -0x3fffff66;
        }
        ppiVar1 = (int **)(*pauVar2 + 8);
        if (param_5 == '\0') {
          *ppiVar1 = (int *)pauStack52;
          *(int **)(*pauVar2 + 0xc) = uStack60._4_4_;
          if ((s78 < s28) || ((s78 <= s28 && (uStack124 <= s24)))) {
            s24 = uStack124;
            s28 = s78;
          }
          *(uint *)pauVar2[1] = s24;
          *(uint *)(pauVar2[1] + 4) = s28;
        }
        else {
          *ppiVar1 = piStack148;
          *(int **)(*pauVar2 + 0xc) = s90;
          *(uint *)pauVar2[1] = uStack124;
          *(uint *)(pauVar2[1] + 4) = s78;
          s2c = (int *)(uStack124 + (int)piStack148);
          s30 = (int *)((int)s90 + (CARRY4(uStack124,(uint)piStack148)) + s78);
        }
        pauStack52 = pauVar2[1];
        *(uint *)(pauVar2[1] + 0xc) = uStack132;
        uStack60 = (uStack60 & 0xffffffff) | ((ulonglong)uStack132 << 0x20);
        uVar2 = FUN_6620a320(uStack132,(uint *)((int)&uStack60 + 4));
        if ((char)uVar2 == '\0') {
          uStack60._4_4_ = (int *)0x4;
        }
        s54 = (s54 & 0xffffffff) | (ZEXT48(uStack60._4_4_) << 0x20);
        uVar1 = FUN_6620be50(&DAT_6624b500,*(undefined4 *)((int)s18 + 0x28),(uint *)ppiVar1,
                             (uint *)pauVar2[1],uStack60._4_4_,pauVar2[1] + 8);
        uStack60 = (uStack60 & 0xffffffff) | ((ulonglong)uVar1 << 0x20);
        if (uVar1 == 0xc000002d) {
          if (param_5 != '\0') {
LAB_6620a2cc:
            FUN_662087b0(s18,pauVar2);
            return (int)uStack60._4_4_;
          }
          *ppiVar1 = piStack148;
          *(int **)(*pauVar2 + 0xc) = s90;
          *(uint *)pauVar2[1] = uStack124;
          *(uint *)(pauVar2[1] + 4) = s78;
          s2c = (int *)(uStack124 + (int)piStack148);
          s30 = (int *)((int)s90 + (CARRY4(uStack124,(uint)piStack148)) + s78);
          param_5 = '\x01';
          uVar1 = FUN_6620be50(&DAT_6624b500,*(undefined4 *)((int)s18 + 0x28),(uint *)ppiVar1,
                               (uint *)pauVar2[1],s54._4_4_,pauVar2[1] + 8);
          uStack60 = (uStack60 & 0xffffffff) | ((ulonglong)uVar1 << 0x20);
        }
        if ((int)uVar1 < 0) goto LAB_6620a2cc;
        pauVar1 = *(undefined (**) [16])((int)s18 + 4);
        *(undefined (**) [16])(*pauVar2 + 4) = pauVar1;
        *(void **)*pauVar2 = s18;
        *(undefined (**) [16])*pauVar1 = pauVar2;
        *(undefined (**) [16])((int)s18 + 4) = pauVar2;
        if (((uint)s1c | (uint)s20) == 0) {
          s1c = *ppiVar1;
          s20 = *(int **)(*pauVar2 + 0xc);
        }
        uStack60._0_4_ = (int *)((int)*ppiVar1 + *(int *)*pauStack52);
        uStack60._4_4_ =
             (int *)(*(int *)(*pauVar2 + 0xc) + *(int *)(*pauStack52 + 4) +
                    (uint)CARRY4((uint)*ppiVar1,*(uint *)*pauStack52));
      } while( true );
    }
  }
  return iVar1;
}



uint FUN_6620a320(uint param_1,uint *param_2)

{
  uint uVar1;
  uint s14 [4];
  
  uVar1 = 0;
  s14[0] = 0x40;
  s14[1] = 0x80;
  s14[2] = 4;
  s14[3] = 8;
  do {
    if ((param_1 & s14[uVar1]) != 0) {
      if (param_2 != (uint *)0x0) {
        *param_2 = s14[uVar1];
      }
      return ((int)(int3)((uint)param_2 >> 8) << 8) + 1;
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 4);
  return uVar1 & 0xffffff00;
}



int __thiscall
FUN_6620a370(void *this,int *param_1,int *param_2,int param_3,uint param_4,uint param_5,char param_6
            )

{
  void *this_00;
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  if ((param_4 | param_5) != 0) {
    if ((*(char *)((int)this + 0x5a) != '\0') &&
       (iVar2 = FUN_66209f90(this,param_1,param_2,param_4,param_5,'\0'), iVar2 < 0)) {
      return iVar2;
    }
    if (*(char *)((int)this + 0x58) == '\0') {
      this_00 = (void *)FUN_66208ab0();
      if ((this_00 != (void *)0x0) && (*(char *)((int)this_00 + 0x20) != '\0')) {
        FUN_6620a420(this_00,*(undefined4 *)((int)this + 0x48),(uint)param_1,(uint)param_2,param_3,
                     param_4,param_5);
      }
      iVar2 = FUN_6620bf70(&DAT_6624b500,*(undefined4 *)((int)this + 0x48),(uint)param_1,
                           (uint)param_2,param_3,param_4,param_5);
    }
    else {
      FUN_6620dc00(param_1,param_3,param_4);
      iVar2 = 0;
    }
  }
  if ((param_6 != '\0') && (iVar1 = FUN_66209870((int **)this), -1 < iVar2)) {
    iVar2 = iVar1;
  }
  return iVar2;
}



undefined4 __thiscall
FUN_6620a420(void *this,undefined4 param_1,uint param_2,uint param_3,int param_4,uint param_5,
            int param_6)

{
  int iVar1;
  int *piVar1;
  uint uVar1;
  uint uVar2;
  int *s1c;
  uint s18;
  int s14;
  uint s10;
  int *sc;
  uint s8;
  
  uVar1 = param_3;
  param_3 = 0;
  s1c = (int *)((param_2 >> 0xc) | (uVar1 << 0x14));
  uVar1 = uVar1 >> 0xc;
  s10 = param_2 + ((param_2 >> 0xc) * -0x1000);
  uVar2 = s10 + param_5;
  s8 = param_5;
  iVar1 = param_6 + (uint)CARRY4(s10,param_5);
  while ((s18 = uVar1, sc = s1c, iVar1 != 0 || (0x1000 < uVar2))) {
    uVar2 = 0x1000 - s10;
    FUN_6620acb0((void *)((int)this + 0x14),&s14,(uint *)&s1c);
    if (s14 == *(int *)((int)this + 0x14)) {
      if (*(int *)((int)this + 0x18) == *(int *)((int)this + 0x1c)) {
        FUN_66209f00(this,*(int *)((int)this + 4));
      }
      *(int *)((int)this + 0x28) = *(int *)((int)this + 0x28) + 1;
      piVar1 = FUN_66209e30(this,param_1,sc,uVar1);
    }
    else {
      *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + 1;
      piVar1 = *(int **)(s14 + 0x18);
    }
    if (piVar1 == (int *)0x0) goto LAB_6620a57e;
    FUN_6620d5b0((int)piVar1 + s10,param_3 + param_4,uVar2);
    param_3 = param_3 + uVar2;
    param_6 = param_6 - (uint)(s8 < uVar2);
    s1c = (int *)((int)sc + 1);
    uVar1 = uVar1 + (((int *)0xfffffffe < sc));
    s10 = 0;
    uVar2 = s8 - uVar2;
    s8 = uVar2;
    iVar1 = param_6;
  }
  FUN_6620acb0((void *)((int)this + 0x14),&s14,(uint *)&s1c);
  if (s14 == *(int *)((int)this + 0x14)) {
    if (*(int *)((int)this + 0x18) == *(int *)((int)this + 0x1c)) {
      FUN_66209f00(this,*(int *)((int)this + 4));
    }
    *(int *)((int)this + 0x28) = *(int *)((int)this + 0x28) + 1;
    piVar1 = FUN_66209e30(this,param_1,sc,uVar1);
  }
  else {
    *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + 1;
    piVar1 = *(int **)(s14 + 0x18);
  }
  if (piVar1 != (int *)0x0) {
    FUN_6620d5b0(s10 + (int)piVar1,param_4 + param_3,s8);
    return 0;
  }
LAB_6620a57e:
  if ((param_3 == s8) && (param_6 == 0)) {
    return 0;
  }
  return 0xc0000004;
}



undefined4 * allocate_initialized_struct101(void)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 *s1c [2];
  undefined *s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621bac0;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s14 = &stack0xffffffd4;
  puVar1 = (undefined4 *)safe_malloc(0x18);
  if (puVar1 == (undefined4 *)0x0) {
    raise_fatal_allocation_exception();
  }
  s8 = 0;
  s1c[0] = puVar1;
  CopyMemoryDWord(puVar1,s1c);
  CopyMemoryDWord(puVar1 + 1,s1c);
  CopyMemoryDWord(puVar1 + 2,s1c);
  *(undefined2 *)(puVar1 + 3) = 0x101;
  *in_FS_OFFSET = s10;
  return puVar1;
}



undefined4 * FUN_6620a670(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621bad0;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  puVar1 = (undefined4 *)safe_malloc(0xc);
  if (puVar1 == (undefined4 *)0x0) {
    raise_fatal_allocation_exception();
  }
  if (param_1 == (undefined4 *)0x0) {
    param_1 = puVar1;
    param_2 = puVar1;
  }
  s8 = 0;
  CopyMemoryDWord(puVar1,&param_1);
  CopyMemoryDWord(puVar1 + 1,&param_2);
  *in_FS_OFFSET = s10;
  return puVar1;
}



undefined4 * __fastcall FUN_6620a710(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621bae0;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  puVar1 = (undefined4 *)safe_malloc(0x20);
  if (puVar1 == (undefined4 *)0x0) {
    raise_fatal_allocation_exception();
  }
  s8 = 0;
  CopyMemoryDWord(puVar1,param_1);
  CopyMemoryDWord(puVar1 + 1,param_1);
  CopyMemoryDWord(puVar1 + 2,param_1);
  *in_FS_OFFSET = s10;
  return puVar1;
}



void __thiscall FUN_6620a7b0(void *this,int *param_1,uint *param_2)

{
  char cVar1;
  uint uVar1;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  bool bVar1;
  
                    // WARNING: Load size is inaccurate
  puVar5 = *this;
  puVar2 = (undefined4 *)puVar5[1];
  cVar1 = *(char *)((int)puVar2 + 0xd);
  puVar1 = puVar5;
  puVar3 = puVar2;
  while (cVar1 == '\0') {
    uVar1 = puVar3[5];
    bVar1 = param_2[1] <= uVar1;
    if ((bVar1 && (uVar1 != param_2[1])) || ((bVar1 && (*param_2 <= (uint)puVar3[4])))) {
      if ((*(char *)((int)puVar5 + 0xd) != '\0') &&
         ((bVar1 = param_2[1] < uVar1, bVar1 || (param_2[1] == uVar1) &&
          ((bVar1 || (*param_2 < (uint)puVar3[4])))))) {
        puVar5 = puVar3;
      }
      puVar4 = (undefined4 *)*puVar3;
    }
    else {
      puVar4 = (undefined4 *)puVar3[2];
      puVar3 = puVar1;
    }
    puVar1 = puVar3;
    puVar3 = puVar4;
    cVar1 = *(char *)((int)puVar4 + 0xd);
  }
  if (*(char *)((int)puVar5 + 0xd) == '\0') {
    puVar2 = (undefined4 *)*puVar5;
  }
  if (*(char *)((int)puVar2 + 0xd) == '\0') {
    uVar1 = param_2[1];
    do {
      bVar1 = (uint)puVar2[5] <= uVar1;
      if ((bVar1 && (uVar1 != puVar2[5])) || ((bVar1 && ((uint)puVar2[4] <= *param_2)))) {
        puVar3 = (undefined4 *)puVar2[2];
      }
      else {
        puVar3 = (undefined4 *)*puVar2;
        puVar5 = puVar2;
      }
      puVar2 = puVar3;
    } while (*(char *)((int)puVar3 + 0xd) == '\0');
  }
  *param_1 = (int)puVar1;
  param_1[1] = (int)puVar5;
  return;
}



void FUN_6620a850(int *param_1)

{
  char cVar1;
  int *piVar1;
  
  cVar1 = *(char *)((int)param_1 + 0xd);
  while (cVar1 == '\0') {
    FUN_6620a850((int *)param_1[2]);
    piVar1 = (int *)*param_1;
    FID_conflict__free(param_1);
    param_1 = piVar1;
    cVar1 = *(char *)((int)piVar1 + 0xd);
  }
  return;
}



void __thiscall FUN_6620a890(void *this,int *param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  
  ppiVar1 = (int **)param_1[2];
  param_1[2] = (int)*ppiVar1;
  if (*(char *)((int)*ppiVar1 + 0xd) == '\0') {
    (*ppiVar1)[1] = (int)param_1;
  }
  ppiVar1[1] = (int *)param_1[1];
                    // WARNING: Load size is inaccurate
  if (param_1 == *(int **)(*this + 4)) {
    *(int ***)(*this + 4) = ppiVar1;
    *ppiVar1 = param_1;
    param_1[1] = (int)ppiVar1;
    return;
  }
  ppiVar2 = (int **)param_1[1];
  if (param_1 == *ppiVar2) {
    *ppiVar2 = (int *)ppiVar1;
    *ppiVar1 = param_1;
    param_1[1] = (int)ppiVar1;
    return;
  }
  ppiVar2[2] = (int *)ppiVar1;
  *ppiVar1 = param_1;
  param_1[1] = (int)ppiVar1;
  return;
}



void __thiscall FUN_6620a8f0(void *this,int *param_1)

{
  int iVar1;
  int *piVar1;
  
  iVar1 = *param_1;
  *param_1 = *(int *)(iVar1 + 8);
  if (*(char *)(*(int *)(iVar1 + 8) + 0xd) == '\0') {
    *(int **)(*(int *)(iVar1 + 8) + 4) = param_1;
  }
  *(int *)(iVar1 + 4) = param_1[1];
                    // WARNING: Load size is inaccurate
  if (param_1 == *(int **)(*this + 4)) {
    *(int *)(*this + 4) = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  piVar1 = (int *)param_1[1];
  if (param_1 == (int *)piVar1[2]) {
    piVar1[2] = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  *piVar1 = iVar1;
  *(int **)(iVar1 + 8) = param_1;
  param_1[1] = iVar1;
  return;
}



void __fastcall FUN_6620a950(int *param_1)

{
  char cVar1;
  int *piVar1;
  int *_Memory;
  
  cVar1 = *(char *)((int)*(int **)(*param_1 + 4) + 0xd);
  _Memory = *(int **)(*param_1 + 4);
  while (cVar1 == '\0') {
    FUN_6620a850((int *)_Memory[2]);
    piVar1 = (int *)*_Memory;
    FID_conflict__free(_Memory);
    _Memory = piVar1;
    cVar1 = *(char *)((int)piVar1 + 0xd);
  }
  *(int *)(*param_1 + 4) = *param_1;
  *(int *)*param_1 = *param_1;
  *(int *)(*param_1 + 8) = *param_1;
  param_1[1] = 0;
  return;
}



int ** __thiscall FUN_6620a9a0(void *this,int **param_1,int **param_2,int **param_3)

{
  char cVar1;
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  int *s8;
  
                    // WARNING: Load size is inaccurate
  s8 = (int *)this;
  if ((param_2 == (int **)**this) && (param_3 == *this)) {
    FUN_6620a950((int *)this);
                    // WARNING: Load size is inaccurate
    *param_1 = **this;
    return param_1;
  }
  if (param_2 != param_3) {
    do {
      ppiVar2 = param_2;
      if (*(char *)((int)param_2 + 0xd) == '\0') {
        ppiVar1 = (int **)param_2[2];
        if (*(char *)((int)ppiVar1 + 0xd) == '\0') {
          cVar1 = *(char *)((int)*ppiVar1 + 0xd);
          param_2 = ppiVar1;
          ppiVar1 = (int **)*ppiVar1;
          while (cVar1 == '\0') {
            cVar1 = *(char *)((int)*ppiVar1 + 0xd);
            param_2 = ppiVar1;
            ppiVar1 = (int **)*ppiVar1;
          }
        }
        else {
          cVar1 = *(char *)((int)param_2[1] + 0xd);
          ppiVar3 = (int **)param_2[1];
          ppiVar1 = param_2;
          while ((param_2 = ppiVar3, cVar1 == '\0' && (ppiVar1 == (int **)param_2[2]))) {
            cVar1 = *(char *)((int)param_2[1] + 0xd);
            ppiVar3 = (int **)param_2[1];
            ppiVar1 = param_2;
          }
        }
      }
      FUN_6620aa40(this,&s8,ppiVar2);
    } while (param_2 != param_3);
  }
  *param_1 = (int *)param_2;
  return param_1;
}



void __thiscall FUN_6620aa40(void *this,int **param_1,int **param_2)

{
  undefined uVar1;
  char cVar1;
  int **ppiVar1;
  int **_Memory;
  int **ppiVar2;
  int **ppiVar3;
  int **ppiVar4;
  int **ppiVar5;
  
  _Memory = param_2;
  FUN_66207f40((int **)&param_2);
  ppiVar3 = (int **)*_Memory;
  if (*(char *)((int)ppiVar3 + 0xd) == '\0') {
    ppiVar5 = ppiVar3;
    if ((*(char *)((int)_Memory[2] + 0xd) == '\0') &&
       (ppiVar5 = (int **)param_2[2], param_2 != _Memory)) {
      ppiVar3[1] = (int *)param_2;
      *param_2 = *_Memory;
      ppiVar3 = param_2;
      if (param_2 != (int **)_Memory[2]) {
        ppiVar3 = (int **)param_2[1];
        if (*(char *)((int)ppiVar5 + 0xd) == '\0') {
          ppiVar5[1] = (int *)ppiVar3;
        }
        *ppiVar3 = (int *)ppiVar5;
        param_2[2] = _Memory[2];
        _Memory[2][1] = (int)param_2;
      }
                    // WARNING: Load size is inaccurate
      if (*(int ***)(*this + 4) == _Memory) {
        *(int ***)(*this + 4) = param_2;
      }
      else {
        ppiVar2 = (int **)_Memory[1];
        if ((int **)*ppiVar2 == _Memory) {
          *ppiVar2 = (int *)param_2;
        }
        else {
          ppiVar2[2] = (int *)param_2;
        }
      }
      param_2[1] = _Memory[1];
      uVar1 = *(undefined *)(param_2 + 3);
      *(undefined *)(param_2 + 3) = *(undefined *)(_Memory + 3);
      *(undefined *)(_Memory + 3) = uVar1;
      goto LAB_6620ab65;
    }
  }
  else {
    ppiVar5 = (int **)_Memory[2];
  }
  ppiVar3 = (int **)_Memory[1];
  if (*(char *)((int)ppiVar5 + 0xd) == '\0') {
    ppiVar5[1] = (int *)ppiVar3;
  }
                    // WARNING: Load size is inaccurate
  if (*(int ***)(*this + 4) == _Memory) {
    *(int ***)(*this + 4) = ppiVar5;
  }
  else if ((int **)*ppiVar3 == _Memory) {
    *ppiVar3 = (int *)ppiVar5;
  }
  else {
    ppiVar3[2] = (int *)ppiVar5;
  }
                    // WARNING: Load size is inaccurate
  ppiVar2 = *this;
  if ((int **)*ppiVar2 == _Memory) {
    ppiVar4 = ppiVar3;
    if (*(char *)((int)ppiVar5 + 0xd) == '\0') {
      cVar1 = *(char *)((int)*ppiVar5 + 0xd);
      ppiVar2 = (int **)*ppiVar5;
      ppiVar4 = ppiVar5;
      while (ppiVar1 = ppiVar2, cVar1 == '\0') {
        ppiVar2 = (int **)*ppiVar1;
        cVar1 = *(char *)((int)ppiVar2 + 0xd);
        ppiVar4 = ppiVar1;
      }
                    // WARNING: Load size is inaccurate
      ppiVar2 = *this;
    }
    *ppiVar2 = (int *)ppiVar4;
  }
                    // WARNING: Load size is inaccurate
  if (*(int ***)(*this + 8) == _Memory) {
    if (*(char *)((int)ppiVar5 + 0xd) == '\0') {
      cVar1 = *(char *)((int)ppiVar5[2] + 0xd);
      ppiVar2 = (int **)ppiVar5[2];
      ppiVar4 = ppiVar5;
      while (ppiVar1 = ppiVar2, cVar1 == '\0') {
        ppiVar2 = (int **)ppiVar1[2];
        cVar1 = *(char *)((int)ppiVar2 + 0xd);
        ppiVar4 = ppiVar1;
      }
                    // WARNING: Load size is inaccurate
      *(int ***)(*this + 8) = ppiVar4;
    }
    else {
      *(int ***)(*this + 8) = ppiVar3;
    }
  }
LAB_6620ab65:
  if (*(char *)(_Memory + 3) == '\x01') {
                    // WARNING: Load size is inaccurate
    if (ppiVar5 != *(int ***)(*this + 4)) {
      do {
        ppiVar2 = ppiVar3;
        if (*(char *)(ppiVar5 + 3) != '\x01') break;
        ppiVar3 = (int **)*ppiVar2;
        if (ppiVar5 == ppiVar3) {
          ppiVar3 = (int **)ppiVar2[2];
          if (*(char *)(ppiVar3 + 3) == '\0') {
            *(undefined *)(ppiVar3 + 3) = 1;
            *(undefined *)(ppiVar2 + 3) = 0;
            FUN_6620a890(this,(int *)ppiVar2);
            ppiVar3 = (int **)ppiVar2[2];
          }
          if (*(char *)((int)ppiVar3 + 0xd) == '\0') {
            if ((*(char *)(*ppiVar3 + 3) != '\x01') || (*(char *)(ppiVar3[2] + 3) != '\x01')) {
              if (*(char *)(ppiVar3[2] + 3) == '\x01') {
                *(undefined *)(*ppiVar3 + 3) = 1;
                *(undefined *)(ppiVar3 + 3) = 0;
                FUN_6620a8f0(this,(int *)ppiVar3);
                ppiVar3 = (int **)ppiVar2[2];
              }
              *(undefined *)(ppiVar3 + 3) = *(undefined *)(ppiVar2 + 3);
              *(undefined *)(ppiVar2 + 3) = 1;
              *(undefined *)(ppiVar3[2] + 3) = 1;
              FUN_6620a890(this,(int *)ppiVar2);
              break;
            }
LAB_6620ac2f:
            *(undefined *)(ppiVar3 + 3) = 0;
          }
        }
        else {
          if (*(char *)(ppiVar3 + 3) == '\0') {
            *(undefined *)(ppiVar3 + 3) = 1;
            *(undefined *)(ppiVar2 + 3) = 0;
            FUN_6620a8f0(this,(int *)ppiVar2);
            ppiVar3 = (int **)*ppiVar2;
          }
          if (*(char *)((int)ppiVar3 + 0xd) == '\0') {
            if ((*(char *)(ppiVar3[2] + 3) == '\x01') && (*(char *)(*ppiVar3 + 3) == '\x01'))
            goto LAB_6620ac2f;
            if (*(char *)(*ppiVar3 + 3) == '\x01') {
              *(undefined *)(ppiVar3[2] + 3) = 1;
              *(undefined *)(ppiVar3 + 3) = 0;
              FUN_6620a890(this,(int *)ppiVar3);
              ppiVar3 = (int **)*ppiVar2;
            }
            *(undefined *)(ppiVar3 + 3) = *(undefined *)(ppiVar2 + 3);
            *(undefined *)(ppiVar2 + 3) = 1;
            *(undefined *)(*ppiVar3 + 3) = 1;
            FUN_6620a8f0(this,(int *)ppiVar2);
            break;
          }
        }
                    // WARNING: Load size is inaccurate
        ppiVar3 = (int **)ppiVar2[1];
        ppiVar5 = ppiVar2;
      } while (ppiVar2 != *(int ***)(*this + 4));
    }
    *(undefined *)(ppiVar5 + 3) = 1;
  }
  FID_conflict__free(_Memory);
  if (*(int *)((int)this + 4) != 0) {
    *(int *)((int)this + 4) = *(int *)((int)this + 4) + -1;
  }
  *param_1 = (int *)param_2;
  return;
}



void __thiscall FUN_6620acb0(void *this,int *param_1,uint *param_2)

{
  undefined4 *puVar1;
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  bool bVar1;
  
                    // WARNING: Load size is inaccurate
  puVar1 = *this;
  puVar4 = puVar1;
  if (*(char *)((int)(undefined4 *)puVar1[1] + 0xd) == '\0') {
    uVar1 = param_2[1];
    puVar2 = (undefined4 *)puVar1[1];
    do {
      bVar1 = uVar1 <= (uint)puVar2[5];
      if ((bVar1 && (puVar2[5] != uVar1)) || ((bVar1 && (*param_2 <= (uint)puVar2[4])))) {
        puVar3 = (undefined4 *)*puVar2;
        puVar4 = puVar2;
      }
      else {
        puVar3 = (undefined4 *)puVar2[2];
      }
      puVar2 = puVar3;
    } while (*(char *)((int)puVar3 + 0xd) == '\0');
  }
  if (puVar4 != puVar1) {
    uVar1 = param_2[1];
    bVar1 = (uint)puVar4[5] <= uVar1;
    if ((bVar1) && ((bVar1 && (uVar1 != puVar4[5]) || ((uint)puVar4[4] <= *param_2)))) {
      *param_1 = (int)puVar4;
      return;
    }
  }
  *param_1 = (int)puVar1;
  return;
}



void __cdecl FUN_6620ad30(int *param_1,undefined *param_2)

{
  short *psVar1;
  uint context_number;
  int iVar1;
  undefined *puVar1;
  
  context_number = param_1[1];
  puVar1 = &DAT_6621ca68;
  if (param_2 != (undefined *)0x0) {
    puVar1 = param_2;
  }
  if (context_number != 0) {
    psVar1 = (short *)(*param_1 + (context_number * 2));
    do {
      psVar1 = psVar1 + -1;
      if ((*psVar1 != 0x5c) && (*psVar1 != 0x2f)) break;
      context_number = context_number - 1;
    } while (context_number != 0);
  }
  for (iVar1 = 0;
      (*(short *)(puVar1 + (iVar1 * 2)) == 0x5c || (*(short *)(puVar1 + (iVar1 * 2)) == 0x2f));
      iVar1 = iVar1 + 1) {
  }
  update_context(param_1,context_number);
  invoke_qhandler(param_1,'\x01',(short *)&DAT_6621ccf0,-1,0,(undefined4 *)0x0);
  invoke_qhandler(param_1,'\x01',(short *)(puVar1 + (iVar1 * 2)),-1,0,(undefined4 *)0x0);
  return;
}



uint __cdecl ProcessPathTypeAndBuildOutput(short *param_1,void *param_2)

{
  uint uVar1;
  byte bVar1;
  undefined4 *in_FS_OFFSET;
  ushort *scc;
  int sc8;
  uint s1c;
  int s18;
  undefined4 s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s8 = 0xffffffff;
  puStack12 = &LAB_6621b6db;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  pass_context_to_handler(&scc,param_1,-1);
  s8 = 0;
  s1c = 0;
  s18 = 0;
  s14 = 0;
  FUN_6620b070(&s1c,scc);
  if (((s1c >> 1) & 1) != 0) {
    get_context(param_2,(short **)&scc);
    bVar1 = 1;
    goto LAB_6620af2c;
  }
  if ((s1c & 1) == 0) {
    if (((s1c >> 2) & 1) != 0) {
      safeget_ctxblob(param_2,u______6621cf18,-1);
      invoke_qhandler(param_2,'\x01',(short *)(scc + 4),-1,0,(undefined4 *)0x0);
      bVar1 = 1;
      goto LAB_6620af2c;
    }
    if (((s1c >> 3) & 1) != 0) {
      safeget_ctxblob(param_2,u__Device__6621cf24,-1);
      invoke_qhandler(param_2,'\x01',(short *)(scc + s18),-1,0,(undefined4 *)0x0);
      bVar1 = 1;
      goto LAB_6620af2c;
    }
    get_context(param_2,(short **)&scc);
  }
  else {
    if (((s1c >> 9) & 1) != 0) {
      safeget_ctxblob(param_2,u_____UNC__6621cf04,-1);
      invoke_qhandler(param_2,'\x01',(short *)(scc + 2),-1,0,(undefined4 *)0x0);
      bVar1 = 1;
      goto LAB_6620af2c;
    }
    if (((s1c >> 0xb) & 1) != 0) {
      safeget_ctxblob(param_2,u______6621cf18,-1);
      invoke_qhandler(param_2,'\x01',(short *)scc,sc8,0,(undefined4 *)0x0);
      bVar1 = 1;
      goto LAB_6620af2c;
    }
  }
  bVar1 = 0;
LAB_6620af2c:
  s8 = 0xffffffff;
  uVar1 = manage_memstate(&scc);
  *in_FS_OFFSET = s10;
  return (uVar1 & 0xffffff00) | (uint)bVar1;
}



int __cdecl FUN_6620af50(short **param_1,short *param_2)

{
  short sVar1;
  int iVar1;
  
  if (*param_1 == (short *)0x0) {
    if (param_2 != (short *)0x0) {
      *param_2 = 0;
    }
    return 0;
  }
  iVar1 = 0;
  sVar1 = **param_1;
  while (sVar1 != 0x5c) {
    if (sVar1 == 0) goto LAB_6620af8c;
    *param_1 = *param_1 + 1;
    iVar1 = iVar1 + 1;
    sVar1 = **param_1;
  }
  *param_1 = *param_1 + 1;
LAB_6620af8c:
  if (param_2 != (short *)0x0) {
    *param_2 = sVar1;
  }
  return iVar1;
}



short * __cdecl FUN_6620afa0(short **param_1)

{
  short sVar1;
  short *psVar1;
  short *psVar2;
  
  psVar1 = *param_1;
  if (psVar1 != (short *)0x0) {
    psVar2 = (short *)0x0;
    sVar1 = *psVar1;
    while (sVar1 == 0x5c) {
      psVar1 = psVar1 + 1;
      psVar2 = (short *)((int)psVar2 + 1);
      *param_1 = psVar1;
      sVar1 = *psVar1;
    }
    return psVar2;
  }
  return psVar1;
}



// WARNING: Could not reconcile some variable overlaps

int __cdecl FUN_6620afd0(short *param_1,char param_2)

{
  short sVar1;
  short *psVar1;
  int iVar1;
  int iVar2;
  int iVar3;
  short *s8;
  
  psVar1 = param_1;
  s8 = param_1;
  if (param_1 != (short *)0x0) {
    iVar3 = 0;
    if (param_2 == '\0') {
      if (*param_1 != 0x5c) {
        return 0;
      }
      if (param_1[1] != 0x5c) {
        return 0;
      }
      iVar3 = 2;
    }
    iVar1 = FUN_6620af50(&s8,(short *)&param_1);
    if (iVar1 != 0) {
      iVar3 = iVar3 + iVar1;
      if ((short)param_1 == 0x5c) {
        iVar3 = iVar3 + 1;
      }
      if (iVar3 != 0) {
        param_1 = psVar1 + iVar3;
        iVar1 = 0;
        if (param_1 != (short *)0x0) {
          sVar1 = *param_1;
          while (sVar1 == 0x5c) {
            param_1 = param_1 + 1;
            iVar1 = iVar1 + 1;
            sVar1 = *param_1;
          }
        }
        iVar2 = FUN_6620af50(&param_1,(short *)&s8);
        if (iVar2 != 0) {
          iVar2 = iVar3 + iVar1 + iVar2;
          if ((short)s8 == 0x5c) {
            return iVar2 + 1;
          }
          return iVar2;
        }
      }
    }
  }
  return 0;
}



// WARNING: Could not reconcile some variable overlaps

void __thiscall FUN_6620b070(void *this,ushort *param_1)

{
  int iVar1;
  ushort *puVar1;
  uint uVar1;
  undefined4 uVar2;
  short *psVar1;
  int iVar2;
  void *s8;
  
  puVar1 = param_1;
  *(undefined4 *)this = 1;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  if ((param_1 == (ushort *)0x0) || (*param_1 == 0)) {
    *(undefined4 *)this = 0x101;
  }
  else {
    s8 = this;
    FUN_6620b170(this,param_1);
    uVar1 = FUN_6620b270(this,(int)puVar1);
    if ((char)uVar1 == '\0') {
      uVar2 = FUN_6620b400(this,(int)puVar1);
      if ((char)uVar2 == '\0') {
        uVar1 = FUN_6620b3c0(this,(uint)puVar1);
        if ((char)uVar1 == '\0') {
                    // WARNING: Load size is inaccurate
          if ((*this & 1) == 0) {
            param_1 = puVar1 + *(int *)((int)this + 4);
            psVar1 = FUN_6620afa0((short **)&param_1);
            *(int *)((int)this + 8) = *(int *)((int)this + 8) + (int)psVar1;
            iVar1 = *(int *)((int)this + 8);
            iVar2 = FUN_6620af50((short **)&param_1,(short *)&s8);
            if (iVar2 == 0) {
                    // WARNING: Load size is inaccurate
              *(uint *)this = *this | 0x100;
              return;
            }
            iVar2 = iVar2 + iVar1;
            *(int *)((int)this + 8) = iVar2;
            if ((short)s8 == 0x5c) {
              *(int *)((int)this + 8) = iVar2 + 1;
            }
                    // WARNING: Load size is inaccurate
            *(uint *)this = *this | 0x4000;
            return;
          }
          if (*puVar1 == 0x5c) {
                    // WARNING: Load size is inaccurate
            *(uint *)this = *this | 0x10000;
            *(undefined4 *)((int)this + 8) = 1;
            return;
          }
                    // WARNING: Load size is inaccurate
          *(uint *)this = *this | 0x20000;
          return;
        }
      }
    }
  }
  return;
}



void __thiscall FUN_6620b170(void *this,ushort *param_1)

{
  int iVar1;
  
  *(undefined4 *)this = 1;
  *(undefined4 *)((int)this + 4) = 0;
  if (param_1 == (ushort *)0x0) goto LAB_6620b22e;
  iVar1 = _wcsncmp((wchar_t *)param_1,u______6621cf18,4);
  if (iVar1 == 0) {
    *(undefined4 *)this = 2;
  }
  else {
    iVar1 = FUN_6620e9db(param_1,(ushort *)u__Global____6621cf38,10);
    if (iVar1 == 0) {
      *(undefined4 *)this = 2;
      *(undefined4 *)((int)this + 4) = 10;
      goto LAB_6620b22e;
    }
    iVar1 = FUN_6620e9db(param_1,(ushort *)u__DosDevices__6621cf50,0xc);
    if (iVar1 == 0) {
      *(undefined4 *)this = 2;
      *(undefined4 *)((int)this + 4) = 0xc;
      goto LAB_6620b22e;
    }
    iVar1 = _wcsncmp((wchar_t *)param_1,u______6621cf6c,4);
    if (iVar1 == 0) {
      *(undefined4 *)this = 8;
    }
    else {
      iVar1 = _wcsncmp((wchar_t *)param_1,u______6621cf78,4);
      if (iVar1 != 0) goto LAB_6620b22e;
      *(undefined4 *)this = 4;
    }
  }
  *(undefined4 *)((int)this + 4) = 4;
LAB_6620b22e:
                    // WARNING: Load size is inaccurate
  if ((((*this >> 1) & 1) != 0) || (((*this >> 2) & 1) != 0)) {
    iVar1 = FUN_6620e9db(param_1 + *(int *)((int)this + 4),(ushort *)u_UNC__6621cf84,4);
    if (iVar1 == 0) {
                    // WARNING: Load size is inaccurate
      *(uint *)this = *this | 0x10;
      *(int *)((int)this + 4) = *(int *)((int)this + 4) + 4;
    }
  }
  return;
}



uint __thiscall FUN_6620b270(void *this,int param_1)

{
  ushort *puVar1;
  ushort uVar1;
  uint uVar2;
  int iVar1;
  uint uVar3;
  uint uVar4;
  
                    // WARNING: Load size is inaccurate
  uVar2 = *this;
  iVar1 = *(int *)((int)this + 4);
  puVar1 = (ushort *)(param_1 + (iVar1 * 2));
  if (((uVar2 >> 4) & 1) != 0) {
    return (uVar2 >> 0xc) << 8;
  }
  uVar4 = (uint)*puVar1;
  if ((ushort)(*puVar1 - 0x41) < 0x1a) {
    uVar3 = uVar4 - 0x41;
  }
  else {
    uVar3 = uVar4 - 0x61;
    if (0x19 < (ushort)uVar3) goto LAB_6620b3ab;
    uVar3 = uVar4 - 0x61;
  }
  if ((-1 < (int)uVar3) && (puVar1[1] == 0x3a)) {
    *(uint *)this = uVar2 | 0x1000000;
    if ((uVar2 & 1) != 0) {
      if (puVar1[2] == 0x5c) {
        *(int *)((int)this + 8) = iVar1 + 3;
        *(uint *)this = uVar2 | 0x1000800;
        return ((int)(int3)((uint)(iVar1 + 3) >> 8) << 8) + 1;
      }
      *(int *)((int)this + 8) = iVar1 + 2;
      *(uint *)this = uVar2 | 0x1001000;
      return ((int)(int3)((uint)(iVar1 + 2) >> 8) << 8) + 1;
    }
    if (((uVar2 & 2) != 0) || ((uVar2 & 4) != 0)) {
      uVar1 = puVar1[2];
      if (uVar1 == 0) {
        *(int *)((int)this + 8) = iVar1 + 2;
        *(uint *)this = uVar2 | 0x1002000;
        return ((int)(int3)((uint)(iVar1 + 2) >> 8) << 8) + 1;
      }
      if (uVar1 == 0x5c) {
        *(int *)((int)this + 8) = iVar1 + 3;
        *(uint *)this = uVar2 | 0x1000800;
        return ((int)(int3)((uint)(iVar1 + 3) >> 8) << 8) + 1;
      }
      *(uint *)this = uVar2 | 0x1000100;
      return ((int)(int3)(uint3)(byte)(uVar1 >> 8) << 8) + 1;
    }
    uVar3 = (uVar2 | 0x1000000) >> 3;
    if ((uVar2 & 8) != 0) {
      uVar3 = (uint)puVar1[2];
      if (puVar1[2] == 0) {
        *(int *)((int)this + 8) = iVar1 + 2;
        *(uint *)this = uVar2 | 0x1002000;
        return ((int)(int3)((uint)(iVar1 + 2) >> 8) << 8) + 1;
      }
      if (uVar3 == 0x5c) {
        *(int *)((int)this + 8) = iVar1 + 3;
        *(uint *)this = uVar2 | 0x1002000;
        return ((int)(int3)((uint)(iVar1 + 3) >> 8) << 8) + 1;
      }
    }
  }
LAB_6620b3ab:
  return uVar3 & 0xffffff00;
}



uint __thiscall FUN_6620b3c0(void *this,uint param_1)

{
  ushort *puVar1;
  ushort uVar1;
  
                    // WARNING: Load size is inaccurate
  puVar1 = (ushort *)(param_1 + (*(int *)((int)this + 4) * 2));
  if ((*this & 1) != 0) {
    uVar1 = *puVar1;
    param_1 = (uint)uVar1;
    if (((param_1 == 0x3a) || ((0x2f < param_1 && (param_1 < 0x3a)))) && (puVar1[1] == 0x3a)) {
                    // WARNING: Load size is inaccurate
      *(uint *)this = *this | 0x400;
      return ((int)(int3)(uint3)(byte)(uVar1 >> 8) << 8) + 1;
    }
  }
  return param_1 & 0xffffff00;
}


/*
Unable to decompile 'FUN_6620b400'
Cause: Exception while decompiling 6620b400: Decompiler process died

*/


void __cdecl FUN_6620b470(byte *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  if ((0xd6 < *param_1) && (*param_1 < 0xd9)) {
    FUN_6620c070(param_1,param_3,param_4);
    return;
  }
  FUN_6620d5b0(param_3,param_1 + 1,param_4);
  return;
}



bool FUN_6620b4b0(void)

{
  if (DAT_662253b4 == '\0') {
    FUN_6620c120(&PTR_s_ntdll_662253ac);
  }
  return DAT_66225038 != 0;
}



bool FUN_6620b4d0(void)

{
  if (DAT_662253b4 == '\0') {
    FUN_6620c120(&PTR_s_ntdll_662253ac);
  }
  return DAT_6622508c != 0;
}



undefined8 FUN_6620b4f0(void)

{
  undefined8 uVar1;
  
  if (DAT_662253b4 == '\0') {
    FUN_6620c120(&PTR_s_ntdll_662253ac);
  }
  if (DAT_66225038 != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x6620b510. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (*DAT_66225038)();
    return uVar1;
  }
  return 0xffffffffc0000002;
}



undefined8 FUN_6620b520(void)

{
  undefined8 uVar1;
  
  if (DAT_662253b4 == '\0') {
    FUN_6620c120(&PTR_s_ntdll_662253ac);
  }
  if (DAT_66225070 != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x6620b540. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (*DAT_66225070)();
    return uVar1;
  }
  return 0xffffffffc0000002;
}



undefined8 FUN_6620b550(void)

{
  undefined8 uVar1;
  
  if (DAT_662253b4 == '\0') {
    FUN_6620c120(&PTR_s_ntdll_662253ac);
  }
  if (DAT_6622508c != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x6620b570. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (*DAT_6622508c)();
    return uVar1;
  }
  return 0xffffffffc0000002;
}



undefined8 FUN_6620b580(void)

{
  undefined8 uVar1;
  
  if (DAT_662253b4 == '\0') {
    FUN_6620c120(&PTR_s_ntdll_662253ac);
  }
  if (DAT_662250a8 != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x6620b5a0. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (*DAT_662250a8)();
    return uVar1;
  }
  return 0xffffffffc000007a;
}



undefined (*) [16] __fastcall FUN_6620b5b0(undefined (*param_1) [16])

{
  *param_1 = ZEXT816(0);
  *(undefined4 *)param_1[1] = 0;
  *(undefined4 *)(param_1[1] + 4) = 0;
  *(undefined4 *)(param_1[1] + 8) = 0;
  *(undefined4 *)(param_1[1] + 0xc) = 0;
  *(undefined4 *)param_1[2] = 0;
  *(undefined4 *)(param_1[2] + 4) = 0;
  *(undefined4 *)(param_1[2] + 8) = 0;
  return param_1;
}



void __fastcall thunk_FUN_6620b7a0(undefined (*param_1) [16])

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar1;
  
  if (*(int *)(param_1[1] + 4) != 0) {
    RtlFreeSid(*(int *)(param_1[1] + 4));
    *(undefined4 *)(param_1[1] + 4) = 0;
  }
  if (*(int *)(param_1[1] + 8) != 0) {
    RtlFreeSid(*(int *)(param_1[1] + 8));
    *(undefined4 *)(param_1[1] + 8) = 0;
  }
  if (*(int *)(param_1[1] + 0xc) != 0) {
    RtlFreeSid(*(int *)(param_1[1] + 0xc));
    *(undefined4 *)(param_1[1] + 0xc) = 0;
  }
  if (*(int *)param_1[2] != 0) {
    RtlFreeSid(*(int *)param_1[2]);
    *(undefined4 *)param_1[2] = 0;
  }
  iVar1 = *(int *)(param_1[2] + 4);
  if (iVar1 != 0) {
    uVar2 = 0;
    uVar1 = FUN_662069c0();
    RtlFreeHeap(uVar1,uVar2,iVar1);
    *(undefined4 *)(param_1[2] + 4) = 0;
  }
  iVar1 = *(int *)(param_1[2] + 8);
  if (iVar1 != 0) {
    uVar2 = 0;
    uVar1 = FUN_662069c0();
    RtlFreeHeap(uVar1,uVar2,iVar1);
    *(undefined4 *)(param_1[2] + 8) = 0;
  }
  *param_1 = ZEXT816(0);
  *(undefined4 *)param_1[1] = 0;
  return;
}



int __thiscall FUN_6620b600(void *this,undefined4 param_1,undefined4 param_2)

{
  bool bVar1;
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 s14;
  undefined2 s10;
  undefined4 sc;
  undefined2 s8;
  
  FUN_6620b7a0((undefined (*) [16])this);
  iVar1 = RtlCreateSecurityDescriptor(this,1);
  if (-1 < iVar1) {
    sc = 0;
    s8 = 0x500;
    iVar1 = RtlAllocateAndInitializeSid(&sc,1,0x12,0,0,0,0,0,0,0,(int)this + 0x14);
    if ((-1 < iVar1) &&
       (iVar1 = RtlAllocateAndInitializeSid(&sc,2,0x20,0x220,0,0,0,0,0,0,(int)this + 0x18),
       -1 < iVar1)) {
      s14 = 0;
      s10 = 0x100;
      iVar1 = RtlAllocateAndInitializeSid(&s14,1,0,0,0,0,0,0,0,0,(int)this + 0x1c);
      if (-1 < iVar1) {
        iVar1 = RtlLengthSid(*(undefined4 *)((int)this + 0x1c));
        iVar2 = RtlLengthSid(*(undefined4 *)((int)this + 0x18));
        iVar3 = RtlLengthSid(*(undefined4 *)((int)this + 0x14));
        iVar2 = iVar1 + iVar2 + iVar3 + 0x20;
        uVar2 = 0;
        iVar1 = iVar2;
        uVar1 = FUN_662069c0();
        iVar1 = RtlAllocateHeap(uVar1,uVar2,iVar1);
        *(int *)((int)this + 0x24) = iVar1;
        if (iVar1 == 0) {
          FUN_6620b7a0((undefined (*) [16])this);
          return -0x3fffff66;
        }
        iVar1 = RtlCreateAcl(iVar1,iVar2,2);
        if ((((-1 < iVar1) &&
             (iVar1 = RtlAddAccessAllowedAce
                                (*(undefined4 *)((int)this + 0x24),2,param_2,
                                 *(undefined4 *)((int)this + 0x14)), -1 < iVar1)) &&
            (iVar1 = RtlAddAccessAllowedAce
                               (*(undefined4 *)((int)this + 0x24),2,param_2,
                                *(undefined4 *)((int)this + 0x18)), -1 < iVar1)) &&
           ((iVar1 = RtlAddAccessAllowedAce
                               (*(undefined4 *)((int)this + 0x24),2,param_1,
                                *(undefined4 *)((int)this + 0x1c)), -1 < iVar1 &&
            (iVar1 = RtlSetDaclSecurityDescriptor(this,1,*(undefined4 *)((int)this + 0x24),0),
            -1 < iVar1)))) {
          bVar1 = FUN_66202da0((int *)&DAT_6624b2f8);
          if (bVar1 != false) {
            iVar1 = FUN_6620b840(this,0x1000,1);
          }
          if (-1 < iVar1) {
            return iVar1;
          }
        }
      }
    }
  }
  FUN_6620b7a0((undefined (*) [16])this);
  return iVar1;
}



void __fastcall FUN_6620b7a0(undefined (*param_1) [16])

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar1;
  
  if (*(int *)(param_1[1] + 4) != 0) {
    RtlFreeSid(*(int *)(param_1[1] + 4));
    *(undefined4 *)(param_1[1] + 4) = 0;
  }
  if (*(int *)(param_1[1] + 8) != 0) {
    RtlFreeSid(*(int *)(param_1[1] + 8));
    *(undefined4 *)(param_1[1] + 8) = 0;
  }
  if (*(int *)(param_1[1] + 0xc) != 0) {
    RtlFreeSid(*(int *)(param_1[1] + 0xc));
    *(undefined4 *)(param_1[1] + 0xc) = 0;
  }
  if (*(int *)param_1[2] != 0) {
    RtlFreeSid(*(int *)param_1[2]);
    *(undefined4 *)param_1[2] = 0;
  }
  iVar1 = *(int *)(param_1[2] + 4);
  if (iVar1 != 0) {
    uVar2 = 0;
    uVar1 = FUN_662069c0();
    RtlFreeHeap(uVar1,uVar2,iVar1);
    *(undefined4 *)(param_1[2] + 4) = 0;
  }
  iVar1 = *(int *)(param_1[2] + 8);
  if (iVar1 != 0) {
    uVar2 = 0;
    uVar1 = FUN_662069c0();
    RtlFreeHeap(uVar1,uVar2,iVar1);
    *(undefined4 *)(param_1[2] + 8) = 0;
  }
  *param_1 = ZEXT816(0);
  *(undefined4 *)param_1[1] = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __thiscall FUN_6620b840(void *this,undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  bool bVar1;
  int iVar1;
  int iVar2;
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 sc;
  undefined2 s8;
  
  bVar1 = FUN_66202da0((int *)&DAT_6624b2f8);
  if (bVar1 == false) {
    return -0x3fffff45;
  }
  puVar1 = (undefined4 *)((int)this + 0x20);
  sc = 0;
  s8 = 0x1000;
  iVar1 = RtlAllocateAndInitializeSid(&sc,1,param_1,0,0,0,0,0,0,0,puVar1);
  if (-1 < iVar1) {
    iVar2 = RtlLengthSid(*puVar1);
    uVar2 = 0;
    iVar1 = iVar2 + 0x10;
    uVar1 = FUN_662069c0();
    iVar1 = RtlAllocateHeap(uVar1,uVar2,iVar1);
    *(int *)((int)this + 0x28) = iVar1;
    if (iVar1 == 0) {
      return -0x3fffff66;
    }
    iVar1 = RtlCreateAcl(iVar1,iVar2 + 0x10,2);
    if ((-1 < iVar1) &&
       (iVar1 = (*_DAT_66222870)(*(undefined4 *)((int)this + 0x28),2,0,*puVar1,0x11,param_2),
       -1 < iVar1)) {
      iVar2 = RtlSetSaclSecurityDescriptor(this,1,*(undefined4 *)((int)this + 0x28),0);
      iVar1 = 0;
      if (iVar2 < 0) {
        iVar1 = iVar2;
      }
    }
  }
  return iVar1;
}



undefined4 __fastcall FUN_6620b910(undefined4 param_1)

{
  return param_1;
}



void FUN_6620b920(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  undefined4 *s34 [10];
  uint sc;
  undefined4 *s8;
  
  s34[6] = (undefined4 *)0x0;
  s34[7] = (undefined4 *)0x0;
  sc = 0;
  s8 = (undefined4 *)&stack0x00000010;
  for (; (sc < 4 && (param_3 != 0)); param_3 = param_3 - 1) {
    s34[sc * 2] = (undefined4 *)*s8;
    s34[(sc * 2) + 1] = (undefined4 *)s8[1];
    sc = sc + 1;
    s8 = s8 + 2;
  }
  s34[8] = s8;
  if ((param_3 & 1) != 0) {
    param_3 = param_3 + 1;
  }
  for (; param_3 != 0; param_3 = param_3 - 1) {
  }
  iVar1 = 4;
  do {
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}



undefined8 FUN_6620ba50(void)

{
  return 0;
}



int __thiscall FUN_6620ba90(void *this,void *param_1)

{
  void *pvVar1;
  int iVar1;
  uint uVar1;
  uint uVar2;
  int iVar2;
  uint *puVar1;
  longlong lVar1;
  undefined s4c [20];
  uint s38 [2];
  uint s30;
  uint s2c;
  uint s28;
  int s24;
  uint s20;
  int s1c;
  uint s18;
  uint s14;
  void *s10;
  uint sc;
  uint s8;
  
  s10 = this;
  lVar1 = FUN_6620ba50();
  iVar1 = FUN_66208e70(param_1,(uint)(lVar1 + 0x60),(uint)((ulonglong)(lVar1 + 0x60) >> 0x20),
                       (int)&s20,8,0);
  if (-1 < iVar1) {
    *(uint *)((int)this + 8) = s20;
    *(int *)((int)this + 0xc) = s1c;
    iVar1 = FUN_66208e70(param_1,s20 + 0x18,s1c + (uint)(0xffffffe7 < s20),(int)&s28,8,0);
    if (-1 < iVar1) {
      uVar2 = s28 + 0x30;
      *(undefined4 *)((int)this + 0x10) = 0;
      uVar1 = s24 + (uint)(0xffffffcf < s28);
      puVar1 = (uint *)((int)this + 0x10);
      *(undefined4 *)((int)this + 0x14) = 0;
      s18 = uVar2;
      s14 = uVar1;
      s8 = uVar2;
      iVar1 = FUN_66208e70(param_1,uVar2,uVar1,(int)&s18,8,0);
      while (-1 < iVar1) {
        if ((s18 == uVar2) && (s14 == uVar1)) {
LAB_6620bbfe:
          pvVar1 = s10;
          if ((*puVar1 | *(uint *)((int)this + 0x14)) == 0) {
            return -0x3ffffecb;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(uint *)((int)this + 0x14),1,
                               s_NtGetContextThread_6621d320,(uint *)((int)s10 + 0x48),(char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtSetContextThread_6621d334,(uint *)((int)pvVar1 + 0x50),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtQueryInformationThread_6621d348,(uint *)((int)pvVar1 + 0x58),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtProtectVirtualMemory_6621d364,(uint *)((int)pvVar1 + 0x18),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtWriteVirtualMemory_6621d37c,(uint *)((int)pvVar1 + 0x30),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtMapViewOfSection_6621d394,(uint *)((int)pvVar1 + 0x38),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtAllocateVirtualMemory_6621d3a8,(uint *)((int)pvVar1 + 0x28),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtFreeVirtualMemory_6621d3c0,(uint *)((int)pvVar1 + 0x20),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtUnmapViewOfSection_6621d3d4,(uint *)((int)pvVar1 + 0x40),
                               (char *)0x0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_662089f0(param_1,*puVar1,*(undefined4 *)((int)this + 0x14),1,
                               s_NtQueryVirtualMemory_6621d3ec,(uint *)((int)pvVar1 + 0x60),
                               (char *)0x0);
          if (-1 < iVar1) {
            return 0;
          }
          return iVar1;
        }
        sc = s18 - 0x20;
        iVar2 = s14 - ((s18 < 0x20));
        iVar1 = FUN_66208e70(param_1,s18 + 0x38,iVar2 + (uint)(0xffffffa7 < sc),(int)s38,0x10,0);
        if (iVar1 < 0) {
          return iVar1;
        }
        if ((s38[0] & 0xfffe) == 0x12) {
          iVar1 = FUN_66208e70(param_1,s30,s2c,(int)s4c,s38[0] & 0xffff,0);
          if (iVar1 < 0) {
            return iVar1;
          }
          iVar1 = FUN_66203690(s4c,9,u_ntdll_dll_6621c904,9,1);
          if (iVar1 == 0) {
            iVar1 = FUN_66208e70(param_1,sc + 0x30,iVar2 + (uint)(0xffffffcf < sc),(int)puVar1,8,0);
            if (iVar1 < 0) {
              return iVar1;
            }
            goto LAB_6620bbfe;
          }
        }
        iVar1 = FUN_66208e70(param_1,s18,s14,(int)&s18,8,0);
        uVar2 = s8;
      }
    }
  }
  return iVar1;
}



void __fastcall FUN_6620bd60(int *param_1)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar1;
  undefined4 *in_FS_OFFSET;
  int *s74 [24];
  int s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621baf8;
  *in_FS_OFFSET = &s10;
  uVar1 = AcquireResourceLockWithRetry(param_1);
  if ((char)uVar1 != '\0') {
    s14 = -1;
    uVar2 = FUN_66202dc0((int *)&DAT_6624b2f8);
    if ((char)uVar2 != '\0') {
      uVar1 = FUN_66202d20((int *)&DAT_6624b2f8);
      if (((char)uVar1 != '\0') &&
         (iVar1 = NtDuplicateObject(0xffffffff,0xffffffff,0xffffffff,&s14,0,0,2), iVar1 < 0)) {
        s14 = -1;
      }
      FUN_66207c60(s74,s14,1);
      s8 = 0;
      iVar1 = FUN_6620ba90(param_1,s74);
      if (s14 != -1) {
        NtClose(s14);
      }
      if (iVar1 < 0) {
        DisplayHardErrorAndTerminate(s_Wow64_cpp_6621d314,0x204,(short *)0x0);
      }
      s8 = 0xffffffff;
      FUN_66207e40(s74);
    }
    FUN_66202d10(param_1);
  }
  *in_FS_OFFSET = s10;
  return;
}



int __thiscall
FUN_6620be50(void *this,undefined4 param_1,uint *param_2,uint *param_3,undefined4 param_4,
            undefined4 param_5)

{
  int iVar1;
  uint uVar1;
  uint uVar2;
  bool bVar1;
  
  uVar2 = *param_3 + *param_2;
  uVar1 = param_3[1] + param_2[1] + (uint)CARRY4(*param_3,*param_2);
  bVar1 = uVar1 < param_2[1];
  if (((bVar1) || (((bVar1 || (uVar1 == param_2[1]) && (uVar2 < *param_2)) || (1 < uVar1)))) ||
     ((uVar1 != 0 && (uVar2 != 0)))) {
    FUN_6620bd60((int *)this);
    if ((*(uint *)((int)this + 0x18) | *(uint *)((int)this + 0x1c)) == 0) {
      return -0x3ffffff3;
    }
    iVar1 = FUN_6620b920(*(undefined4 *)((int)this + 0x18),*(uint *)((int)this + 0x1c),5);
    if (iVar1 < 0) {
      return iVar1;
    }
  }
  else {
    iVar1 = NtProtectVirtualMemory(param_1,param_2,param_3,param_4,param_5);
    if (iVar1 < 0) {
      return iVar1;
    }
  }
  return 0;
}



undefined4 __fastcall
FUN_6620bef0(int *param_1,undefined param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_66202dc0((int *)&DAT_6624b2f8);
  if ((char)uVar1 == '\0') {
    uVar2 = DisplayHardErrorAndTerminate(s_Wow64_cpp_6621d314,0x260,(short *)0x0);
    return uVar2;
  }
  FUN_6620bd60(param_1);
  if ((param_1[0x18] | param_1[0x19]) == 0) {
    return 0xc000000d;
  }
  uVar2 = FUN_6620b920(param_1[0x18],param_1[0x19],6);
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __thiscall
FUN_6620bf70(void *this,undefined4 param_1,uint param_2,uint param_3,undefined4 param_4,uint param_5
            ,uint param_6)

{
  uint uVar1;
  uint uVar2;
  bool bVar1;
  int iVar1;
  uint uVar3;
  uint s10;
  uint sc;
  
  bVar1 = FUN_6620b4d0();
  uVar2 = param_6;
  uVar1 = param_5;
  if (bVar1 != false) {
    iVar1 = (*_DAT_66222874)(param_1,param_2,param_3,param_4,param_5,param_6,&param_5);
    if (iVar1 < 0) {
      return iVar1;
    }
    if (param_5 != uVar1) {
      return -0x3ffffffc;
    }
    if (param_6 != uVar2) {
      return -0x3ffffffc;
    }
  }
  uVar3 = param_3 + uVar2 + (uint)CARRY4(param_2,uVar1);
  if ((uVar3 < param_3) ||
     ((((uVar3 <= param_3 && ((param_2 + uVar1) < param_2)) || (1 < uVar3)) ||
      ((uVar3 != 0 && (param_2 + uVar1 != 0)))))) {
    FUN_6620bd60((int *)this);
    param_6 = *(uint *)((int)this + 0x30);
    if ((param_6 | *(uint *)((int)this + 0x34)) == 0) {
      return -0x3ffffff3;
    }
    iVar1 = FUN_6620b920(param_6,*(uint *)((int)this + 0x34),5);
    if (iVar1 < 0) {
      return iVar1;
    }
    if ((s10 == uVar1) && (sc == uVar2)) {
      return 0;
    }
  }
  else {
    iVar1 = NtWriteVirtualMemory(param_1,param_2,param_4,uVar1,&param_3);
    if (iVar1 < 0) {
      return iVar1;
    }
    if ((param_3 == uVar1) && (uVar2 == 0)) {
      return 0;
    }
  }
  return -0x3ffffffc;
}


/*
Unable to decompile 'FUN_6620c070'
Cause: Exception while decompiling 6620c070: Decompiler process died

*/


// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_6620c120(undefined4 *param_1)

{
  LPCSTR pCVar1;
  uint uVar1;
  FARPROC pFVar1;
  SchedulerPolicy *this;
  SchedulerPolicy *this_00;
  LPCSTR *ppCVar1;
  undefined4 *in_FS_OFFSET;
  LPCWSTR s17c [44];
  short *scc [44];
  HMODULE s1c;
  undefined *s18;
  undefined s14;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  s10 = *in_FS_OFFSET;
  s8 = 0xffffffff;
  puStack12 = &LAB_6621bb39;
  *in_FS_OFFSET = &s10;
  if (*(char *)(param_1 + 2) == '\0') {
    s18 = &DAT_6624b570;
    s14 = 0;
    AcquireCriticalSectionWithLock((int)&DAT_6624b570);
    s14 = 1;
    s8 = 0;
    if (*(int *)param_1[1] != 0) {
      FUN_66202ff0(s17c,*param_1,0xffffffff);
      s8._0_1_ = 1;
      s1c = LoadLibraryW(s17c[0]);
      if (s1c == (HMODULE)0x0) {
        reset_flags_clean_memory(scc);
        s8._0_1_ = 2;
        Concurrency::SchedulerPolicy::SchedulerPolicy
                  (this,(unsigned_int)scc,u_Unable_to_load__ls_6621d420,s17c[0]);
        DisplayHardErrorAndTerminate(s_InlineHook_cpp_6621d448,0x20,scc[0]);
        s8._0_1_ = 1;
        manage_memstate(scc);
      }
      else {
        uVar1 = GetSystemInfoFlags();
        ppCVar1 = (LPCSTR *)param_1[1];
        pCVar1 = *ppCVar1;
        while (pCVar1 != (LPCSTR)0x0) {
          if (((*(ushort *)(ppCVar1 + 5) <= (ushort)uVar1) &&
              ((ushort)uVar1 < *(ushort *)((int)ppCVar1 + 0x16))) &&
             ((*(char *)(ppCVar1 + 6) == '\0' || (*(char *)(ppCVar1 + 6) == ' ')))) {
            pFVar1 = GetProcAddress(s1c,*ppCVar1);
            if (pFVar1 == (FARPROC)0x0) {
              if (*(char *)((int)ppCVar1 + 0x1a) == '\0') {
                reset_flags_clean_memory(scc);
                s8._0_1_ = 3;
                Concurrency::SchedulerPolicy::SchedulerPolicy
                          (this_00,(unsigned_int)scc,u_Unable_to_find__hs_in__ls_6621d458,*ppCVar1,
                           s17c[0]);
                DisplayHardErrorAndTerminate(s_InlineHook_cpp_6621d448,0x43,scc[0]);
                s8._0_1_ = 1;
                manage_memstate(scc);
                break;
              }
            }
            else {
              ppCVar1[3] = (LPCSTR)pFVar1;
            }
          }
          ppCVar1 = ppCVar1 + 7;
          pCVar1 = *ppCVar1;
        }
      }
      *(undefined *)(param_1 + 2) = 1;
      s8 = (uint)s8._1_3_ << 8;
      manage_memstate(s17c);
    }
    s8 = 0xffffffff;
    s14 = 0;
    ReleaseCriticalSection(&DAT_6624b570);
  }
  *in_FS_OFFSET = s10;
  return;
}



int FUN_6620c2d0(uint *param_1,char *param_2)

{
  char cVar1;
  uint uVar1;
  int iVar1;
  int iVar2;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar1;
  char *pcVar2;
  bool bVar1;
  char s10;
  int sc;
  int s8;
  
  uVar2 = 0x80000000;
  s8 = 8;
  uVar3 = 1;
  pcVar2 = param_2;
LAB_6620c300:
  do {
    while( true ) {
      bVar1 = CARRY4(uVar2,uVar2);
      uVar2 = uVar2 * 2;
      if (uVar2 == 0) {
        uVar2 = *param_1;
        param_1 = param_1 + 1;
        bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
        uVar2 = (uVar2 * 2) + 1;
      }
      if (!bVar1) break;
      cVar1 = '\0';
      iVar1 = sc;
      do {
        bVar1 = CARRY4(uVar2,uVar2);
        uVar2 = uVar2 * 2;
        if (uVar2 == 0) {
          uVar2 = *param_1;
          param_1 = param_1 + 1;
          bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
          uVar2 = (uVar2 * 2) + 1;
        }
        cVar1 = (cVar1 * '\x02') + bVar1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
      uVar1 = (uint)(byte)(cVar1 + s10);
LAB_6620c335:
      *pcVar2 = (char)uVar1;
      pcVar2 = pcVar2 + 1;
    }
    bVar1 = CARRY4(uVar2,uVar2);
    uVar2 = uVar2 * 2;
    if (uVar2 == 0) {
      uVar2 = *param_1;
      param_1 = param_1 + 1;
      bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
      uVar2 = (uVar2 * 2) + 1;
    }
    if (bVar1) {
      iVar1 = 1;
      do {
        bVar1 = CARRY4(uVar2,uVar2);
        uVar2 = uVar2 * 2;
        if (uVar2 == 0) {
          uVar2 = *param_1;
          param_1 = param_1 + 1;
          bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
          uVar2 = (uVar2 * 2) + 1;
        }
        iVar1 = (iVar1 * 2) + (uint)bVar1;
        bVar1 = CARRY4(uVar2,uVar2);
        uVar2 = uVar2 * 2;
        if (uVar2 == 0) {
          uVar2 = *param_1;
          param_1 = param_1 + 1;
          bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
          uVar2 = (uVar2 * 2) + 1;
        }
      } while (bVar1);
      if (iVar1 == 2) {
        iVar2 = 1;
        do {
          bVar1 = CARRY4(uVar2,uVar2);
          uVar2 = uVar2 * 2;
          if (uVar2 == 0) {
            uVar2 = *param_1;
            param_1 = param_1 + 1;
            bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
            uVar2 = (uVar2 * 2) + 1;
          }
          iVar2 = (iVar2 * 2) + (uint)bVar1;
          bVar1 = CARRY4(uVar2,uVar2);
          uVar2 = uVar2 * 2;
          if (uVar2 == 0) {
            uVar2 = *param_1;
            param_1 = param_1 + 1;
            bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
            uVar2 = (uVar2 * 2) + 1;
          }
          uVar1 = uVar3;
          uVar4 = uVar3;
        } while (bVar1);
      }
      else {
        uVar1 = 0;
        iVar2 = s8;
        do {
          bVar1 = CARRY4(uVar2,uVar2);
          uVar2 = uVar2 * 2;
          if (uVar2 == 0) {
            uVar2 = *param_1;
            param_1 = param_1 + 1;
            bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
            uVar2 = (uVar2 * 2) + 1;
          }
          uVar1 = (uVar1 * 2) + (uint)bVar1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
        uVar1 = uVar1 | ((iVar1 + -3) << ((byte)s8 & 0x1f));
        iVar2 = 1;
        do {
          bVar1 = CARRY4(uVar2,uVar2);
          uVar2 = uVar2 * 2;
          if (uVar2 == 0) {
            uVar2 = *param_1;
            param_1 = param_1 + 1;
            bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
            uVar2 = (uVar2 * 2) + 1;
          }
          iVar2 = (iVar2 * 2) + (uint)bVar1;
          bVar1 = CARRY4(uVar2,uVar2);
          uVar2 = uVar2 * 2;
          if (uVar2 == 0) {
            uVar2 = *param_1;
            param_1 = param_1 + 1;
            bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
            uVar2 = (uVar2 * 2) + 1;
          }
        } while (bVar1);
        uVar3 = uVar1;
        if (uVar1 < 0x10000) {
          if (uVar1 < 0x37ff) {
            if (0x27e < uVar1) goto LAB_6620c579;
            uVar4 = uVar1;
            if (0x7f < uVar1) goto LAB_6620c57a;
            iVar2 = iVar2 + 1;
            goto LAB_6620c577;
          }
        }
        else {
LAB_6620c577:
          iVar2 = iVar2 + 1;
        }
        iVar2 = iVar2 + 1;
LAB_6620c579:
        iVar2 = iVar2 + 1;
        uVar4 = uVar3;
      }
LAB_6620c57a:
      pcVar1 = pcVar2 + -uVar1;
      for (; uVar3 = uVar4, iVar2 != 0; iVar2 = iVar2 + -1) {
        *pcVar2 = *pcVar1;
        pcVar1 = pcVar1 + 1;
        pcVar2 = pcVar2 + 1;
      }
      goto LAB_6620c300;
    }
    bVar1 = CARRY4(uVar2,uVar2);
    uVar2 = uVar2 * 2;
    if (uVar2 == 0) {
      uVar2 = *param_1;
      param_1 = param_1 + 1;
      bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
      uVar2 = (uVar2 * 2) + 1;
    }
    if (bVar1) {
      iVar2 = 4;
      iVar1 = 0;
      do {
        bVar1 = CARRY4(uVar2,uVar2);
        uVar2 = uVar2 * 2;
        if (uVar2 == 0) {
          uVar2 = *param_1;
          param_1 = param_1 + 1;
          bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
          uVar2 = (uVar2 * 2) + 1;
        }
        iVar1 = (iVar1 * 2) + (uint)bVar1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      uVar1 = iVar1 - 1;
      if (uVar1 == 0) goto LAB_6620c335;
      if (-1 < (int)uVar1) goto LAB_6620c579;
      bVar1 = CARRY4(uVar2,uVar2);
      uVar2 = uVar2 * 2;
      if (uVar2 == 0) {
        uVar2 = *param_1;
        param_1 = param_1 + 1;
        bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
        uVar2 = (uVar2 * 2) + 1;
      }
      if (bVar1) {
        do {
          iVar1 = 0x100;
          do {
            iVar2 = 8;
            cVar1 = '\0';
            do {
              bVar1 = CARRY4(uVar2,uVar2);
              uVar2 = uVar2 * 2;
              if (uVar2 == 0) {
                uVar2 = *param_1;
                param_1 = param_1 + 1;
                bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
                uVar2 = (uVar2 * 2) + 1;
              }
              cVar1 = (cVar1 * '\x02') + bVar1;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
            *pcVar2 = cVar1;
            pcVar2 = pcVar2 + 1;
            iVar1 = iVar1 + -1;
          } while (iVar1 != 0);
          bVar1 = CARRY4(uVar2,uVar2);
          uVar2 = uVar2 * 2;
          if (uVar2 == 0) {
            uVar2 = *param_1;
            param_1 = param_1 + 1;
            bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
            uVar2 = (uVar2 * 2) + 1;
          }
        } while (bVar1);
      }
      else {
        iVar2 = 1;
        iVar1 = 0;
        do {
          bVar1 = CARRY4(uVar2,uVar2);
          uVar2 = uVar2 * 2;
          if (uVar2 == 0) {
            uVar2 = *param_1;
            param_1 = param_1 + 1;
            bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
            uVar2 = (uVar2 * 2) + 1;
          }
          iVar1 = (iVar1 * 2) + (uint)bVar1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
        sc = iVar1 + 7;
        s10 = '\0';
        if (sc != 8) {
          s10 = '\0';
          iVar1 = 8;
          do {
            bVar1 = CARRY4(uVar2,uVar2);
            uVar2 = uVar2 * 2;
            if (uVar2 == 0) {
              uVar2 = *param_1;
              param_1 = param_1 + 1;
              bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
              uVar2 = (uVar2 * 2) + 1;
            }
            s10 = (s10 * '\x02') + bVar1;
            iVar1 = iVar1 + -1;
          } while (iVar1 != 0);
        }
      }
    }
    else {
      iVar1 = 7;
      uVar1 = 0;
      do {
        bVar1 = CARRY4(uVar2,uVar2);
        uVar2 = uVar2 * 2;
        if (uVar2 == 0) {
          uVar2 = *param_1;
          param_1 = param_1 + 1;
          bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
          uVar2 = (uVar2 * 2) + 1;
        }
        uVar1 = (uVar1 * 2) + (uint)bVar1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
      iVar2 = 2;
      iVar1 = 0;
      do {
        bVar1 = CARRY4(uVar2,uVar2);
        uVar2 = uVar2 * 2;
        if (uVar2 == 0) {
          uVar2 = *param_1;
          param_1 = param_1 + 1;
          bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
          uVar2 = (uVar2 * 2) + 1;
        }
        iVar1 = (iVar1 * 2) + (uint)bVar1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      iVar2 = iVar1 + 2;
      uVar4 = uVar1;
      if (uVar1 != 0) goto LAB_6620c57a;
      if (iVar2 == 2) {
        return (int)pcVar2 - (int)param_2;
      }
      iVar1 = iVar1 + 3;
      s8 = 0;
      do {
        bVar1 = CARRY4(uVar2,uVar2);
        uVar2 = uVar2 * 2;
        if (uVar2 == 0) {
          uVar2 = *param_1;
          param_1 = param_1 + 1;
          bVar1 = CARRY4(uVar2,uVar2) || (0xfffffffe < (uVar2 * 2));
          uVar2 = (uVar2 * 2) + 1;
        }
        s8 = (s8 * 2) + (uint)bVar1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
  } while( true );
}



void Wsafe_malloc(size_t param_1)

{
                    // This is a wrapper
  safe_malloc(param_1);
  return;
}



// Library Function - Single Match
//  char * __cdecl std::_Allocate<char>(unsigned int,char *)
// 
// Library: Visual Studio 2012 Release

char * __cdecl std::_Allocate_char_(unsigned_int param_1,char *param_2)

{
  char *pcVar1;
  
  pcVar1 = (char *)0x0;
  if ((param_1 != 0) && (pcVar1 = (char *)safe_malloc(param_1), pcVar1 == (char *)0x0)) {
    pcVar1 = (char *)raise_fatal_allocation_exception();
    return pcVar1;
  }
  return pcVar1;
}



// Library Function - Single Match
//  public: __thiscall std::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>>::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>>(char const *)
// 
// Library: Visual Studio 2015 Release

basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ * __thiscall
std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
basic_string_char_struct_std__char_traits_char__class_std__allocator_char___
          (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *this,
          char *param_1)

{
  unsigned_int uVar1;
  
  *(undefined4 *)(this + 0x10) = 0;
  *(undefined4 *)(this + 0x14) = 0xf;
  *this = (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___)0x0;
  uVar1 = char_traits<char>::length(param_1);
  assign(this,param_1,uVar1);
  return this;
}



undefined ** __thiscall FUN_6620c5f9(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_6621d490;
  return (undefined **)this;
}



undefined ** __thiscall FUN_6620c614(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_6621d4b8;
  return (undefined **)this;
}



undefined ** __thiscall FUN_6620c62f(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_6621d4ac;
  return (undefined **)this;
}



undefined ** __thiscall FUN_6620c64a(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_6621d4c4;
  return (undefined **)this;
}



// Library Function - Single Match
//  public: bool __thiscall std::error_condition::operator==(class std::error_condition const
// &)const 
// 
// Library: Visual Studio 2012 Release

bool __thiscall std::error_condition::operator__(error_condition *this,error_condition *param_1)

{
  bool bVar1;
  
  if ((*(int *)(this + 4) == *(int *)(param_1 + 4)) && (*(int *)this == *(int *)param_1)) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}


/*
Unable to decompile 'FUN_6620c694'
Cause: Exception while decompiling 6620c694: Decompiler process died

*/

/*
Unable to decompile 'FUN_6620c6b4'
Cause: Exception while decompiling 6620c6b4: Decompiler process died

*/

/*
Unable to decompile 'FUN_6620c6d9'
Cause: Exception while decompiling 6620c6d9: Decompiler process died

*/


// WARNING: Function: __EH_prolog3_catch replaced with injection: EH_prolog3
// WARNING: Function: __EH_epilog3 replaced with injection: EH_epilog3

void __thiscall FUN_6620c6f8(void *this,char *param_1,char *param_2)

{
  uint uVar1;
  uint uVar2;
  void *pvVar1;
  char *pcVar1;
  
  pcVar1 = (char *)((uint)param_1 | 0xf);
  if (pcVar1 != (char *)0xffffffff) {
    uVar1 = *(uint *)((int)this + 0x14);
    uVar2 = uVar1 >> 1;
    param_1 = pcVar1;
    if (((uint)pcVar1 / 3) < uVar2) {
      if ((-uVar2 - 2) < uVar1) {
        param_1 = (char *)0xfffffffe;
      }
      else {
        param_1 = (char *)(uVar2 + uVar1);
      }
    }
  }
  pcVar1 = std::_Allocate_char_((unsigned_int)(param_1 + 1),(char *)0x0);
  if (param_2 != (char *)0x0) {
    pvVar1 = this;
    if (0xf < *(uint *)((int)this + 0x14)) {
                    // WARNING: Load size is inaccurate
      pvVar1 = *this;
    }
    if (param_2 != (char *)0x0) {
      FUN_6620d5b0(pcVar1,pvVar1,param_2);
    }
  }
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            ((basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)this,
             true,0);
  if (this != (void *)0x0) {
    *(char **)this = pcVar1;
  }
  *(char **)((int)this + 0x14) = param_1;
  *(char **)((int)this + 0x10) = param_2;
  if ((char *)0xf < param_1) {
                    // WARNING: Load size is inaccurate
    this = *this;
  }
  *(char *)((int)this + (int)param_2) = '\0';
  return;
}



uint __thiscall FUN_6620c7ef(void *this,char *param_1,char param_2)

{
  code *pcVar1;
  char *pcVar2;
  uint uVar1;
  
  if (param_1 != (char *)0xffffffff) {
    if (*(char **)((int)this + 0x14) < param_1) {
      FUN_6620c6f8(this,param_1,*(char **)((int)this + 0x10));
    }
    else if ((param_2 == '\0') || ((char *)0xf < param_1)) {
      if (param_1 == (char *)0x0) {
        *(undefined4 *)((int)this + 0x10) = 0;
        if (0xf < *(uint *)((int)this + 0x14)) {
                    // WARNING: Load size is inaccurate
          this = *this;
        }
        *(undefined *)this = 0;
      }
    }
    else {
      pcVar2 = *(char **)((int)this + 0x10);
      if (param_1 < *(char **)((int)this + 0x10)) {
        pcVar2 = param_1;
      }
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                ((basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)
                 this,true,(unsigned_int)pcVar2);
    }
    return (uint)(param_1 != (char *)0x0);
  }
  FUN_6620c903(s_string_too_long_6621d580);
  pcVar1 = (code *)swi(3);
  uVar1 = (*pcVar1)();
  return uVar1;
}



// Library Function - Single Match
//  public: bool __thiscall std::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>>::_Inside(char const *)
// 
// Library: Visual Studio 2015 Release

bool __thiscall
std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Inside
          (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *this,
          char *param_1)

{
  basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *pbVar1;
  
  if (param_1 != (char *)0x0) {
    pbVar1 = this;
    if (0xf < *(uint *)(this + 0x14)) {
      pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                this;
    }
    if (pbVar1 <= param_1) {
      pbVar1 = this;
      if (0xf < *(uint *)(this + 0x14)) {
        pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                  this;
      }
      if (param_1 < (pbVar1 + *(int *)(this + 0x10))) {
        return true;
      }
    }
  }
  return false;
}



// Library Function - Single Match
//  public: void __thiscall std::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>>::_Tidy(bool,unsigned int)
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2019 Release

void __thiscall
std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
          (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *this,
          bool param_1,unsigned_int param_2)

{
  void *_Memory;
  
  if ((param_1 != false) && (0xf < *(uint *)(this + 0x14))) {
    _Memory = *(void **)this;
    if (param_2 != 0) {
      FUN_6620d5b0(this,_Memory,param_2);
    }
    FID_conflict__free(_Memory);
  }
  *(unsigned_int *)(this + 0x10) = param_2;
  *(undefined4 *)(this + 0x14) = 0xf;
  this[param_2] = (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___)0x0;
  return;
}



void raise_fatal_allocation_exception(void)

{
  code *pcVar1;
  undefined **ctx [3];
  char *s8;
  
  s8 = s__fbad_allocation_6621d496 + 2;
  setup_object_fields(ctx,&s8);
  ctx[0] = &PTR_FUN_6621d490;
  Handle_flags_Raise_exc((int *)ctx,&control_exc_flags);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_6620c903(char *param_1)

{
  code *pcVar1;
  undefined **s10 [3];
  
  std::exception::exception((exception *)s10,&param_1);
  s10[0] = &PTR_FUN_6621d4b8;
  Handle_flags_Raise_exc((int *)s10,&DAT_66223ae4);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_6620c931(char *param_1)

{
  code *pcVar1;
  undefined **s10 [3];
  
  std::exception::exception((exception *)s10,&param_1);
  s10[0] = &PTR_FUN_6621d4c4;
  Handle_flags_Raise_exc((int *)s10,&DAT_66223b20);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined4 * __thiscall FUN_6620c95f(void *this,undefined4 *param_1,uint param_2,char *param_3)

{
  code *pcVar1;
  uint uVar1;
  void *pvVar1;
  undefined4 *puVar1;
  char *pcVar2;
  
  if ((uint)param_1[4] < param_2) {
    FUN_6620c931(s_invalid_string_position_6621d590);
    pcVar1 = (code *)swi(3);
    puVar1 = (undefined4 *)(*pcVar1)();
    return puVar1;
  }
  pcVar2 = (char *)(param_1[4] - param_2);
  if (param_3 < pcVar2) {
    pcVar2 = param_3;
  }
  if ((undefined4 *)this == param_1) {
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::erase
              ((basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)this,
               (unsigned_int)(pcVar2 + param_2));
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::erase
              ((basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)this,
               0,param_2);
  }
  else {
    uVar1 = FUN_6620c7ef(this,pcVar2,'\0');
    if ((char)uVar1 != '\0') {
      if (0xf < (uint)param_1[5]) {
        param_1 = (undefined4 *)*param_1;
      }
      pvVar1 = this;
      if (0xf < *(uint *)((int)this + 0x14)) {
                    // WARNING: Load size is inaccurate
        pvVar1 = *this;
      }
      if (pcVar2 != (char *)0x0) {
        FUN_6620d5b0(pvVar1,param_2 + (int)param_1,pcVar2);
      }
      *(char **)((int)this + 0x10) = pcVar2;
      pvVar1 = this;
      if (0xf < *(uint *)((int)this + 0x14)) {
                    // WARNING: Load size is inaccurate
        pvVar1 = *this;
      }
      *(char *)((int)pvVar1 + (int)pcVar2) = '\0';
    }
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>&
// __thiscall std::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>>::assign(char const *,unsigned int)
// 
// Library: Visual Studio 2015 Release

basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ * __thiscall
std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
          (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *this,
          char *param_1,unsigned_int param_2)

{
  bool bVar1;
  uint uVar1;
  basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *pbVar1;
  
  bVar1 = _Inside(this,param_1);
  if (bVar1 == false) {
    uVar1 = FUN_6620c7ef(this,(char *)param_2,'\0');
    if ((char)uVar1 != '\0') {
      pbVar1 = this;
      if (0xf < *(uint *)(this + 0x14)) {
        pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                  this;
      }
      if (param_2 != 0) {
        FUN_6620d5b0(pbVar1,param_1,param_2);
      }
      *(unsigned_int *)(this + 0x10) = param_2;
      pbVar1 = this;
      if (0xf < *(uint *)(this + 0x14)) {
        pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                  this;
      }
      pbVar1[param_2] =
           (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___)0x0;
    }
  }
  else {
    pbVar1 = this;
    if (0xf < *(uint *)(this + 0x14)) {
      pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                this;
    }
    this = (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)
           FUN_6620c95f(this,(undefined4 *)this,(int)param_1 - (int)pbVar1,(char *)param_2);
  }
  return this;
}



// Library Function - Single Match
//  public: virtual class std::error_condition __thiscall
// std::_System_error_category::default_error_condition(int)const 
// 
// Library: Visual Studio 2012 Release

error_condition __thiscall
std::_System_error_category::default_error_condition(_System_error_category *this,int param_1)

{
  char *pcVar1;
  int in_stack_00000008;
  
  pcVar1 = _Syserror_map(in_stack_00000008);
  *(int *)param_1 = in_stack_00000008;
  if (pcVar1 == (char *)0x0) {
    *(undefined ***)(param_1 + 4) = &PTR_PTR_FUN_66249f78;
  }
  else {
    *(undefined ***)(param_1 + 4) = &PTR_PTR_FUN_66249f70;
  }
  return SUB41(param_1,0);
}



void __thiscall FUN_6620ca99(void *this,undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  param_1[1] = this;
  return;
}



// Library Function - Single Match
//  public: virtual bool __thiscall std::error_category::equivalent(class std::error_code const
// &,int)const 
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

bool __thiscall
std::error_category::equivalent(error_category *this,error_code *param_1,int param_2)

{
  bool bVar1;
  
  if ((this == *(error_category **)(param_1 + 4)) && (*(int *)param_1 == param_2)) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}



void __thiscall FUN_6620cac8(void *this,undefined4 param_1,undefined4 param_2)

{
  error_condition *this_00;
  void **ppvVar1;
  void *sc;
  void *pvStack8;
  
                    // WARNING: Load size is inaccurate
  ppvVar1 = &sc;
  sc = this;
  pvStack8 = this;
  this_00 = (error_condition *)(**(code **)(*this + 0xc))(ppvVar1,param_1,param_2);
  std::error_condition::operator__(this_00,(error_condition *)ppvVar1);
  return;
}



// Library Function - Single Match
//  public: class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>&
// __thiscall std::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>>::erase(unsigned int)
// 
// Library: Visual Studio 2012 Release

basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ * __thiscall
std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::erase
          (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *this,
          unsigned_int param_1)

{
  code *pcVar1;
  basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *pbVar1;
  
  if (*(uint *)(this + 0x10) < param_1) {
    FUN_6620c931(s_invalid_string_position_6621d590);
    pcVar1 = (code *)swi(3);
    pbVar1 = (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)
             (*pcVar1)();
    return pbVar1;
  }
  *(unsigned_int *)(this + 0x10) = param_1;
  pbVar1 = this;
  if (0xf < *(uint *)(this + 0x14)) {
    pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)this;
  }
  pbVar1[param_1] =
       (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___)0x0;
  return this;
}



// Library Function - Single Match
//  public: class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>&
// __thiscall std::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>>::erase(unsigned int,unsigned int)
// 
// Library: Visual Studio 2012 Release

basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ * __thiscall
std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::erase
          (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *this,
          unsigned_int param_1,unsigned_int param_2)

{
  uint uVar1;
  code *pcVar1;
  basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *pbVar1;
  int iVar1;
  
  uVar1 = *(uint *)(this + 0x10);
  if (uVar1 < param_1) {
    FUN_6620c931(s_invalid_string_position_6621d590);
    pcVar1 = (code *)swi(3);
    pbVar1 = (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)
             (*pcVar1)();
    return pbVar1;
  }
  if (param_2 < (uVar1 - param_1)) {
    if (param_2 != 0) {
      pbVar1 = this;
      if (0xf < *(uint *)(this + 0x14)) {
        pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                  this;
      }
      iVar1 = uVar1 - param_2;
      if (iVar1 - param_1 != 0) {
        FUN_6620dc00(pbVar1 + param_1,pbVar1 + param_1 + param_2,iVar1 - param_1);
      }
      *(int *)(this + 0x10) = iVar1;
      pbVar1 = this;
      if (0xf < *(uint *)(this + 0x14)) {
        pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                  this;
      }
      pbVar1[iVar1] =
           (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___)0x0;
    }
  }
  else {
    *(unsigned_int *)(this + 0x10) = param_1;
    pbVar1 = this;
    if (0xf < *(uint *)(this + 0x14)) {
      pbVar1 = *(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ **)
                this;
    }
    pbVar1[param_1] =
         (basic_string_char_struct_std__char_traits_char__class_std__allocator_char___)0x0;
  }
  return this;
}



// Library Function - Single Match
//  public: static unsigned int __cdecl std::char_traits<char>::length(char const *)
// 
// Library: Visual Studio 2012 Release

unsigned_int __cdecl std::char_traits<char>::length(char *param_1)

{
  unsigned_int uVar1;
  
  if (*param_1 == '\0') {
    return 0;
  }
  uVar1 = _strlen(param_1);
  return uVar1;
}



basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *
FUN_6620cbb2(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *param_1,
            int param_2)

{
  char *pcVar1;
  
  pcVar1 = std::_Syserror_map(param_2);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = s_unknown_error_6621d50c;
  }
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
  basic_string_char_struct_std__char_traits_char__class_std__allocator_char___(param_1,pcVar1);
  return param_1;
}



// Library Function - Single Match
//  public: virtual class std::basic_string<char,struct std::char_traits<char>,class
// std::allocator<char>> __thiscall std::_Iostream_error_category::message(int)const 
// 
// Library: Visual Studio 2015 Release

basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ __thiscall
std::_Iostream_error_category::message(_Iostream_error_category *this,int param_1)

{
  int in_stack_00000008;
  
  if (in_stack_00000008 == 1) {
    basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
    basic_string_char_struct_std__char_traits_char__class_std__allocator_char___
              ((basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)
               param_1,s_iostream_stream_error_6621d544);
  }
  else {
    FUN_6620cbb2((basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *)
                 param_1,in_stack_00000008);
  }
  return SUB41(param_1,0);
}



basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *
FUN_6620cc0f(basic_string_char_struct_std__char_traits_char__class_std__allocator_char___ *param_1,
            int param_2)

{
  char *pcVar1;
  
  pcVar1 = (char *)FUN_6620cc77(param_2);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = s_unknown_error_6621d50c;
  }
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
  basic_string_char_struct_std__char_traits_char__class_std__allocator_char___(param_1,pcVar1);
  return param_1;
}



// Library Function - Single Match
//  char const * __cdecl std::_Syserror_map(int)
// 
// Library: Visual Studio 2012 Release

char * __cdecl std::_Syserror_map(int param_1)

{
  int *piVar1;
  int *piVar2;
  
  piVar2 = &DAT_6621d800;
  if (PTR_s_address_family_not_supported_6621d804 != (undefined *)0x0) {
    do {
      if (*piVar2 == param_1) {
        return (char *)piVar2[1];
      }
      piVar1 = piVar2 + 3;
      piVar2 = piVar2 + 2;
    } while (*piVar1 != 0);
  }
  return (char *)0x0;
}



int __cdecl FUN_6620cc77(int param_1)

{
  int *piVar1;
  int *piVar2;
  
  piVar2 = &DAT_6621d5a8;
  if (PTR_s_permission_denied_6621d5ac != (undefined *)0x0) {
    do {
      if (*piVar2 == param_1) {
        return piVar2[1];
      }
      piVar1 = piVar2 + 3;
      piVar2 = piVar2 + 2;
    } while (*piVar1 != 0);
  }
  return 0;
}



// Library Function - Single Match
//  _wcslen
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2015 Release,
// Visual Studio 2019 Release

size_t __cdecl _wcslen(wchar_t *_Str)

{
  wchar_t wVar1;
  wchar_t *pwVar1;
  
  pwVar1 = _Str;
  do {
    wVar1 = *pwVar1;
    pwVar1 = pwVar1 + 1;
  } while (wVar1 != L'\0');
  return (((int)pwVar1 - (int)_Str) >> 1) - 1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_6620ccba(undefined4 param_1,int param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 uVar1;
  int iVar1;
  DWORD *_Memory;
  DWORD DVar1;
  
  if (param_2 == 1) {
    bVar1 = FUN_6620fafd();
    if (((int)(int3)extraout_var << 8) + bVar1 != 0) {
      iVar1 = FUN_6620f67f();
      if (iVar1 != 0) {
        FUN_66210383();
        _DAT_6624d3b8 = GetCommandLineA();
        _DAT_6624b5a8 = returnzero();
        iVar1 = FUN_6620fb1a();
        if (-1 < iVar1) {
          iVar1 = returnzero();
          if (-1 < iVar1) {
            iVar1 = returnzero();
            if (-1 < iVar1) {
              iVar1 = FUN_6620f894(0);
              if (iVar1 == 0) {
                DAT_6624b5a4 = DAT_6624b5a4 + 1;
                goto LAB_6620ce21;
              }
            }
          }
          __ioterm();
        }
        FUN_6620f6f5();
      }
      FUN_6620fb12();
    }
LAB_6620ccd7:
    uVar1 = 0;
  }
  else {
    if (param_2 == 0) {
      if (DAT_6624b5a4 < 1) goto LAB_6620ccd7;
      DAT_6624b5a4 = DAT_6624b5a4 + -1;
      if (_DAT_6624b5dc == 0) {
        __cexit();
      }
      FUN_6620f75c();
      if (param_3 == 0) {
        __ioterm();
        FUN_6620f6f5();
        FUN_6620fb12();
      }
      FUN_6620cd9c();
    }
    else if (param_2 == 2) {
      iVar1 = FUN_6620ff37(DAT_66249f90);
      if (iVar1 == 0) {
        _Memory = (DWORD *)FUN_662102aa(1,0x3bc);
        if (_Memory != (DWORD *)0x0) {
          iVar1 = FUN_6620ff56(DAT_66249f90,_Memory);
          if (iVar1 != 0) {
            FUN_6620f5cc((int)_Memory,0);
            DVar1 = GetCurrentThreadId();
            *_Memory = DVar1;
            _Memory[1] = 0xffffffff;
            goto LAB_6620ce21;
          }
          FID_conflict__free(_Memory);
        }
        goto LAB_6620ccd7;
      }
    }
    else if (param_2 == 3) {
      FUN_6620f50f((void *)0x0);
    }
LAB_6620ce21:
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_6620cd9c(void)

{
  int unaff_ESI;
  
  if ((unaff_ESI == 0) && (DAT_66249f90 != -1)) {
    FUN_6620f6f5();
  }
  return;
}



// Library Function - Single Match
//  __DllMainCRTStartup@12
// 
// Library: Visual Studio 2012 Release

void __DllMainCRTStartup_12(undefined4 param_1,int param_2,int param_3)

{
  if (param_2 == 1) {
    ___security_init_cookie();
  }
  ___DllMainCRTStartup(param_1,param_2,param_3);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___DllMainCRTStartup
// 
// Library: Visual Studio 2012 Release

uint __cdecl ___DllMainCRTStartup(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar1;
  
  iVar1 = 1;
  if ((param_2 == 0) && (DAT_6624b5a4 == 0)) {
LAB_6620cf55:
    uVar1 = 0;
  }
  else {
    if ((param_2 == 1) || (param_2 == 2)) {
      if (DAT_6621e300 != (code *)0x0) {
        iVar1 = (*DAT_6621e300)(param_1,param_2,param_3);
      }
      if ((iVar1 == 0) || (iVar1 = FUN_6620ccba(param_1,param_2,param_3), iVar1 == 0))
      goto LAB_6620cf55;
    }
    uVar1 = FUN_6620fef4();
    if ((param_2 == 1) && (uVar1 == 0)) {
      FUN_6620fef4();
      FUN_6620ccba(param_1,0,param_3);
      if (DAT_6621e300 != (code *)0x0) {
        (*DAT_6621e300)(param_1,0,param_3);
      }
    }
    if ((param_2 == 0) || (param_2 == 3)) {
      iVar1 = FUN_6620ccba(param_1,param_2,param_3);
      uVar1 = uVar1 & -(uint)(iVar1 != 0);
      if ((uVar1 != 0) && (DAT_6621e300 != (code *)0x0)) {
        uVar1 = (*DAT_6621e300)(param_1,param_2,param_3);
      }
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  ___DllXcptFilter
// 
// Library: Visual Studio 2012 Release

void __cdecl
___DllXcptFilter(undefined4 param_1,int param_2,int param_3,ulong param_4,
                _EXCEPTION_POINTERS *param_5)

{
  if (param_2 == 1) {
    FUN_6620ccba(param_1,0,param_3);
  }
  ___CppXcptFilter(param_4,param_5);
  return;
}



void init_proc(void)

{
  undefined4 in_FS_OFFSET;
  undefined auStack12 [12];
  
  *(undefined **)in_FS_OFFSET = auStack12;
  return;
}



void __cdecl FUN_6620cfa3(undefined4 param_1,uint param_2,undefined4 param_3)

{
  undefined in_DL;
  undefined1 unaff_SI;
  
  FUN_6620f208(*(uint *)(param_2 + 8) ^ param_2,in_DL,unaff_SI);
  FUN_66211b1d(param_1,*(undefined4 *)(param_2 + 0x10),param_3,0,*(undefined4 *)(param_2 + 0xc),
               *(undefined4 *)(param_2 + 0x14),param_2,0);
  return;
}



// Library Function - Single Match
//  __TranslatorGuardHandler
// 
// Library: Visual Studio 2015 Release

undefined4 __cdecl
__TranslatorGuardHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined in_DL;
  undefined1 unaff_BL;
  code *s8;
  
  FUN_6620f208(*(uint *)(param_2 + 8) ^ (uint)param_2,in_DL,unaff_BL);
  if ((*(uint *)(param_1 + 4) & 0x66) != 0) {
    *(undefined4 *)(param_2 + 0x24) = 1;
    return 1;
  }
  FUN_66211b1d(param_1,*(undefined4 *)(param_2 + 0x10),param_3,0,*(undefined4 *)(param_2 + 0xc),
               *(undefined4 *)(param_2 + 0x14),*(undefined4 *)(param_2 + 0x18),1);
  if (*(int *)(param_2 + 0x24) == 0) {
    _UnwindNestedFrames(param_2,param_1);
  }
  FUN_6620d0da((undefined4 *)0x123,&s8,0,0,0,0,0);
                    // WARNING: Could not recover jumptable at 0x6620d069. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*s8)();
  return uVar1;
}



// Library Function - Single Match
//  void * __cdecl _CallCatchBlock2(struct EHRegistrationNode *,struct _s_FuncInfo const *,void
// *,int,unsigned long)
// 
// Library: Visual Studio 2015 Release

void * __cdecl
_CallCatchBlock2(EHRegistrationNode *param_1,_s_FuncInfo *param_2,void *param_3,int param_4,
                unsigned_long param_5)

{
  void *pvVar1;
  int **in_FS_OFFSET;
  int *s1c;
  code *s18;
  uint s14;
  _s_FuncInfo *s10;
  EHRegistrationNode *sc;
  int s8;
  
  s14 = DAT_6624a120 ^ (uint)&s1c;
  s10 = param_2;
  s8 = param_4 + 1;
  s18 = FUN_6620cfa3;
  sc = param_1;
  s1c = *in_FS_OFFSET;
  *in_FS_OFFSET = (int *)&s1c;
  pvVar1 = (void *)__CallSettingFrame_12(param_3,param_1,param_5);
  *in_FS_OFFSET = s1c;
  return pvVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  void __stdcall _CallMemberFunction1(void *,void *,void *)
//  void __stdcall _CallMemberFunction2(void *,void *,void *,int)
// 
// Library: Visual Studio 2012 Release

void FID_conflict__CallMemberFunction1(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
                    // WARNING: Could not recover jumptable at 0x6620d0d8. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



undefined4 __cdecl
FUN_6620d0da(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  _ptiddata p_Var1;
  undefined4 **in_FS_OFFSET;
  undefined4 *s3c;
  code *s38;
  uint s34;
  undefined4 s30;
  undefined4 *s2c;
  undefined4 s28;
  undefined4 s24;
  undefined *s20;
  undefined *s1c;
  int s18;
  undefined4 *s14;
  undefined4 s10;
  code *sc;
  undefined4 s8;
  
  s1c = &stack0xfffffffc;
  s20 = &stack0xffffffc0;
  if (param_1 == (undefined4 *)0x123) {
    *param_2 = 0x6620d183;
    s8 = 1;
  }
  else {
    s38 = __TranslatorGuardHandler;
    s34 = DAT_6624a120 ^ (uint)&s3c;
    s30 = param_5;
    s2c = param_2;
    s28 = param_6;
    s24 = param_7;
    s18 = 0;
    s3c = *in_FS_OFFSET;
    *in_FS_OFFSET = &s3c;
    s8 = 1;
    s14 = param_1;
    s10 = param_3;
    p_Var1 = __getptd();
    sc = (code *)p_Var1->_translator;
    (*sc)(*param_1,&s14);
    s8 = 0;
    if (s18 == 0) {
      *in_FS_OFFSET = s3c;
    }
    else {
      *s3c = **in_FS_OFFSET;
      *in_FS_OFFSET = s3c;
    }
  }
  return s8;
}



int __cdecl FUN_6620d1b1(int param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  uint uVar1;
  uint uVar2;
  uint s8;
  
  uVar1 = *(uint *)(param_1 + 0xc);
  iVar1 = *(int *)(param_1 + 0x10);
  uVar2 = uVar1;
  s8 = uVar1;
  if (-1 < param_2) {
    do {
      if (uVar1 == 0xffffffff) {
        _inconsistency();
      }
      uVar1 = uVar1 - 1;
      if (((*(int *)((uVar1 * 0x14) + 4 + iVar1) < param_3) &&
          (param_3 <= *(int *)((uVar1 * 0x14) + 8 + iVar1))) || (uVar1 == 0xffffffff)) {
        param_2 = param_2 + -1;
        uVar2 = s8;
        s8 = uVar1;
      }
    } while (-1 < param_2);
  }
  uVar1 = uVar1 + 1;
  *param_4 = uVar1;
  *param_5 = uVar2;
  if (((*(uint *)(param_1 + 0xc) <= uVar2) && (uVar2 != *(uint *)(param_1 + 0xc))) ||
     (uVar2 < uVar1)) {
    _inconsistency();
  }
  return (uVar1 * 0x14) + iVar1;
}



// Library Function - Single Match
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2015 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
  undefined4 *in_FS_OFFSET;
  
  *in_FS_OFFSET = *(undefined4 *)*in_FS_OFFSET;
                    // WARNING: Could not recover jumptable at 0x6620d258. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)
// 
// Library: Visual Studio 2015 Release

void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  
  puVar1 = (undefined4 *)*in_FS_OFFSET;
  RtlUnwind(param_1,(PVOID)0x6620d28b,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) & 0xfffffffd;
  *puVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = puVar1;
  return;
}



// Library Function - Single Match
//  __CreateFrameInfo
// 
// Library: Visual Studio 2012 Release

undefined4 * __cdecl __CreateFrameInfo(undefined4 *param_1,undefined4 param_2)

{
  _ptiddata p_Var1;
  
  *param_1 = param_2;
  p_Var1 = __getptd();
  param_1[1] = p_Var1->_pFrameInfoChain;
  p_Var1 = __getptd();
  p_Var1->_pFrameInfoChain = param_1;
  return param_1;
}



// Library Function - Single Match
//  __FindAndUnlinkFrame
// 
// Library: Visual Studio 2012 Release

void __cdecl __FindAndUnlinkFrame(void *param_1)

{
  void *pvVar1;
  _ptiddata p_Var1;
  void *pvVar2;
  
  p_Var1 = __getptd();
  if (param_1 == p_Var1->_pFrameInfoChain) {
    p_Var1 = __getptd();
    p_Var1->_pFrameInfoChain = *(void **)((int)param_1 + 4);
  }
  else {
    p_Var1 = __getptd();
    pvVar1 = p_Var1->_pFrameInfoChain;
    do {
      pvVar2 = pvVar1;
      if (*(int *)((int)pvVar2 + 4) == 0) {
        _inconsistency();
        return;
      }
      pvVar1 = *(void **)((int)pvVar2 + 4);
    } while (param_1 != *(void **)((int)pvVar2 + 4));
    *(undefined4 *)((int)pvVar2 + 4) = *(undefined4 *)((int)param_1 + 4);
  }
  return;
}



// Library Function - Single Match
//  __IsExceptionObjectToBeDestroyed
// 
// Library: Visual Studio 2012 Release

undefined4 __cdecl __IsExceptionObjectToBeDestroyed(int param_1)

{
  int *piVar1;
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  piVar1 = (int *)p_Var1->_pFrameInfoChain;
  while( true ) {
    if (piVar1 == (int *)0x0) {
      return 1;
    }
    if (*piVar1 == param_1) break;
    piVar1 = (int *)piVar1[1];
  }
  return 0;
}



// Library Function - Multiple Matches With Different Base Names
//  ___CxxFrameHandler
//  ___CxxFrameHandler2
//  ___CxxFrameHandler3
// 
// Library: Visual Studio

undefined4 __cdecl
FID_conflict____CxxFrameHandler3
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  uVar1 = FUN_66211b1d(param_1,param_2,param_3,param_4);
  return uVar1;
}



// Library Function - Single Match
//  __fpmath
// 
// Library: Visual Studio 2012 Release

void __cdecl __fpmath(int param_1)

{
  FUN_6620d3a6();
  if (param_1 != 0) {
    __setdefaultprecision();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_6620d3a6(void)

{
  Ptr_6624a128 = __cfltcvt;
  DAT_6624a12c = FUN_66212551;
  _DAT_6624a130 = FUN_662125e2;
  _DAT_6624a134 = FUN_6621263c;
  _DAT_6624a138 = __positive;
  _DAT_6624a13c = __cfltcvt;
  Ptr_6624a140 = __cfltcvt_l;
  _DAT_6624a144 = FUN_662125fa;
  Ptr_6624a148 = FUN_66212562;
  Ptr_6624a14c = FUN_6621264d;
  return;
}


/*
Unable to decompile 'FUN_6620d410'
Cause: Exception while decompiling 6620d410: Decompiler process died

*/


// Library Function - Single Match
//  _wcscmp
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2019 Release

int __cdecl _wcscmp(wchar_t *_Str1,wchar_t *_Str2)

{
  int iVar1;
  int iVar2;
  uint uVar1;
  
  uVar1 = (uint)(ushort)*_Str2;
  iVar1 = ((ushort)*_Str1) - uVar1;
  if (iVar1 == 0) {
    iVar2 = (int)_Str1 - (int)_Str2;
    do {
      if ((short)uVar1 == 0) break;
      _Str2 = (wchar_t *)((ushort *)_Str2 + 1);
      uVar1 = (uint)(ushort)*_Str2;
      iVar1 = (*(ushort *)(iVar2 + (int)_Str2)) - uVar1;
    } while (iVar1 == 0);
  }
  if (iVar1 < 0) {
    iVar1 = -1;
  }
  else if (0 < iVar1) {
    iVar1 = 1;
  }
  return iVar1;
}



void __cdecl Wwide_char_to_integer(ushort *param_1)

{
                    // Wrapper wrapped in a wrapper wtf
  Wwide_character_to_integer(param_1,(ushort **)0x0,10);
  return;
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio

ulonglong __allmul(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return (((ulonglong)param_1 * (ulonglong)param_3) & 0xffffffff) |
         ((ulonglong)
          ((int)(((ulonglong)param_1 * (ulonglong)param_3) >> 0x20) +
          (param_2 * param_3) + (param_1 * param_4)) << 0x20);
}


/*
Unable to decompile 'FUN_6620d5b0'
Cause: Exception while decompiling 6620d5b0: Decompiler process died

*/

/*
Unable to decompile 'FUN_6620dc00'
Cause: Exception while decompiling 6620dc00: Decompiler process died

*/


void __cdecl FID_conflict__free(void *_Memory)

{
  FID_conflict__free(_Memory);
  return;
}



void __cdecl FUN_6620e249(char *param_1,uint param_2,ushort *param_3,int **param_4)

{
  FUN_6620e264(param_1,param_2,param_3,(pthreadlocinfo *)0x0,param_4);
  return;
}



undefined4 __cdecl
FUN_6620e264(char *param_1,uint param_2,ushort *param_3,pthreadlocinfo *param_4,int **param_5)

{
  int *piVar1;
  undefined4 uVar1;
  int iVar1;
  FILE s24;
  
  s24._ptr = (char *)0x0;
  piVar1 = &s24._cnt;
  for (iVar1 = 7; iVar1 != 0; iVar1 = iVar1 + -1) {
    *piVar1 = 0;
    piVar1 = piVar1 + 1;
  }
  if (param_3 == (ushort *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
    uVar1 = 0xffffffff;
  }
  else if ((param_2 == 0) || (param_1 != (char *)0x0)) {
    s24._flag = 0x42;
    s24._base = param_1;
    s24._ptr = param_1;
    if (param_2 < 0x40000000) {
      s24._cnt = param_2 * 2;
    }
    else {
      s24._cnt = 0x7fffffff;
    }
    uVar1 = FUN_66212e6a((int)&s24,param_3,param_4,param_5);
    if (param_1 != (char *)0x0) {
      s24._cnt = s24._cnt + -1;
      if (s24._cnt < 0) {
        FUN_66212d1b(0,&s24);
      }
      else {
        *s24._ptr = '\0';
        s24._ptr = s24._ptr + 1;
      }
      s24._cnt = s24._cnt + -1;
      if (s24._cnt < 0) {
        FUN_66212d1b(0,&s24);
      }
      else {
        *s24._ptr = '\0';
      }
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



void __cdecl sanitycheck_parameter(int param_1,undefined4 sanity_check_param)

{
                    // This is a wrapper
  call_with_validated_state(FUN_66212e6a,param_1,0,sanity_check_param);
  return;
}



undefined4 __cdecl
call_with_validated_state(undefined *target_function,int handler,undefined4 arg3,undefined4 arg4)

{
  int *global_errno;
  undefined4 handle;
  int i;
  undefined4 *state_buffer;
  undefined4 request_id;
  undefined4 flags [7];
  
  request_id = 0;
  state_buffer = flags;
  for (i = 7; i != 0; i = i + -1) {
    *state_buffer = 0;
    state_buffer = state_buffer + 1;
  }
  if (handler == 0) {
    global_errno = __errno();
    *global_errno = 0x16;
    report_invalid_parameter();
    handle = 0xffffffff;
  }
  else {
                    // Max value
                    // 
    flags[0] = 0x7fffffff;
                    // Sanity check
    flags[2] = 0x42;
    flags[1] = 0;
    request_id = 0;
    handle = (*(code *)target_function)(&request_id,handler,arg3,arg4);
  }
  return handle;
}



void __cdecl safe_malloc(size_t byte_size)

{
  code *pcVar1;
  int iVar1;
  void *pvVar1;
  undefined **object [3];
  char *field1;
  
  do {
    pvVar1 = _malloc(byte_size);
    if (pvVar1 != (void *)0x0) {
      return;
    }
    iVar1 = __callnewh(byte_size);
  } while (iVar1 != 0);
  field1 = s__fbad_allocation_6621d496 + 2;
  setup_object_fields(object,&field1);
  object[0] = &PTR_FUN_6621d490;
  Handle_flags_Raise_exc((int *)object,&control_exc_flags);
                    // Software interruption
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void __cdecl FID_conflict__free(void *_Memory)

{
  BOOL BVar1;
  int *piVar1;
  DWORD DVar1;
  int iVar1;
  
  if (_Memory != (void *)0x0) {
    BVar1 = HeapFree(hHeap_6624b5e8,0,_Memory);
    if (BVar1 == 0) {
      piVar1 = __errno();
      DVar1 = GetLastError();
      iVar1 = __get_errno_from_oserr(DVar1);
      *piVar1 = iVar1;
    }
  }
  return;
}


/*
Unable to decompile 'FUN_6620e410'
Cause: Exception while decompiling 6620e410: Decompiler process died

*/


pthreadlocinfo * __thiscall FUN_6620e53b(void *this,pthreadlocinfo *param_1)

{
  uint uVar1;
  _ptiddata p_Var1;
  pthreadlocinfo ptVar1;
  pthreadmbcinfo ptVar2;
  
  *(undefined *)((int)this + 0xc) = 0;
  if (param_1 == (pthreadlocinfo *)0x0) {
    p_Var1 = __getptd();
    *(_ptiddata *)((int)this + 8) = p_Var1;
    ptVar1 = p_Var1->ptlocinfo;
    *(pthreadlocinfo *)this = ptVar1;
    *(pthreadmbcinfo *)((int)this + 4) = p_Var1->ptmbcinfo;
    if ((ptVar1 != (pthreadlocinfo)PTR_DAT_6624a954) && ((p_Var1->_ownlocale & DAT_6624aa18) == 0))
    {
      ptVar1 = FUN_66213f25();
      *(pthreadlocinfo *)this = ptVar1;
    }
    if ((*(int *)((int)this + 4) != DAT_6624a6f4) &&
       ((*(uint *)(*(int *)((int)this + 8) + 0x70) & DAT_6624aa18) == 0)) {
      ptVar2 = FUN_662142a7();
      *(pthreadmbcinfo *)((int)this + 4) = ptVar2;
    }
    uVar1 = *(uint *)(*(int *)((int)this + 8) + 0x70);
    if ((uVar1 & 2) == 0) {
      *(uint *)(*(int *)((int)this + 8) + 0x70) = uVar1 | 2;
      *(undefined *)((int)this + 0xc) = 1;
    }
  }
  else {
    *(pthreadlocinfo *)this = *param_1;
    *(pthreadlocinfo *)((int)this + 4) = param_1[1];
  }
  return (pthreadlocinfo *)this;
}



uint __cdecl
FUN_6620e5c3(pthreadlocinfo *param_1,byte *param_2,byte **param_3,uint param_4,uint param_5)

{
  byte *pbVar1;
  ushort uVar1;
  int *piVar1;
  undefined2 extraout_var;
  uint uVar2;
  uint uVar3;
  int iVar1;
  byte *pbVar2;
  pthreadlocinfo ptVar1;
  pthreadlocinfo s28 [2];
  int s20;
  char s1c;
  ushort *s18;
  uint s14;
  uint s10;
  uint sc;
  byte s5;
  
  FUN_6620e53b(s28,param_1);
  if (param_3 != (byte **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (byte *)0x0) || ((param_4 != 0 && (((int)param_4 < 2 || (0x24 < (int)param_4))))))
  {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
  }
  else {
    s10 = 0;
    s5 = *param_2;
    ptVar1 = s28[0];
    pbVar1 = param_2;
    while( true ) {
      pbVar2 = pbVar1 + 1;
      if (ptVar1->mb_cur_max < 2) {
        uVar2 = (ptVar1->pctype[s5]) & 8;
      }
      else {
        uVar1 = FUN_662146e0((uint)s5,8,s28);
        uVar2 = ((int)(short)extraout_var << 0x10) + uVar1;
        ptVar1 = s28[0];
      }
      if (uVar2 == 0) break;
      s5 = *pbVar2;
      pbVar1 = pbVar2;
    }
    if (s5 == 0x2d) {
      param_5 = param_5 | 2;
LAB_6620e661:
      s5 = *pbVar2;
      pbVar2 = pbVar1 + 2;
    }
    else if (s5 == 0x2b) goto LAB_6620e661;
    if (((-1 < (int)param_4) && (param_4 != 1)) && ((int)param_4 < 0x25)) {
      if (param_4 == 0) {
        if (s5 != 0x30) {
          param_4 = 10;
          goto LAB_6620e6d2;
        }
        if ((*pbVar2 != 0x78) && (*pbVar2 != 0x58)) {
          param_4 = 8;
          goto LAB_6620e6d2;
        }
        param_4 = 0x10;
      }
      else if ((param_4 != 0x10) || (s5 != 0x30)) goto LAB_6620e6d2;
      if ((*pbVar2 == 0x78) || (*pbVar2 == 0x58)) {
        s5 = pbVar2[1];
        pbVar2 = pbVar2 + 2;
      }
LAB_6620e6d2:
      uVar2 = (uint)(0xffffffff / (ulonglong)param_4);
      s14 = (uint)(0xffffffff % (ulonglong)param_4);
      s18 = s28[0]->pctype;
      do {
        if ((s18[s5] & 4) == 0) {
          if ((s18[s5] & 0x103) == 0) goto LAB_6620e753;
          iVar1 = (int)(char)s5;
          if ((byte)(s5 + 0x9f) < 0x1a) {
            iVar1 = iVar1 + -0x20;
          }
          uVar3 = iVar1 - 0x37;
        }
        else {
          uVar3 = (int)(char)s5 - 0x30;
        }
        if (param_4 <= uVar3) goto LAB_6620e753;
        if ((s10 < uVar2) || ((s10 == uVar2 && (uVar3 <= s14)))) {
          s10 = (s10 * param_4) + uVar3;
          param_5 = param_5 | 8;
        }
        else {
          param_5 = param_5 | 0xc;
          if (param_3 == (byte **)0x0) goto LAB_6620e753;
        }
        s5 = *pbVar2;
        pbVar2 = pbVar2 + 1;
      } while( true );
    }
    if (param_3 != (byte **)0x0) {
      *param_3 = param_2;
    }
  }
  s10 = 0;
LAB_6620e7d3:
  if (s1c != '\0') {
    *(uint *)(s20 + 0x70) = *(uint *)(s20 + 0x70) & 0xfffffffd;
  }
  return s10;
LAB_6620e753:
  pbVar2 = pbVar2 + -1;
  if ((param_5 & 8) == 0) {
    if (param_3 != (byte **)0x0) {
      pbVar2 = param_2;
    }
    s10 = 0;
  }
  else if (((param_5 & 4) != 0) ||
          (((param_5 & 1) == 0 &&
           ((((param_5 & 2) != 0 && (0x80000000 < s10)) ||
            (((param_5 & 2) == 0 && (0x7fffffff < s10)))))))) {
    s10 = uVar2;
    sc = param_5;
    piVar1 = __errno();
    *piVar1 = 0x22;
    param_5 = sc;
    if ((sc & 1) == 0) {
      s10 = (((sc & 2) != 0)) + 0x7fffffff;
    }
    else {
      s10 = 0xffffffff;
    }
  }
  if (param_3 != (byte **)0x0) {
    *param_3 = pbVar2;
  }
  if ((param_5 & 2) != 0) {
    s10 = -s10;
  }
  goto LAB_6620e7d3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_6620e7e9(byte *param_1,byte **param_2,uint param_3)

{
  undefined **ppuVar1;
  
  if (_DAT_6624b728 == 0) {
    ppuVar1 = &PTR_DAT_6624aa10;
  }
  else {
    ppuVar1 = (undefined **)0x0;
  }
  FUN_6620e5c3((pthreadlocinfo *)ppuVar1,param_1,param_2,param_3,1);
  return;
}


/*
Unable to decompile 'FUN_6620e813'
Cause: Exception while decompiling 6620e813: Decompiler process died

*/


void __cdecl FUN_6620e84d(undefined4 param_1)

{
  FUN_6620e813(param_1,0);
  return;
}



void __cdecl FUN_6620e85e(ushort param_1)

{
  get_char_types(param_1,8);
  return;
}



void Handle_flags_Raise_exc(int *context,byte *control_bytes)

{
  int i;
  DWORD *flags_source;
  DWORD *exception_flags_buffer;
  DWORD exception_flags [4];
  DWORD exc_args;
  ULONG_PTR lparguments;
  int *sc;
  byte *s8;
  
  flags_source = &DAT_6621e308;
  exception_flags_buffer = exception_flags;
                    // Points to next Dword, copies PdVar1 values progressively
  for (i = 8; i != 0; i = i + -1) {
    *exception_flags_buffer = *flags_source;
    flags_source = flags_source + 1;
    exception_flags_buffer = exception_flags_buffer + 1;
  }
  if ((control_bytes != (byte *)0) && ((*control_bytes & 16) != 0)) {
    i = *(int *)(*context + -4);
    control_bytes = *(byte **)(i + 0x18);
    (**(code **)(i + 32))((int *)(*context + -4));
  }
  sc = context;
  if ((control_bytes != (byte *)0) && ((*control_bytes & 8) != 0)) {
    lparguments = 0x1994000;
  }
  s8 = control_bytes;
  RaiseException(exception_flags[0],exception_flags[1],exc_args,&lparguments);
  return;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Library: Visual Studio 2012 Release

void __thiscall type_info::_type_info(type_info *this)

{
  *(undefined ***)this = &PTR__scalar_deleting_destructor__6621e32c;
  _Type_info_dtor(this);
  return;
}



// Library Function - Single Match
//  public: bool __thiscall type_info::operator==(class type_info const &)const 
// 
// Library: Visual Studio 2012 Release

bool __thiscall type_info::operator__(type_info *this,type_info *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp((char *)(param_1 + 9),(char *)(this + 9));
  return (bool)('\x01' - (iVar1 != 0));
}


/*
Unable to decompile '`scalar_deleting_destructor''
Cause: Exception while decompiling 6620e8fe: Decompiler process died

*/


int __cdecl FUN_6620e91d(short *param_1,int param_2,short *param_3,int param_4)

{
  short sVar1;
  int *piVar1;
  int iVar1;
  short *psVar1;
  int iVar2;
  
  if (param_4 == 0) {
    if (param_1 == (short *)0x0) {
      if (param_2 == 0) {
        return 0;
      }
    }
    else {
LAB_6620e93c:
      if (param_2 != 0) {
        if (param_4 == 0) {
          *param_1 = 0;
          return 0;
        }
        if (param_3 != (short *)0x0) {
          iVar2 = param_2;
          if (param_4 == -1) {
            iVar1 = (int)param_1 - (int)param_3;
            do {
              sVar1 = *param_3;
              *(short *)(iVar1 + (int)param_3) = sVar1;
              param_3 = param_3 + 1;
              if (sVar1 == 0) break;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
          }
          else {
            psVar1 = param_1;
            do {
              sVar1 = *(short *)(((int)param_3 - (int)param_1) + (int)psVar1);
              *psVar1 = sVar1;
              psVar1 = psVar1 + 1;
              if ((sVar1 == 0) || (iVar2 = iVar2 + -1, iVar2 == 0)) break;
              param_4 = param_4 + -1;
            } while (param_4 != 0);
            if (param_4 == 0) {
              *psVar1 = 0;
            }
          }
          if (iVar2 != 0) {
            return 0;
          }
          if (param_4 == -1) {
            param_1[param_2 + -1] = 0;
            return 0x50;
          }
          *param_1 = 0;
          piVar1 = __errno();
          iVar2 = 0x22;
          goto LAB_6620e961;
        }
        *param_1 = 0;
      }
    }
  }
  else if (param_1 != (short *)0x0) goto LAB_6620e93c;
  piVar1 = __errno();
  iVar2 = 0x16;
LAB_6620e961:
  *piVar1 = iVar2;
  report_invalid_parameter();
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_6620e9db(ushort *param_1,ushort *param_2,int param_3)

{
  ushort uVar1;
  int iVar1;
  int *piVar1;
  ushort uVar2;
  
  if (_DAT_6624b728 == 0) {
    iVar1 = 0;
    if (param_3 != 0) {
      if ((param_1 == (ushort *)0x0) || (param_2 == (ushort *)0x0)) {
        piVar1 = __errno();
        *piVar1 = 0x16;
        report_invalid_parameter();
        iVar1 = 0x7fffffff;
      }
      else {
        iVar1 = (int)param_1 - (int)param_2;
        do {
          uVar2 = *(ushort *)(iVar1 + (int)param_2);
          if ((0x40 < uVar2) && (uVar2 < 0x5b)) {
            uVar2 = uVar2 + 0x20;
          }
          uVar1 = *param_2;
          if ((0x40 < uVar1) && (uVar1 < 0x5b)) {
            uVar1 = uVar1 + 0x20;
          }
          param_2 = param_2 + 1;
          param_3 = param_3 + -1;
        } while (((param_3 != 0) && (uVar2 != 0)) && (uVar2 == uVar1));
        iVar1 = (uint)uVar2 - (uint)uVar1;
      }
    }
  }
  else {
    iVar1 = FUN_6620ea91(param_1,param_2,param_3,(pthreadlocinfo *)0x0);
  }
  return iVar1;
}



int __cdecl FUN_6620ea91(ushort *param_1,ushort *param_2,int param_3,pthreadlocinfo *param_4)

{
  ushort uVar1;
  ushort uVar2;
  int *piVar1;
  uint uVar3;
  int iVar1;
  pthreadlocinfo s18 [2];
  int s10;
  char sc;
  
  iVar1 = 0;
  if (param_3 != 0) {
    if ((param_1 == (ushort *)0x0) || (param_2 == (ushort *)0x0)) {
      piVar1 = __errno();
      *piVar1 = 0x16;
      report_invalid_parameter();
      iVar1 = 0x7fffffff;
    }
    else {
      FUN_6620e53b(s18,param_4);
      if (s18[0]->locale_name[2] == (wchar_t *)0x0) {
        iVar1 = (int)param_1 - (int)param_2;
        do {
          uVar1 = *(ushort *)(iVar1 + (int)param_2);
          if ((0x40 < uVar1) && (uVar1 < 0x5b)) {
            uVar1 = uVar1 + 0x20;
          }
          uVar2 = *param_2;
          if ((0x40 < uVar2) && (uVar2 < 0x5b)) {
            uVar2 = uVar2 + 0x20;
          }
          param_2 = param_2 + 1;
          param_3 = param_3 + -1;
        } while (((param_3 != 0) && (uVar1 != 0)) && (uVar1 == uVar2));
      }
      else {
        do {
          uVar3 = FUN_6621493d((uint)*param_1,s18);
          uVar1 = (ushort)uVar3;
          uVar3 = FUN_6621493d((uint)*param_2,s18);
          uVar2 = (ushort)uVar3;
          param_3 = param_3 + -1;
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          if ((param_3 == 0) || (uVar1 == 0)) break;
        } while (uVar1 == uVar2);
      }
      iVar1 = (uint)uVar1 - (uint)uVar2;
      if (sc != '\0') {
        *(uint *)(s10 + 0x70) = *(uint *)(s10 + 0x70) & 0xfffffffd;
      }
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  __aullshr
// 
// Library: Visual Studio

ulonglong __fastcall __aullshr(byte param_1,uint param_2)

{
  uint in_EAX;
  
  if (0x3f < param_1) {
    return 0;
  }
  if (param_1 < 0x20) {
    return ((longlong)(int)(param_2 >> (param_1 & 0x1f)) << 0x20) +
           ((in_EAX >> (param_1 & 0x1f)) | (param_2 << (0x20 - (param_1 & 0x1f))));
  }
  return (ulonglong)(param_2 >> (param_1 & 0x1f));
}



void FUN_6620ecb6(int param_1)

{
  __local_unwind2(*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}


/*
Unable to decompile 'FUN_6620ece0'
Cause: Exception while decompiling 6620ece0: Decompiler process died

*/


// Library Function - Single Match
//  __aulldvrm
// 
// Library: Visual Studio

undefined8 __aulldvrm(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar1;
  uint uVar2;
  int iVar1;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  
  uVar2 = param_1;
  uVar6 = param_4;
  uVar4 = param_2;
  uVar7 = param_3;
  if (param_4 == 0) {
    uVar2 = param_2 / param_3;
    iVar1 = (int)(((((ulonglong)param_2 % (ulonglong)param_3) << 0x20) | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar3 = uVar6 >> 1;
      uVar7 = (uVar7 >> 1) | ((uint)((uVar6 & 1) != 0) << 0x1f);
      uVar5 = uVar4 >> 1;
      uVar2 = (uVar2 >> 1) | ((uint)((uVar4 & 1) != 0) << 0x1f);
      uVar6 = uVar3;
      uVar4 = uVar5;
    } while (uVar3 != 0);
    uVar1 = (ulonglong)(((longlong)(int)uVar5 << 0x20) + uVar2) / (ulonglong)uVar7;
    iVar1 = (int)uVar1;
    lVar1 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar2 = (uint)((ulonglong)lVar1 >> 0x20);
    uVar6 = uVar2 + (iVar1 * param_4);
    if (((CARRY4(uVar2,iVar1 * param_4)) || (param_2 < uVar6)) ||
       ((param_2 <= uVar6 && (param_1 < (uint)lVar1)))) {
      iVar1 = iVar1 + -1;
    }
    uVar2 = 0;
  }
  return ((longlong)(int)uVar2 << 0x20) + iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

PVOID __cdecl ThreadSafeAppendEncodedPointer(PVOID param_1)

{
  PVOID pvVar1;
  
  lockmem8();
  pvVar1 = AppendEncodedPointerToDynamicArray(param_1);
  WLeave_critical_session();
  return pvVar1;
}



void WLeave_critical_session(void)

{
  Wleavecritical_session();
  return;
}



PVOID __cdecl AppendEncodedPointerToDynamicArray(PVOID param_1)

{
  PVOID *decoded_pointer;
  PVOID *decode_ptr2;
  SIZE_T blocksize;
  SIZE_T blocksize_buffer;
  PVOID resized_memory;
  int iVar1;
  
  decoded_pointer = (PVOID *)DecodePointer(Ptr_6624d3b0);
  decode_ptr2 = (PVOID *)DecodePointer(Ptr_6624d3ac);
  if ((decode_ptr2 < decoded_pointer) ||
     (iVar1 = (int)decode_ptr2 - (int)decoded_pointer, (iVar1 + 4U) < 4)) {
    return (PVOID)0x0;
  }
  blocksize = get_allocated_block_size(decoded_pointer);
  if (blocksize < (iVar1 + 4U)) {
    blocksize_buffer = 0x800;
    if (blocksize < 0x800) {
      blocksize_buffer = blocksize;
    }
                    // Resize memory
    if (((blocksize_buffer + blocksize) < blocksize) ||
       (resized_memory = realloc_timeout(decoded_pointer,blocksize_buffer + blocksize),
       resized_memory == (void *)0x0)) {
      if ((blocksize + 0x10) < blocksize) {
        return (PVOID)0x0;
      }
      resized_memory = realloc_timeout(decoded_pointer,blocksize + 0x10);
      if (resized_memory == (void *)0x0) {
        return (PVOID)0x0;
      }
    }
    decode_ptr2 = (PVOID *)((int)resized_memory + ((iVar1 >> 2) * 4));
    Ptr_6624d3b0 = EncodePointer(resized_memory);
  }
  resized_memory = EncodePointer(param_1);
  *decode_ptr2 = resized_memory;
  Ptr_6624d3ac = EncodePointer(decode_ptr2 + 1);
  return param_1;
}



int __cdecl CheckPointerAppendedSuccessfully(PVOID param_1)

{
  PVOID pvVar1;
  
  pvVar1 = ThreadSafeAppendEncodedPointer(param_1);
  return ((pvVar1 != (PVOID)0x0)) - 1;
}



// Library Function - Single Match
//  _wcsncmp
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2019 Release

int __cdecl _wcsncmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  if (_MaxCount != 0) {
    for (; ((_MaxCount = _MaxCount - 1, _MaxCount != 0 && (*_Str1 != 0)) && (*_Str1 == *_Str2));
        _Str1 = (wchar_t *)((ushort *)_Str1 + 1)) {
      _Str2 = (wchar_t *)((ushort *)_Str2 + 1);
    }
    return (uint)(ushort)*_Str1 - (uint)(ushort)*_Str2;
  }
  return _MaxCount;
}


/*
Unable to decompile '_strlen'
Cause: Exception while decompiling 6620f050: Decompiler process died

*/


// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  *(undefined4 *)(this + 4) = 0;
  *(undefined ***)this = &PTR_FUN_6621e334;
  this[8] = (exception)0x0;
  FUN_6620f1a1(this,*param_1);
  return this;
}



undefined ** __thiscall setup_object_fields(void *this,undefined4 *param_1)

{
  *(undefined ***)this = &PTR_FUN_6621e334;
  *(undefined4 *)((int)this + 4) = *param_1;
  *(undefined *)((int)this + 8) = 0;
  return (undefined **)this;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2012 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined4 *)(this + 4) = 0;
  *(undefined ***)this = &PTR_FUN_6621e334;
  this[8] = (exception)0x0;
  operator_(this,param_1);
  return this;
}



void __fastcall FUN_6620f13e(undefined **param_1)

{
  *param_1 = (undefined *)&PTR_FUN_6621e334;
  std::exception::_Tidy((exception *)param_1);
  return;
}



// Library Function - Single Match
//  public: class std::exception & __thiscall std::exception::operator=(class std::exception const
// &)
// 
// Library: Visual Studio 2012 Release

exception * __thiscall std::exception::operator_(exception *this,exception *param_1)

{
  if (this != param_1) {
    _Tidy(this);
    if (param_1[8] == (exception)0x0) {
      *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
    }
    else {
      FUN_6620f1a1(this,*(char **)(param_1 + 4));
    }
  }
  return this;
}


/*
Unable to decompile 'FUN_6620f17c'
Cause: Exception while decompiling 6620f17c: Decompiler process died

*/


void __thiscall FUN_6620f1a1(void *this,char *param_1)

{
  size_t sVar1;
  char *_Dst;
  
  if (param_1 != (char *)0x0) {
    sVar1 = _strlen(param_1);
    _Dst = (char *)_malloc(sVar1 + 1);
    *(char **)((int)this + 4) = _Dst;
    if (_Dst != (char *)0x0) {
      _strcpy_s(_Dst,sVar1 + 1,param_1);
      *(undefined *)((int)this + 8) = 1;
    }
  }
  return;
}



// Library Function - Single Match
//  private: void __thiscall std::exception::_Tidy(void)
// 
// Library: Visual Studio 2012 Release

void __thiscall std::exception::_Tidy(exception *this)

{
  if (this[8] != (exception)0x0) {
    FID_conflict__free(*(void **)(this + 4));
  }
  *(undefined4 *)(this + 4) = 0;
  this[8] = (exception)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_6620f208(int param_1,undefined param_2,undefined param_3)

{
  code *pcVar1;
  undefined4 uVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar4;
  undefined4 extraout_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte bVar1;
  byte bVar2;
  byte in_AF;
  byte bVar3;
  byte bVar4;
  byte in_TF;
  byte in_IF;
  byte bVar5;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined8 uVar5;
  undefined4 unaff_retaddr;
  
  if (param_1 == DAT_6624a120) {
    return;
  }
  uVar3 = IsProcessorFeaturePresent(0x17);
  uVar5 = ((longlong)(int)extraout_EDX << 0x20) + uVar3;
  bVar1 = 0;
  bVar5 = 0;
  bVar4 = (int)uVar3 < 0;
  bVar3 = uVar3 == 0;
  bVar2 = (POPCOUNT(uVar3 & 0xff) & 1U) == 0;
  uVar4 = extraout_ECX;
  uVar1 = unaff_retaddr;
  uVar2 = unaff_EBP;
  if (!(bool)bVar3) {
    pcVar1 = (code *)swi(0x29);
    uVar5 = (*pcVar1)();
    uVar4 = extraout_ECX_00;
    uVar1 = unaff_retaddr;
    uVar2 = unaff_EBP;
  }
  _DAT_6624b8cc = uVar2;
  _DAT_6624b7d4 = uVar1;
  _DAT_6624b8d8 =
       ((uint)(in_NT & 1) * 0x4000) | ((uint)(bVar5 & 1) * 0x800) | ((uint)(in_IF & 1) * 0x200) |
       ((uint)(in_TF & 1) * 0x100) | ((uint)(bVar4 & 1) * 0x80) | ((uint)(bVar3 & 1) * 0x40) |
       ((uint)(in_AF & 1) * 0x10) | ((uint)(bVar2 & 1) * 4) | (uint)(bVar1 & 1) |
       ((uint)(in_ID & 1) * 0x200000) | ((uint)(in_VIP & 1) * 0x100000) |
       ((uint)(in_VIF & 1) * 0x80000) | ((uint)(in_AC & 1) * 0x40000);
  _DAT_6624b8dc = &param_3;
  _DAT_6624b818 = 0x10001;
  _DAT_6624b7c8 = 0xc0000409;
  _DAT_6624b7cc = 1;
  _DAT_6624b7d8 = 1;
  _DAT_6624b7dc = 2;
  _DAT_6624b8a4 = in_GS;
  _DAT_6624b8a8 = in_FS;
  _DAT_6624b8ac = in_ES;
  _DAT_6624b8b0 = in_DS;
  _DAT_6624b8b4 = unaff_EDI;
  _DAT_6624b8b8 = unaff_ESI;
  _DAT_6624b8bc = unaff_EBX;
  _DAT_6624b8c4 = uVar4;
  DAT_6624b8d0 = _DAT_6624b7d4;
  _DAT_6624b8d4 = in_CS;
  _DAT_6624b8e0 = in_SS;
  ___raise_securityfailure((EXCEPTION_POINTERS *)&PTR_DAT_6621ebe8);
  _DAT_6624b8c0 = (undefined4)((ulonglong)uVar5 >> 0x20);
  _DAT_6624b8c8 = (undefined4)uVar5;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __EH_epilog3
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __EH_epilog3(void)

{
  undefined4 *unaff_EBP;
  undefined4 *in_FS_OFFSET;
  undefined4 unaff_retaddr;
  
  *in_FS_OFFSET = unaff_EBP[-3];
  *unaff_EBP = unaff_retaddr;
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_1
// Library Function - Single Match
//  __EH_prolog3_catch
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __cdecl __EH_prolog3_catch(int param_1)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  int *in_FS_OFFSET;
  undefined4 unaff_retaddr;
  uint auStack28 [5];
  undefined s8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack28 + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack28 + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack28 + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack28 + iVar1 + 4) = DAT_6624a120 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack28 + iVar1) = unaff_retaddr;
  *in_FS_OFFSET = (int)s8;
  return;
}



_ptiddata __cdecl FUN_6620f261(int param_1,void *param_2)

{
  int *piVar1;
  code *pcVar1;
  void *pvVar1;
  _ptiddata p_Var1;
  int *piVar2;
  int iVar1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 != (_ptiddata)0x0) {
    piVar1 = (int *)p_Var1->_pxcptacttab;
    piVar2 = piVar1;
    do {
      if (*piVar2 == param_1) break;
      piVar2 = piVar2 + 3;
    } while (piVar2 < (piVar1 + 0x24));
    if (((piVar1 + 0x24) <= piVar2) || (*piVar2 != param_1)) {
      piVar2 = (int *)0x0;
    }
    if ((piVar2 == (int *)0x0) || (pcVar1 = (code *)piVar2[2], pcVar1 == (code *)0x0)) {
      p_Var1 = (_ptiddata)0x0;
    }
    else if (pcVar1 == (code *)0x5) {
      piVar2[2] = 0;
      p_Var1 = (_ptiddata)0x1;
    }
    else if (pcVar1 == (code *)0x1) {
      p_Var1 = (_ptiddata)0xffffffff;
    }
    else {
      pvVar1 = p_Var1->_tpxcptinfoptrs;
      p_Var1->_tpxcptinfoptrs = param_2;
      if (piVar2[1] == 8) {
        iVar1 = 0x24;
        do {
          *(undefined4 *)(iVar1 + 8 + (int)p_Var1->_pxcptacttab) = 0;
          iVar1 = iVar1 + 0xc;
        } while (iVar1 < 0x90);
        iVar1 = p_Var1->_tfpecode;
        if (*piVar2 == -0x3fffff72) {
          p_Var1->_tfpecode = 0x83;
        }
        else if (*piVar2 == -0x3fffff70) {
          p_Var1->_tfpecode = 0x81;
        }
        else if (*piVar2 == -0x3fffff6f) {
          p_Var1->_tfpecode = 0x84;
        }
        else if (*piVar2 == -0x3fffff6d) {
          p_Var1->_tfpecode = 0x85;
        }
        else if (*piVar2 == -0x3fffff73) {
          p_Var1->_tfpecode = 0x82;
        }
        else if (*piVar2 == -0x3fffff71) {
          p_Var1->_tfpecode = 0x86;
        }
        else if (*piVar2 == -0x3fffff6e) {
          p_Var1->_tfpecode = 0x8a;
        }
        else if (*piVar2 == -0x3ffffd4b) {
          p_Var1->_tfpecode = 0x8d;
        }
        else if (*piVar2 == -0x3ffffd4c) {
          p_Var1->_tfpecode = 0x8e;
        }
        (*pcVar1)(8,p_Var1->_tfpecode);
        p_Var1->_tfpecode = iVar1;
      }
      else {
        piVar2[2] = 0;
        (*pcVar1)(piVar2[1]);
      }
      p_Var1->_tpxcptinfoptrs = pvVar1;
      p_Var1 = (_ptiddata)0xffffffff;
    }
  }
  return p_Var1;
}



// Library Function - Single Match
//  ___CppXcptFilter
// 
// Library: Visual Studio 2012 Release

int __cdecl ___CppXcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  _ptiddata p_Var1;
  
  if (_ExceptionNum == 0xe06d7363) {
    p_Var1 = FUN_6620f261(-0x1f928c9d,_ExceptionPtr);
    return (int)p_Var1;
  }
  return (int)(_ptiddata)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_6620f3da(void *param_1)

{
  int *piVar1;
  int iVar1;
  
  if (param_1 != (void *)0x0) {
    if (*(int *)((int)param_1 + 0x24) != 0) {
      FID_conflict__free(*(void **)((int)param_1 + 0x24));
    }
    if (*(int *)((int)param_1 + 0x2c) != 0) {
      FID_conflict__free(*(void **)((int)param_1 + 0x2c));
    }
    if (*(int *)((int)param_1 + 0x34) != 0) {
      FID_conflict__free(*(void **)((int)param_1 + 0x34));
    }
    if (*(int *)((int)param_1 + 0x3c) != 0) {
      FID_conflict__free(*(void **)((int)param_1 + 0x3c));
    }
    if (*(int *)((int)param_1 + 0x40) != 0) {
      FID_conflict__free(*(void **)((int)param_1 + 0x40));
    }
    if (*(int *)((int)param_1 + 0x44) != 0) {
      FID_conflict__free(*(void **)((int)param_1 + 0x44));
    }
    if (*(int *)((int)param_1 + 0x48) != 0) {
      FID_conflict__free(*(void **)((int)param_1 + 0x48));
    }
    if (*(undefined **)((int)param_1 + 0x5c) != &DAT_6621e350) {
      FID_conflict__free(*(void **)((int)param_1 + 0x5c));
    }
    __lock(0xd);
    piVar1 = *(int **)((int)param_1 + 0x68);
    if (piVar1 != (int *)0x0) {
      LOCK();
      iVar1 = *piVar1;
      *piVar1 = iVar1 + -1;
      if ((iVar1 + -1 == 0) && (piVar1 != (int *)&DAT_6624a4d0)) {
        FID_conflict__free(piVar1);
      }
    }
    FUN_6620f4fa();
    __lock(0xc);
    piVar1 = *(int **)((int)param_1 + 0x6c);
    if (piVar1 != (int *)0x0) {
      FUN_66213e85(piVar1);
      if (((piVar1 != (int *)PTR_DAT_6624a954) && (piVar1 != (int *)&DAT_6624a958)) &&
         (*piVar1 == 0)) {
        FUN_66213d2b(piVar1);
      }
    }
    FUN_6620f506();
    FID_conflict__free(param_1);
  }
  return;
}



void FUN_6620f4fa(void)

{
  leavecritical(0xd);
  return;
}



void FUN_6620f506(void)

{
  leavecritical(0xc);
  return;
}



void __cdecl FUN_6620f50f(void *param_1)

{
  if (DAT_66249f90 != 0xffffffff) {
    if (param_1 == (void *)0x0) {
      param_1 = (void *)FUN_6620ff37(DAT_66249f90);
    }
    FUN_6620ff56(DAT_66249f90,(LPVOID)0x0);
    FUN_6620f3da(param_1);
  }
  return;
}



// Library Function - Single Match
//  __getptd
// 
// Library: Visual Studio 2012 Release

_ptiddata __cdecl __getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x10);
  }
  return p_Var1;
}



// Library Function - Single Match
//  __getptd_noexit
// 
// Library: Visual Studio 2012 Release

_ptiddata __cdecl __getptd_noexit(void)

{
  DWORD dwErrCode;
  _ptiddata _Memory;
  int iVar1;
  DWORD DVar1;
  
  dwErrCode = GetLastError();
  _Memory = (_ptiddata)FUN_6620ff37(DAT_66249f90);
  if (_Memory == (_ptiddata)0x0) {
    _Memory = (_ptiddata)FUN_662102aa(1,0x3bc);
    if (_Memory != (_ptiddata)0x0) {
      iVar1 = FUN_6620ff56(DAT_66249f90,_Memory);
      if (iVar1 == 0) {
        FID_conflict__free(_Memory);
        _Memory = (_ptiddata)0x0;
      }
      else {
        FUN_6620f5cc((int)_Memory,0);
        DVar1 = GetCurrentThreadId();
        _Memory->_thandle = 0xffffffff;
        _Memory->_tid = DVar1;
      }
    }
  }
  SetLastError(dwErrCode);
  return _Memory;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void __cdecl FUN_6620f5cc(int param_1,int param_2)

{
  *(undefined **)(param_1 + 0x5c) = &DAT_6621e350;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x14) = 1;
  *(undefined4 *)(param_1 + 0x70) = 1;
  *(undefined2 *)(param_1 + 0xb8) = 0x43;
  *(undefined2 *)(param_1 + 0x1be) = 0x43;
  *(undefined **)(param_1 + 0x68) = &DAT_6624a4d0;
  *(undefined4 *)(param_1 + 0x3b8) = 0;
  __lock(0xd);
  LOCK();
  **(int **)(param_1 + 0x68) = **(int **)(param_1 + 0x68) + 1;
  FUN_6620f66d();
  __lock(0xc);
  *(int *)(param_1 + 0x6c) = param_2;
  if (param_2 == 0) {
    *(undefined **)(param_1 + 0x6c) = PTR_DAT_6624a954;
  }
  FUN_66213c96(*(int **)(param_1 + 0x6c));
  FUN_6620f676();
  return;
}



void FUN_6620f66d(void)

{
  leavecritical(0xd);
  return;
}



void FUN_6620f676(void)

{
  leavecritical(0xc);
  return;
}



undefined4 FUN_6620f67f(void)

{
  int iVar1;
  DWORD *pDVar1;
  DWORD DVar1;
  
  FUN_6620f92c();
  iVar1 = FUN_662152f0();
  if (iVar1 != 0) {
    DAT_66249f90 = FUN_6620fefa(FUN_6620f3da);
    if (DAT_66249f90 != 0xffffffff) {
      pDVar1 = (DWORD *)FUN_662102aa(1,0x3bc);
      if (pDVar1 != (DWORD *)0x0) {
        iVar1 = FUN_6620ff56(DAT_66249f90,pDVar1);
        if (iVar1 != 0) {
          FUN_6620f5cc((int)pDVar1,0);
          DVar1 = GetCurrentThreadId();
          pDVar1[1] = 0xffffffff;
          *pDVar1 = DVar1;
          return 1;
        }
      }
      FUN_6620f6f5();
      return 0;
    }
  }
  FUN_6620f6f5();
  return 0;
}



void FUN_6620f6f5(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  undefined **ppuVar1;
  undefined **ppuVar2;
  
  if (DAT_66249f90 != 0xffffffff) {
    FUN_6620ff18(DAT_66249f90);
    DAT_66249f90 = 0xffffffff;
  }
  ppuVar1 = &lpCriticalSection_6624aa38;
  ppuVar2 = &lpCriticalSection_6624aa38;
  do {
    lpCriticalSection = (LPCRITICAL_SECTION)*ppuVar2;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) &&
       (((LPCRITICAL_SECTION *)ppuVar2)[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      FID_conflict__free(lpCriticalSection);
      *ppuVar2 = (undefined *)0x0;
    }
    ppuVar2 = (undefined **)((LPCRITICAL_SECTION *)ppuVar2 + 2);
  } while ((int)ppuVar2 < 0x6624ab58);
  do {
    if (((LPCRITICAL_SECTION)*ppuVar1 != (LPCRITICAL_SECTION)0x0) &&
       (((LPCRITICAL_SECTION *)ppuVar1)[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection((LPCRITICAL_SECTION)*ppuVar1);
    }
    ppuVar1 = (undefined **)((LPCRITICAL_SECTION *)ppuVar1 + 2);
  } while ((int)ppuVar1 < 0x6624ab58);
  return;
}



void __cdecl FUN_6620f712(undefined4 param_1)

{
  BOOL BVar1;
  FARPROC pFVar1;
  HMODULE s8;
  
  BVar1 = GetModuleHandleExW(0,u_mscoree_dll_6621e3f0,&s8);
  if (BVar1 != 0) {
    pFVar1 = GetProcAddress(s8,s_CorExitProcess_6621e408);
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(param_1);
    }
  }
  return;
}



void FUN_6620f746(UINT param_1)

{
  FUN_6620f712(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_6620f75c(void)

{
  int iVar1;
  PVOID _Memory;
  void **ppvVar1;
  
  _Memory = DecodePointer(Ptr_6624d3b0);
  for (ppvVar1 = DAT_6624b5c8; (ppvVar1 != (void **)0x0 && (*ppvVar1 != (void *)0x0));
      ppvVar1 = ppvVar1 + 1) {
    FID_conflict__free(*ppvVar1);
  }
  FID_conflict__free(DAT_6624b5c8);
  DAT_6624b5c8 = (void **)0x0;
  for (ppvVar1 = DAT_6624b5c4; (ppvVar1 != (void **)0x0 && (*ppvVar1 != (void *)0x0));
      ppvVar1 = ppvVar1 + 1) {
    FID_conflict__free(*ppvVar1);
  }
  FID_conflict__free(DAT_6624b5c4);
  DAT_6624b5c4 = (void **)0x0;
  FID_conflict__free(DAT_6624b5c0);
  FID_conflict__free(DAT_6624b5bc);
  DAT_6624b5c0 = (void *)0x0;
  DAT_6624b5bc = (void *)0x0;
  if ((_Memory != (PVOID)0xffffffff) && (Ptr_6624d3b0 != (PVOID)0x0)) {
    FID_conflict__free(_Memory);
  }
  Ptr_6624d3b0 = EncodePointer((PVOID)0xffffffff);
  if (DAT_6624c280 != (void *)0x0) {
    FID_conflict__free(DAT_6624c280);
    DAT_6624c280 = (void *)0x0;
  }
  if (DAT_6624c284 != (void *)0x0) {
    FID_conflict__free(DAT_6624c284);
    DAT_6624c284 = (void *)0x0;
  }
  LOCK();
  iVar1 = *DAT_6624a6f4;
  *DAT_6624a6f4 = *DAT_6624a6f4 + -1;
  if ((iVar1 == 1) && (DAT_6624a6f4 != (int *)&DAT_6624a4d0)) {
    FID_conflict__free(DAT_6624a6f4);
    DAT_6624a6f4 = (int *)&DAT_6624a4d0;
  }
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2012 Release

void __cdecl __amsg_exit(int param_1)

{
  code *pcVar1;
  
  __FF_MSGBANNER();
  HandleRuntimeErrorWithLogging(param_1);
  __exit(0xff);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2012 Release

void __cdecl __cexit(void)

{
  _doexit(0,0,1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_6620f894(undefined4 param_1)

{
  BOOL BVar1;
  int iVar1;
  
  if (PTR___fpmath_6621e304 != (undefined *)0x0) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR___fpmath_6621e304);
    if (BVar1 != 0) {
      (*(code *)PTR___fpmath_6621e304)(param_1);
    }
  }
  FUN_6621272a();
  iVar1 = __initterm_e((undefined **)&DAT_6621c258,(undefined **)&DAT_6621c26c);
  if (iVar1 == 0) {
    CheckPointerAppendedSuccessfully(&LAB_662103a3);
    FUN_6620f964((undefined **)&DAT_6621c22c,(undefined **)&DAT_6621c254);
    if (_DAT_6624d3a8 != (code *)0x0) {
      BVar1 = __IsNonwritableInCurrentImage(&DAT_6624d3a8);
      if (BVar1 != 0) {
        (*_DAT_6624d3a8)(0,2,0);
      }
    }
    iVar1 = 0;
  }
  return iVar1;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2012 Release

void __cdecl __exit(int _Code)

{
  _doexit(_Code,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_6620f92c(void)

{
  PVOID pvVar1;
  HMODULE hModule;
  FARPROC pFVar1;
  
  pvVar1 = EncodePointer((PVOID)0x0);
  FUN_66213c89(pvVar1);
  FUN_66212ca8(pvVar1);
  FUN_66215025(pvVar1);
  FUN_662156ae(pvVar1);
  FUN_66210e8b();
  FUN_662158bf(pvVar1);
  hModule = GetModuleHandleW(u_kernel32_dll_6621ca24);
  pFVar1 = GetProcAddress(hModule,s_FlsAlloc_6621e418);
  DAT_6624d320 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_FlsFree_6621e424);
  DAT_6624d324 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_FlsGetValue_6621e42c);
  DAT_6624d328 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_FlsSetValue_6621e438);
  DAT_6624d32c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_InitializeCriticalSectionEx_6621e444);
  DAT_6624d330 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CreateEventExW_6621e460);
  _DAT_6624d334 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CreateSemaphoreExW_6621e470);
  _DAT_6624d338 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_SetThreadStackGuarantee_6621e484);
  _DAT_6624d33c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CreateThreadpoolTimer_6621e49c);
  _DAT_6624d340 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_SetThreadpoolTimer_6621e4b4);
  _DAT_6624d344 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_WaitForThreadpoolTimerCallbacks_6621e4c8);
  _DAT_6624d348 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CloseThreadpoolTimer_6621e4e8);
  _DAT_6624d34c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CreateThreadpoolWait_6621e500);
  _DAT_6624d350 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_SetThreadpoolWait_6621e518);
  _DAT_6624d354 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CloseThreadpoolWait_6621e52c);
  _DAT_6624d358 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_FlushProcessWriteBuffers_6621e540);
  _DAT_6624d35c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_FreeLibraryWhenCallbackReturns_6621e55c);
  _DAT_6624d360 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetCurrentProcessorNumber_6621e57c);
  _DAT_6624d364 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetLogicalProcessorInformation_6621e598);
  _DAT_6624d368 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CreateSymbolicLinkW_6621e5b8);
  _DAT_6624d36c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_SetDefaultDllDirectories_6621e5cc);
  _DAT_6624d370 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_EnumSystemLocalesEx_6621e5e8);
  _DAT_6624d378 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_CompareStringEx_6621e5fc);
  _DAT_6624d374 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetDateFormatEx_6621e60c);
  _DAT_6624d37c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetLocaleInfoEx_6621e61c);
  _DAT_6624d380 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetTimeFormatEx_6621e62c);
  _DAT_6624d384 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetUserDefaultLocaleName_6621e63c);
  _DAT_6624d388 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_IsValidLocaleName_6621e658);
  _DAT_6624d38c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_LCMapStringEx_6621e66c);
  DAT_6624d390 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetCurrentPackageId_6621e67c);
  DAT_6624d394 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetTickCount64_6621e690);
  _DAT_6624d398 = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_GetFileInformationByHandleExW_6621e6a0);
  _DAT_6624d39c = (uint)pFVar1 ^ DAT_6624a120;
  pFVar1 = GetProcAddress(hModule,s_SetFileInformationByHandleW_6621e6c0);
  _DAT_6624d3a0 = (uint)pFVar1 ^ DAT_6624a120;
  return;
}



void __cdecl FUN_6620f964(undefined **param_1,undefined **param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = 0;
  uVar2 = ~-(uint)(param_2 < param_1) & ((uint)((int)param_2 + (3 - (int)param_1)) >> 2);
  if (uVar2 != 0) {
    do {
      if ((code *)*param_1 != (code *)0x0) {
        (*(code *)*param_1)();
      }
      param_1 = (code **)param_1 + 1;
      uVar1 = uVar1 + 1;
    } while (uVar1 < uVar2);
  }
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl __initterm_e(undefined **param_1,undefined **param_2)

{
  int iVar1;
  
  iVar1 = 0;
  while ((param_1 < param_2 && (iVar1 == 0))) {
    if ((code *)*param_1 != (code *)0x0) {
      iVar1 = (*(code *)*param_1)();
    }
    param_1 = (code **)param_1 + 1;
  }
  return;
}



void lockmem8(void)

{
  __lock(8);
  return;
}



void Wleavecritical_session(void)

{
  leavecritical(8);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x6620faee)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _doexit
// 
// Library: Visual Studio 2012 Release

void __cdecl _doexit(UINT param_1,int param_2,int param_3)

{
  PVOID *ppvVar1;
  PVOID pvVar1;
  code *pcVar1;
  PVOID *ppvVar2;
  PVOID *ppvVar3;
  PVOID *ppvVar4;
  PVOID *s20;
  
  __lock(8);
  pcVar1 = DecodePointer_exref;
  if (_DAT_6624b5b4 != 1) {
    _DAT_6624b5dc = 1;
    DAT_6624b5d8 = (undefined)param_3;
    if (param_2 == 0) {
      s20 = (PVOID *)DecodePointer(Ptr_6624d3b0);
      if (s20 != (PVOID *)0x0) {
        ppvVar1 = (PVOID *)DecodePointer(Ptr_6624d3ac);
        ppvVar4 = ppvVar1;
        while (ppvVar1 = ppvVar1 + -1, s20 <= ppvVar1) {
          pvVar1 = EncodePointer((PVOID)0x0);
          if (*ppvVar1 != pvVar1) {
            if (ppvVar1 < s20) break;
            pcVar1 = (code *)(*pcVar1)(*ppvVar1);
            pvVar1 = EncodePointer((PVOID)0x0);
            *ppvVar1 = pvVar1;
            (*pcVar1)();
            pcVar1 = DecodePointer_exref;
            ppvVar2 = (PVOID *)DecodePointer(Ptr_6624d3b0);
            ppvVar3 = (PVOID *)DecodePointer(Ptr_6624d3ac);
            if ((s20 != ppvVar2) || (ppvVar4 != ppvVar3)) {
              ppvVar1 = ppvVar3;
              s20 = ppvVar2;
              ppvVar4 = ppvVar3;
            }
          }
        }
      }
      FUN_6620f964((undefined **)&DAT_6621c270,(undefined **)&DAT_6621c280);
    }
    FUN_6620f964((undefined **)&DAT_6621c284,(undefined **)&DAT_6621c288);
  }
  FUN_6620fae8();
  if (param_3 == 0) {
    _DAT_6624b5b4 = 1;
    leavecritical(8);
    FUN_6620f746(param_1);
    return;
  }
  return;
}



void FUN_6620fae8(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    leavecritical(8);
  }
  return;
}



bool FUN_6620fafd(void)

{
  hHeap_6624b5e8 = GetProcessHeap();
  return hHeap_6624b5e8 != (HANDLE)0x0;
}



void FUN_6620fb12(void)

{
  hHeap_6624b5e8 = (HANDLE)0x0;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_6620fb1a(void)

{
  HANDLE hFile;
  uint uVar1;
  byte bVar1;
  undefined4 uVar2;
  DWORD DVar1;
  HANDLE pvVar1;
  HANDLE *ppvVar1;
  int iVar1;
  _STARTUPINFOW s78;
  int s34;
  uint s30;
  HANDLE *s2c;
  HANDLE *s28;
  HANDLE *s24;
  HANDLE s20;
  undefined s14 [8];
  undefined4 uStack12;
  undefined *s8;
  
  s8 = &DAT_66223c30;
  uStack12 = 0x6620fb26;
  __lock(0xb);
  s8 = (undefined *)0x0;
  s28 = (HANDLE *)FUN_662102aa(0x20,0x40);
  if (s28 == (HANDLE *)0x0) {
    __local_unwind4(&DAT_6624a120,(int)s14,0xfffffffe);
    uVar2 = 0xffffffff;
  }
  else {
    DAT_6624d3a4 = (HANDLE)0x20;
    DAT_6624b5f0 = s28;
    for (; s28 < (DAT_6624b5f0 + 0x200); s28 = s28 + 0x10) {
      *(undefined2 *)(s28 + 1) = 0xa00;
      *s28 = (HANDLE)0xffffffff;
      s28[2] = (HANDLE)0x0;
      *(byte *)(s28 + 9) = *(byte *)(s28 + 9) & 0x80;
      *(byte *)(s28 + 9) = *(byte *)(s28 + 9) & 0x7f;
      *(undefined2 *)((int)s28 + 0x25) = 0xa0a;
      s28[0xe] = (HANDLE)0x0;
      *(undefined *)(s28 + 0xd) = 0;
    }
    GetStartupInfoW(&s78);
    if ((s78.cbReserved2 != 0) && ((HANDLE *)s78.lpReserved2 != (HANDLE *)0x0)) {
      s20 = *(HANDLE *)s78.lpReserved2;
      s2c = (HANDLE *)((int)s78.lpReserved2 + 4);
      s24 = (HANDLE *)((int)s2c + (int)s20);
      if (0x7ff < (int)s20) {
        s20 = (HANDLE)0x800;
      }
      s34 = 1;
      while (iVar1 = s34, (int)DAT_6624d3a4 < (int)s20) {
        s28 = (HANDLE *)FUN_662102aa(0x20,0x40);
        if (s28 == (HANDLE *)0x0) {
          s20 = DAT_6624d3a4;
          break;
        }
        (&DAT_6624b5f0)[iVar1] = s28;
        DAT_6624d3a4 = (HANDLE)((int)DAT_6624d3a4 + 0x20);
        for (; s28 < (HANDLE *)((int)(&DAT_6624b5f0)[iVar1] + 0x800); s28 = s28 + 0x10) {
          *(undefined2 *)(s28 + 1) = 0xa00;
          *s28 = (HANDLE)0xffffffff;
          s28[2] = (HANDLE)0x0;
          *(byte *)(s28 + 9) = *(byte *)(s28 + 9) & 0x80;
          *(undefined2 *)((int)s28 + 0x25) = 0xa0a;
          s28[0xe] = (HANDLE)0x0;
          *(undefined *)(s28 + 0xd) = 0;
        }
        s34 = iVar1 + 1;
      }
      s30 = 0;
      pvVar1 = s20;
      while (uVar1 = s30, (int)s30 < (int)pvVar1) {
        hFile = *s24;
        if ((((hFile != (HANDLE)0xffffffff) && (hFile != (HANDLE)0xfffffffe)) &&
            ((*(byte *)s2c & 1) != 0)) &&
           (((*(byte *)s2c & 8) != 0 || (DVar1 = GetFileType(hFile), pvVar1 = s20, DVar1 != 0)))) {
          ppvVar1 = (HANDLE *)(((uVar1 & 0x1f) * 0x40) + (int)(&DAT_6624b5f0)[(int)uVar1 >> 5]);
          *ppvVar1 = *s24;
          *(byte *)(ppvVar1 + 1) = *(byte *)s2c;
          s28 = ppvVar1;
          FUN_6620ff78((LPCRITICAL_SECTION)(ppvVar1 + 3),4000,0);
          ppvVar1[2] = (HANDLE)((int)ppvVar1[2] + 1);
          pvVar1 = s20;
        }
        s2c = (HANDLE *)((int)s2c + 1);
        s24 = s24 + 1;
        s30 = uVar1 + 1;
      }
    }
    for (iVar1 = 0; s30 = iVar1, iVar1 < 3; iVar1 = iVar1 + 1) {
      ppvVar1 = DAT_6624b5f0 + (iVar1 * 0x10);
      s28 = ppvVar1;
      if ((*ppvVar1 == (HANDLE)0xffffffff) || (*ppvVar1 == (HANDLE)0xfffffffe)) {
        *(undefined *)(ppvVar1 + 1) = 0x81;
        if (iVar1 == 0) {
          DVar1 = 0xfffffff6;
        }
        else {
          DVar1 = 0xfffffff5 - ((iVar1 != 1));
        }
        s20 = GetStdHandle(DVar1);
        if (((s20 == (HANDLE)0xffffffff) || (s20 == (HANDLE)0x0)) ||
           (DVar1 = GetFileType(s20), DVar1 == 0)) {
          *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x40;
          *ppvVar1 = (HANDLE)0xfffffffe;
          if (DAT_6624d300 != 0) {
            *(undefined4 *)(*(int *)(DAT_6624d300 + (iVar1 * 4)) + 0x10) = 0xfffffffe;
          }
        }
        else {
          *ppvVar1 = s20;
          if ((DVar1 & 0xff) == 2) {
            bVar1 = *(byte *)(ppvVar1 + 1) | 0x40;
LAB_6620fd7a:
            *(byte *)(ppvVar1 + 1) = bVar1;
          }
          else if ((DVar1 & 0xff) == 3) {
            bVar1 = *(byte *)(ppvVar1 + 1) | 8;
            goto LAB_6620fd7a;
          }
          FUN_6620ff78((LPCRITICAL_SECTION)(ppvVar1 + 3),4000,0);
          ppvVar1[2] = (HANDLE)((int)ppvVar1[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x80;
      }
    }
    s8 = (undefined *)0xfffffffe;
    FUN_6620fdc5();
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_6620fdc5(void)

{
  leavecritical(0xb);
  return;
}



// Library Function - Single Match
//  __ioterm
// 
// Library: Visual Studio 2012 Release

void __cdecl __ioterm(void)

{
  void *pvVar1;
  LPCRITICAL_SECTION p_Var1;
  void **ppvVar1;
  LPCRITICAL_SECTION lpCriticalSection;
  
  ppvVar1 = (void **)&DAT_6624b5f0;
  do {
    pvVar1 = *ppvVar1;
    if (pvVar1 != (void *)0x0) {
      if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
        lpCriticalSection = (LPCRITICAL_SECTION)((int)pvVar1 + 0xc);
        do {
          if (lpCriticalSection[-1].SpinCount != 0) {
            DeleteCriticalSection(lpCriticalSection);
          }
          p_Var1 = lpCriticalSection + 2;
          lpCriticalSection = (LPCRITICAL_SECTION)&lpCriticalSection[2].LockSemaphore;
        } while (&p_Var1->LockCount < (LONG *)((int)*ppvVar1 + 0x800U));
      }
      FID_conflict__free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    ppvVar1 = ppvVar1 + 1;
  } while ((int)ppvVar1 < 0x6624b6f0);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __free_base
//  _free
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

void __cdecl FID_conflict__free(void *_Memory)

{
  BOOL BVar1;
  int *piVar1;
  DWORD DVar1;
  int iVar1;
  
  if (_Memory != (void *)0x0) {
    BVar1 = HeapFree(hHeap_6624b5e8,0,_Memory);
    if (BVar1 == 0) {
      piVar1 = __errno();
      DVar1 = GetLastError();
      iVar1 = __get_errno_from_oserr(DVar1);
      *piVar1 = iVar1;
    }
  }
  return;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2015 Release

void __cdecl ___security_init_cookie(void)

{
  DWORD DVar1;
  uint s18;
  uint s14;
  _FILETIME s10;
  uint s8;
  
  s10.dwLowDateTime = 0;
  s10.dwHighDateTime = 0;
  if ((DAT_6624a120 == 0xbb40e64e) || ((DAT_6624a120 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&s10);
    s8 = s10.dwHighDateTime ^ s10.dwLowDateTime;
    DVar1 = GetCurrentThreadId();
    s8 = s8 ^ DVar1;
    DVar1 = GetCurrentProcessId();
    s8 = s8 ^ DVar1;
    QueryPerformanceCounter((LARGE_INTEGER *)&s18);
    DAT_6624a120 = s14 ^ s18 ^ s8 ^ (uint)&s8;
    if (DAT_6624a120 == 0xbb40e64e) {
      DAT_6624a120 = 0xbb40e64f;
    }
    else if ((DAT_6624a120 & 0xffff0000) == 0) {
      DAT_6624a120 = DAT_6624a120 | ((DAT_6624a120 | 0x4711) << 0x10);
    }
    DAT_6624a124 = ~DAT_6624a120;
  }
  else {
    DAT_6624a124 = ~DAT_6624a120;
  }
  return;
}



undefined4 FUN_6620fef4(void)

{
  return 1;
}



void __cdecl FUN_6620fefa(undefined4 param_1)

{
  if ((code *)(DAT_6624d320 ^ DAT_6624a120) != (code *)0x0) {
    (*(code *)(DAT_6624d320 ^ DAT_6624a120))(param_1);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x6620ff12. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsAlloc();
  return;
}



void __cdecl FUN_6620ff18(DWORD param_1)

{
  if ((code *)(DAT_6624d324 ^ DAT_6624a120) != (code *)0x0) {
    (*(code *)(DAT_6624d324 ^ DAT_6624a120))();
    return;
  }
  TlsFree(param_1);
  return;
}



void __cdecl FUN_6620ff37(DWORD param_1)

{
  if ((code *)(DAT_6624d328 ^ DAT_6624a120) != (code *)0x0) {
    (*(code *)(DAT_6624d328 ^ DAT_6624a120))();
    return;
  }
  TlsGetValue(param_1);
  return;
}



void __cdecl FUN_6620ff56(DWORD param_1,LPVOID param_2)

{
  if ((code *)(DAT_6624d32c ^ DAT_6624a120) != (code *)0x0) {
    (*(code *)(DAT_6624d32c ^ DAT_6624a120))();
    return;
  }
  TlsSetValue(param_1,param_2);
  return;
}



undefined4 __cdecl FUN_6620ff78(LPCRITICAL_SECTION param_1,DWORD param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  if ((code *)(DAT_6624d330 ^ DAT_6624a120) != (code *)0x0) {
    uVar1 = (*(code *)(DAT_6624d330 ^ DAT_6624a120))(param_1,param_2,param_3);
    return uVar1;
  }
  InitializeCriticalSectionAndSpinCount(param_1,param_2);
  return 1;
}



bool FUN_6620ffa6(void)

{
  int iVar1;
  int iVar2;
  undefined4 s8;
  
  iVar1 = DAT_66249fd8;
  if (DAT_66249fd8 < 0) {
    s8 = 0;
    iVar1 = 0;
    if (((code *)(DAT_6624d394 ^ DAT_6624a120) != (code *)0x0) &&
       (iVar2 = (*(code *)(DAT_6624d394 ^ DAT_6624a120))(&s8,0), iVar2 == 0x7a)) {
      iVar1 = 1;
    }
  }
  DAT_66249fd8 = iVar1;
  return 0 < DAT_66249fd8;
}



void __cdecl Wsleep(DWORD param_1)

{
  Sleep(param_1);
  return;
}



// Library Function - Single Match
//  ___crtTerminateProcess
// 
// Library: Visual Studio 2012 Release

void __cdecl ___crtTerminateProcess(UINT uExitCode)

{
  HANDLE hProcess;
  
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// Library Function - Single Match
//  ___crtUnhandledException
// 
// Library: Visual Studio 2012 Release

LONG __cdecl ___crtUnhandledException(EXCEPTION_POINTERS *exceptionInfo)

{
  LONG LVar1;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar1 = UnhandledExceptionFilter(exceptionInfo);
  return LVar1;
}



LPVOID __cdecl FUN_662102aa(uint param_1,uint param_2)

{
  LPVOID pvVar1;
  DWORD DVar1;
  
  DVar1 = 0;
  while( true ) {
    pvVar1 = __calloc_impl(param_1,param_2,(int *)0x0);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_6624b6f0 == 0) break;
    Wsleep(DVar1);
    DVar1 = DVar1 + 1000;
    if (DAT_6624b6f0 < DVar1) {
      DVar1 = 0xffffffff;
    }
    if (DVar1 == 0xffffffff) {
      return (LPVOID)0x0;
    }
  }
  return (LPVOID)0x0;
}



void * __cdecl FUN_662102f2(size_t param_1)

{
  uint uVar1;
  void *pvVar1;
  DWORD DVar1;
  
  DVar1 = 0;
  while( true ) {
    uVar1 = DAT_6624b6f0;
    pvVar1 = _malloc(param_1);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (uVar1 == 0) break;
    Wsleep(DVar1);
    DVar1 = DVar1 + 1000;
    if (DAT_6624b6f0 < DVar1) {
      DVar1 = 0xffffffff;
    }
    if (DVar1 == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



void * __cdecl realloc_timeout(void *param_1,size_t param_2)

{
  void *realocated_mem;
  DWORD time;
  
  time = 0;
  do {
    realocated_mem = _realloc(param_1,param_2);
    if (realocated_mem != (void *)0x0) {
      return realocated_mem;
    }
    if (param_2 == 0) {
      return (void *)0x0;
    }
    if (DAT_6624b6f0 == 0) {
      return (void *)0x0;
    }
    Wsleep(time);
    time = time + 1000;
    if (DAT_6624b6f0 < time) {
      time = 0xffffffff;
    }
  } while (time != 0xffffffff);
  return (void *)0x0;
}



void FUN_66210383(void)

{
  code **ppcVar1;
  
  for (ppcVar1 = (code **)&DAT_66222c34; ppcVar1 < &DAT_66222c34; ppcVar1 = ppcVar1 + 1) {
    if (*ppcVar1 != (code *)0x0) {
      (**ppcVar1)();
    }
  }
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4
// 
// Library: Visual Studio

void __cdecl __SEH_prolog4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  int *in_FS_OFFSET;
  undefined4 unaff_retaddr;
  uint auStack28 [5];
  undefined s8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack28 + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack28 + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack28 + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack28 + iVar1 + 4) = DAT_6624a120 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack28 + iVar1) = unaff_retaddr;
  *in_FS_OFFSET = (int)s8;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __SEH_epilog4
// 
// Library: Visual Studio

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 *in_FS_OFFSET;
  undefined4 unaff_retaddr;
  
  *in_FS_OFFSET = unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



undefined4 __cdecl FUN_66210430(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3)

{
  int iVar1;
  uint uVar1;
  code *pcVar1;
  BOOL BVar1;
  undefined4 uVar2;
  undefined in_DL;
  undefined extraout_DL;
  undefined uVar3;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined4 extraout_EDX;
  uint extraout_EDX_00;
  uint uVar4;
  undefined4 unaff_EDI;
  int *piVar1;
  undefined8 uVar5;
  undefined uVar6;
  PEXCEPTION_RECORD s1c;
  DWORD s18;
  _EXCEPTION_RECORD *s14;
  PVOID s10;
  uint sc;
  char s5;
  
  s5 = '\0';
  iVar1 = (int)param_2 + 0x10;
  piVar1 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_6624a120);
  s10 = (PVOID)0x1;
  if (*piVar1 != -2) {
    FUN_6620f208((piVar1[1] + iVar1) ^ *(uint *)(*piVar1 + iVar1),in_DL,(char)unaff_EDI);
    in_DL = extraout_DL;
  }
  FUN_6620f208((piVar1[3] + iVar1) ^ *(uint *)(piVar1[2] + iVar1),in_DL,(char)unaff_EDI);
  uVar6 = (undefined)unaff_EDI;
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    s1c = param_1;
    s18 = param_3;
    *(PEXCEPTION_RECORD *)((int)param_2 + -4) = (PEXCEPTION_RECORD)&s1c;
    sc = *(uint *)((int)param_2 + 0xc);
    uVar2 = extraout_EDX;
    if (*(uint *)((int)param_2 + 0xc) == 0xfffffffe) {
      return s10;
    }
    do {
      s14 = (_EXCEPTION_RECORD *)(piVar1 + (sc * 3) + 4);
      uVar1 = s14->ExceptionCode;
      if ((undefined *)piVar1[(sc * 3) + 5] != (undefined *)0x0) {
        uVar5 = __EH4_CallFilterFunc_8((undefined *)piVar1[(sc * 3) + 5]);
        uVar2 = (undefined4)((ulonglong)uVar5 >> 0x20);
        uVar6 = (undefined)unaff_EDI;
        uVar3 = (undefined)((ulonglong)uVar5 >> 0x20);
        s5 = '\x01';
        if ((int)uVar5 < 0) {
          s10 = (PVOID)0x0;
          goto LAB_6621056b;
        }
        if (0 < (int)uVar5) {
          if (((param_1->ExceptionCode == 0xe06d7363) &&
              (PTR____DestructExceptionObject_6621e7a4 != (undefined *)0x0)) &&
             (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_6621e7a4)
             , BVar1 != 0)) {
            (*(code *)PTR____DestructExceptionObject_6621e7a4)(param_1,1);
          }
          FUN_662159f2(param_2,param_1);
          uVar4 = sc;
          if (*(uint *)((int)param_2 + 0xc) != sc) {
            __EH4_LocalUnwind_16((int)param_2,sc,iVar1,&DAT_6624a120);
            uVar4 = extraout_EDX_00;
          }
          uVar3 = (undefined)uVar4;
          *(uint *)((int)param_2 + 0xc) = uVar1;
          if (*piVar1 != -2) {
            FUN_6620f208((piVar1[1] + iVar1) ^ *(uint *)(*piVar1 + iVar1),uVar3,uVar6);
            uVar3 = extraout_DL_01;
          }
          FUN_6620f208((piVar1[3] + iVar1) ^ *(uint *)(piVar1[2] + iVar1),uVar3,uVar6);
          __EH4_TransferToHandler_8((undefined *)s14->ExceptionRecord);
          pcVar1 = (code *)swi(3);
          uVar2 = (*pcVar1)();
          return uVar2;
        }
      }
      uVar6 = (undefined)unaff_EDI;
      uVar3 = (undefined)uVar2;
      sc = uVar1;
    } while (uVar1 != 0xfffffffe);
    if (s5 == '\0') {
      return s10;
    }
  }
  else {
    if (*(int *)((int)param_2 + 0xc) == -2) {
      return s10;
    }
    __EH4_LocalUnwind_16((int)param_2,0xfffffffe,iVar1,&DAT_6624a120);
    uVar3 = extraout_DL_00;
  }
LAB_6621056b:
  if (*piVar1 != -2) {
    FUN_6620f208((piVar1[1] + iVar1) ^ *(uint *)(*piVar1 + iVar1),uVar3,uVar6);
  }
  FUN_6620f208((piVar1[3] + iVar1) ^ *(uint *)(piVar1[2] + iVar1),(char)piVar1[2],uVar6);
  return s10;
}



void FUN_662105d0(void)

{
  float10 in_ST0;
  
  FUN_66215f78((double)in_ST0);
  FUN_662105ed();
  return;
}


/*
Unable to decompile 'FUN_662105ed'
Cause: Exception while decompiling 662105ed: Decompiler process died

*/

/*
Unable to decompile 'FUN_6621068a'
Cause: Exception while decompiling 6621068a: Decompiler process died

*/

/*
Unable to decompile '__set_exp'
Cause: Exception while decompiling 6621075c: Decompiler process died

*/

/*
Unable to decompile '__handle_exc'
Cause: Exception while decompiling 6621078b: Decompiler process died

*/


// Library Function - Single Match
//  __raise_exc
// 
// Library: Visual Studio 2019 Release

void __cdecl
__raise_exc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
           undefined4 param_5,undefined4 param_6)

{
  FUN_6621098a(param_1,param_2,param_3,param_4,param_5,param_6,0);
  return;
}


/*
Unable to decompile 'FUN_6621098a'
Cause: Exception while decompiling 6621098a: Decompiler process died

*/


// Library Function - Single Match
//  __set_errno_from_matherr
// 
// Library: Visual Studio 2019 Release

void __cdecl __set_errno_from_matherr(int param_1)

{
  int *piVar1;
  
  if (param_1 == 1) {
    piVar1 = __errno();
    *piVar1 = 0x21;
  }
  else if ((param_1 - 2U) < 2) {
    piVar1 = __errno();
    *piVar1 = 0x22;
    return;
  }
  return;
}


/*
Unable to decompile '___set_fpsr_sse2'
Cause: Exception while decompiling 66210c9c: Decompiler process died

*/


int FUN_66210d12(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



// Library Function - Single Match
//  __ctrlfp
// 
// Library: Visual Studio 2019 Release

int __ctrlfp(undefined4 param_1,undefined4 param_2)

{
  short in_FPUControlWord;
  
  return (int)in_FPUControlWord;
}


/*
Unable to decompile 'FUN_66210d4e'
Cause: Exception while decompiling 66210d4e: Decompiler process died

*/


int FUN_66210da6(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



// WARNING: Restarted to delay deadcode elimination for space: stack
// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Library: Visual Studio 2012 Release

void __CallSettingFrame_12(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)__NLG_Notify1(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  __NLG_Notify1(param_3);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl _inconsistency(void)
// 
// Library: Visual Studio 2012 Release

void __cdecl _inconsistency(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)DecodePointer(Ptr_6624b6f4);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
  }
  terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl terminate(void)
// 
// Library: Visual Studio 2012 Release
// Ptr parameter of EncodePointer
// 

void __cdecl terminate(void)

{
  code *pcVar1;
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if ((code *)p_Var1->_terminate != (code *)0x0) {
    (*(code *)p_Var1->_terminate)();
  }
  _abort();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  void __cdecl unexpected(void)
// 
// Library: Visual Studio 2012 Release

void __cdecl unexpected(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if ((code *)p_Var1->_unexpected != (code *)0x0) {
    (*(code *)p_Var1->_unexpected)();
  }
  terminate();
  return;
}



void FUN_66210e8b(void)

{
  Ptr_6624b6f4 = EncodePointer(terminate);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___DestructExceptionObject
// 
// Library: Visual Studio 2012 Release

void __cdecl ___DestructExceptionObject(int *param_1)

{
  byte *pbVar1;
  int *piVar1;
  
  if ((((param_1 != (int *)0x0) && (*param_1 == -0x1f928c9d)) && (param_1[4] == 3)) &&
     ((((param_1[5] == 0x19930520 || (param_1[5] == 0x19930521)) || (param_1[5] == 0x19930522)) &&
      (pbVar1 = (byte *)param_1[7], pbVar1 != (byte *)0x0)))) {
    if (*(undefined **)(pbVar1 + 4) == (undefined *)0x0) {
      if (((*pbVar1 & 0x10) != 0) && (piVar1 = *(int **)param_1[6], piVar1 != (int *)0x0)) {
        (**(code **)(*piVar1 + 8))(piVar1);
      }
    }
    else {
      FID_conflict__CallMemberFunction1(param_1[6],*(undefined **)(pbVar1 + 4));
    }
  }
  return;
}



undefined ** __thiscall FUN_66210f27(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_6621e7ac;
  return (undefined **)this;
}


/*
Unable to decompile 'FUN_66210f4d'
Cause: Exception while decompiling 66210f4d: Decompiler process died

*/


// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  void * __cdecl CallCatchBlock(struct EHExceptionRecord *,struct EHRegistrationNode *,struct
// _CONTEXT *,struct _s_FuncInfo const *,void *,int,unsigned long)
// 
// Library: Visual Studio 2012 Release

void * __cdecl
CallCatchBlock(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,
              _s_FuncInfo *param_4,void *param_5,int param_6,unsigned_long param_7)

{
  _ptiddata p_Var1;
  undefined4 s44 [2];
  undefined4 s3c;
  void *s38;
  void *s34;
  undefined4 *s30;
  undefined4 s2c;
  void *s20;
  undefined4 uStack12;
  undefined *s8;
  
  s8 = &DAT_66223cd8;
  uStack12 = 0x66210f7e;
  s20 = param_5;
  s3c = 0;
  s2c = *(undefined4 *)(param_2 + -4);
  s30 = __CreateFrameInfo(s44,*(undefined4 *)(param_1 + 0x18));
  p_Var1 = __getptd();
  s34 = p_Var1->_curexception;
  p_Var1 = __getptd();
  s38 = p_Var1->_curcontext;
  p_Var1 = __getptd();
  p_Var1->_curexception = param_1;
  p_Var1 = __getptd();
  p_Var1->_curcontext = param_3;
  s8 = (undefined *)0x1;
  s20 = _CallCatchBlock2(param_2,param_4,param_5,param_6,param_7);
  s8 = (undefined *)0xfffffffe;
  FUN_662110b9();
  return param_2;
}



void FUN_662110b9(void)

{
  _ptiddata p_Var1;
  int iVar1;
  int unaff_EBP;
  int *unaff_ESI;
  int unaff_EDI;
  
  *(undefined4 *)(unaff_EDI + -4) = *(undefined4 *)(unaff_EBP + -0x28);
  __FindAndUnlinkFrame(*(void **)(unaff_EBP + -0x2c));
  p_Var1 = __getptd();
  p_Var1->_curexception = *(void **)(unaff_EBP + -0x30);
  p_Var1 = __getptd();
  p_Var1->_curcontext = *(void **)(unaff_EBP + -0x34);
  if (((((*unaff_ESI == -0x1f928c9d) && (unaff_ESI[4] == 3)) &&
       ((unaff_ESI[5] == 0x19930520 ||
        ((unaff_ESI[5] == 0x19930521 || (unaff_ESI[5] == 0x19930522)))))) &&
      (*(int *)(unaff_EBP + -0x38) == 0)) &&
     ((*(int *)(unaff_EBP + -0x1c) != 0 &&
      (iVar1 = __IsExceptionObjectToBeDestroyed(unaff_ESI[6]), iVar1 != 0)))) {
    ___DestructExceptionObject(unaff_ESI);
  }
  return;
}



// WARNING: Function: __EH_prolog3_catch replaced with injection: EH_prolog3
// Library Function - Single Match
//  void __cdecl CallUnexpected(struct _s_ESTypeList const *)
// 
// Library: Visual Studio 2012 Release

void __cdecl CallUnexpected(_s_ESTypeList *param_1)

{
  code *pcVar1;
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (p_Var1->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  unexpected();
  p_Var1 = __getptd();
  p_Var1->_curexcspec = param_1;
  Handle_flags_Raise_exc((int *)0x0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  void __cdecl CatchIt(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct _s_CatchableType const
// *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode *,unsigned char)
// 
// Library: Visual Studio 2015 Release

void __cdecl
CatchIt(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
       _s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,
       _s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,unsigned_char param_11)

{
  void *pvVar1;
  
  if (param_7 != (_s_CatchableType *)0x0) {
    ___BuildCatchObject((int)param_1,(int *)param_2,(uint *)param_6,(byte *)param_7);
  }
  if (param_10 == (EHRegistrationNode *)0x0) {
    param_10 = param_2;
  }
  _UnwindNestedFrames(param_10,param_1);
  ___FrameUnwindToState((int)param_2,param_4,(int)param_5,*(int *)param_8);
  *(int *)(param_2 + 8) = *(int *)(param_8 + 4) + 1;
  pvVar1 = CallCatchBlock(param_1,param_2,param_3,param_5,*(void **)(param_6 + 0xc),param_9,0x100);
  if (pvVar1 != (void *)0x0) {
    _JumpToContinuation(pvVar1,param_2);
  }
  return;
}



// Library Function - Single Match
//  int __cdecl ExFilterRethrow(struct _EXCEPTION_POINTERS *)
// 
// Library: Visual Studio 2012 Release

int __cdecl ExFilterRethrow(_EXCEPTION_POINTERS *param_1)

{
  PEXCEPTION_RECORD pEVar1;
  _ptiddata p_Var1;
  
  pEVar1 = param_1->ExceptionRecord;
  if ((((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 3)) &&
      ((pEVar1->ExceptionInformation[0] == 0x19930520 ||
       ((pEVar1->ExceptionInformation[0] == 0x19930521 ||
        (pEVar1->ExceptionInformation[0] == 0x19930522)))))) &&
     (pEVar1->ExceptionInformation[2] == 0)) {
    p_Var1 = __getptd();
    p_Var1->_cxxReThrow = 1;
    return 1;
  }
  return 0;
}


/*
Unable to decompile 'FUN_66211240'
Cause: Exception while decompiling 66211240: Decompiler process died

*/


void __cdecl
FUN_662115dd(int *param_1,undefined4 *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,
            int param_6,int param_7,EHRegistrationNode *param_8)

{
  _ptiddata p_Var1;
  PVOID pvVar1;
  int iVar1;
  _s_HandlerType *p_Var2;
  uint uVar1;
  int *piVar1;
  uint sc;
  uint s8;
  
  if (*param_1 != -0x7ffffffd) {
    p_Var1 = __getptd();
    if (p_Var1->_translator != (void *)0x0) {
      pvVar1 = EncodePointer((PVOID)0x0);
      p_Var1 = __getptd();
      if ((((p_Var1->_translator != pvVar1) && (*param_1 != -0x1fbcb0b3)) &&
          (*param_1 != -0x1fbcbcae)) &&
         (iVar1 = FUN_6620d0da(param_1,param_2,param_3,param_4,param_5,param_7,param_8), iVar1 != 0)
         ) {
        return;
      }
    }
    if (*(int *)(param_5 + 0xc) == 0) {
      _inconsistency();
    }
    iVar1 = FUN_6620d1b1((int)param_5,param_7,param_6,&sc,&s8);
    if (sc < s8) {
      piVar1 = (int *)(iVar1 + 0xc);
      uVar1 = s8;
      do {
        if ((((piVar1[-3] <= param_6) && (param_6 <= piVar1[-2])) &&
            ((iVar1 = *piVar1 * 0x10, *(int *)(piVar1[1] + -0xc + iVar1) == 0 ||
             (uVar1 = s8, *(char *)(*(int *)(piVar1[1] + -0xc + iVar1) + 8) == '\0')))) &&
           (p_Var2 = (_s_HandlerType *)(iVar1 + piVar1[1] + -0x10), ((byte)*p_Var2 & 0x40) == 0)) {
          CatchIt((EHExceptionRecord *)param_1,(EHRegistrationNode *)param_2,param_3,param_4,param_5
                  ,p_Var2,(_s_CatchableType *)0x0,(_s_TryBlockMapEntry *)(piVar1 + -3),param_7,
                  param_8,1);
          uVar1 = s8;
        }
        sc = sc + 1;
        piVar1 = piVar1 + 5;
      } while (sc < uVar1);
    }
  }
  return;
}



uint __cdecl FUN_662116f9(int param_1,int *param_2)

{
  code *pcVar1;
  int *piVar1;
  byte *in_EAX;
  byte *pbVar1;
  byte **ppbVar1;
  uint uVar1;
  int iVar1;
  
  piVar1 = param_2;
  if (param_2 == (int *)0x0) {
    _inconsistency();
    terminate();
    pcVar1 = (code *)swi(3);
    uVar1 = (*pcVar1)();
    return uVar1;
  }
  uVar1 = 0;
  iVar1 = 0;
  if (0 < *param_2) {
    param_2 = (int *)0x0;
    do {
      ppbVar1 = *(byte ***)(*(int *)(param_1 + 0x1c) + 0xc);
      for (pbVar1 = *ppbVar1; in_EAX = pbVar1, 0 < (int)pbVar1; pbVar1 = pbVar1 + -1) {
        ppbVar1 = ppbVar1 + 1;
        in_EAX = (byte *)FUN_66211bfe((byte *)(piVar1[1] + (int)param_2),*ppbVar1,
                                      *(byte **)(param_1 + 0x1c));
        if (in_EAX != (byte *)0x0) {
          uVar1 = 1;
          break;
        }
      }
      iVar1 = iVar1 + 1;
      param_2 = param_2 + 4;
    } while (iVar1 < *piVar1);
  }
  return ((uint)in_EAX & 0xffffff00) | uVar1;
}



// Library Function - Single Match
//  ___AdjustPointer
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl ___AdjustPointer(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_2[1];
  iVar2 = *param_2 + param_1;
  if (-1 < iVar1) {
    iVar2 = iVar2 + *(int *)(*(int *)(iVar1 + param_1) + param_2[2]) + iVar1;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___BuildCatchObject
// 
// Library: Visual Studio 2012 Release

void __cdecl ___BuildCatchObject(int param_1,int *param_2,uint *param_3,byte *param_4)

{
  char cVar1;
  undefined3 extraout_var;
  int *piVar1;
  int iVar1;
  
  piVar1 = param_2;
  if ((*param_3 & 0x80000000) == 0) {
    piVar1 = (int *)((int)param_2 + param_3[2] + 0xc);
  }
  cVar1 = FUN_66211834(param_1,param_2,param_3,param_4);
  iVar1 = ((int)(int3)extraout_var << 8) + cVar1;
  if (iVar1 == 1) {
    ___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    FID_conflict__CallMemberFunction1(piVar1,*(undefined **)(param_4 + 0x18));
  }
  else if (iVar1 == 2) {
    ___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    FID_conflict__CallMemberFunction1(piVar1,*(undefined **)(param_4 + 0x18));
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

char __cdecl FUN_66211834(int param_1,int *param_2,uint *param_3,byte *param_4)

{
  uint uVar1;
  byte bVar1;
  int iVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  undefined3 extraout_var_08;
  undefined3 extraout_var_09;
  undefined4 uVar2;
  
  if (((param_3[1] == 0) || (*(char *)(param_3[1] + 8) == '\0')) ||
     ((param_3[2] == 0 && ((*param_3 & 0x80000000) == 0)))) {
    return '\0';
  }
  uVar1 = *param_3;
  if (-1 < (int)uVar1) {
    param_2 = (int *)((int)param_2 + param_3[2] + 0xc);
  }
  if ((((char)uVar1 < '\0') && ((*param_4 & 0x10) != 0)) && (DAT_6624b6f8 != (code *)0x0)) {
    iVar1 = (*DAT_6624b6f8)();
    bVar1 = FUN_6621607c(iVar1);
    if ((((int)(int3)extraout_var << 8) + bVar1 == 0) ||
       (bVar1 = FUN_6621607c((int)param_2), ((int)(int3)extraout_var_00 << 8) + bVar1 == 0))
    goto LAB_662119d2;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x18);
    if ((uVar1 & 8) == 0) {
      if ((*param_4 & 1) == 0) {
        if (*(int *)(param_4 + 0x18) == 0) {
          bVar1 = FUN_6621607c(iVar1);
          if ((((int)(int3)extraout_var_05 << 8) + bVar1 != 0) &&
             (bVar1 = FUN_6621607c((int)param_2), ((int)(int3)extraout_var_06 << 8) + bVar1 != 0)) {
            uVar2 = *(undefined4 *)(param_4 + 0x14);
            iVar1 = ___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
            FUN_6620dc00(param_2,iVar1,uVar2);
            return '\0';
          }
        }
        else {
          bVar1 = FUN_6621607c(iVar1);
          if (((((int)(int3)extraout_var_07 << 8) + bVar1 != 0) &&
              (bVar1 = FUN_6621607c((int)param_2), ((int)(int3)extraout_var_08 << 8) + bVar1 != 0))
             && (bVar1 = FUN_6621607c(*(int *)(param_4 + 0x18)),
                ((int)(int3)extraout_var_09 << 8) + bVar1 != 0)) {
            return ((*param_4 & 4) != 0) + '\x01';
          }
        }
LAB_662119d2:
        _inconsistency();
        return '\0';
      }
      bVar1 = FUN_6621607c(iVar1);
      if ((((int)(int3)extraout_var_03 << 8) + bVar1 == 0) ||
         (bVar1 = FUN_6621607c((int)param_2), ((int)(int3)extraout_var_04 << 8) + bVar1 == 0))
      goto LAB_662119d2;
      FUN_6620dc00(param_2,*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_4 + 0x14));
      if (*(int *)(param_4 + 0x14) != 4) {
        return '\0';
      }
      if (*param_2 == 0) {
        return '\0';
      }
      iVar1 = *param_2;
      goto LAB_662118c5;
    }
    bVar1 = FUN_6621607c(iVar1);
    if ((((int)(int3)extraout_var_01 << 8) + bVar1 == 0) ||
       (bVar1 = FUN_6621607c((int)param_2), ((int)(int3)extraout_var_02 << 8) + bVar1 == 0))
    goto LAB_662119d2;
    iVar1 = *(int *)(param_1 + 0x18);
  }
  *param_2 = iVar1;
LAB_662118c5:
  iVar1 = ___AdjustPointer(iVar1,(int *)(param_4 + 8));
  *param_2 = iVar1;
  return '\0';
}



// Library Function - Single Match
//  ___FrameUnwindFilter
// 
// Library: Visual Studio 2012 Release

_ptiddata __cdecl ___FrameUnwindFilter(int **param_1)

{
  int *piVar1;
  _ptiddata p_Var1;
  
  piVar1 = *param_1;
  if ((*piVar1 == -0x1fbcbcae) || (*piVar1 == -0x1fbcb0b3)) {
    p_Var1 = __getptd();
    if (0 < p_Var1->_ProcessingThrow) {
      p_Var1 = __getptd();
      p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + -1;
    }
  }
  else if (*piVar1 == -0x1f928c9d) {
    p_Var1 = __getptd();
    p_Var1->_ProcessingThrow = 0;
    terminate();
    return p_Var1;
  }
  return (_ptiddata)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___FrameUnwindToState
// 
// Library: Visual Studio 2012 Release

void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4)

{
  _ptiddata p_Var1;
  int iVar1;
  int iVar2;
  
  if (*(int *)(param_3 + 4) < 0x81) {
    iVar1 = (int)*(char *)(param_1 + 8);
  }
  else {
    iVar1 = *(int *)(param_1 + 8);
  }
  p_Var1 = __getptd();
  p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + 1;
  while (iVar2 = iVar1, iVar2 != param_4) {
    if ((iVar2 < 0) || (*(int *)(param_3 + 4) <= iVar2)) {
      _inconsistency();
    }
    iVar1 = *(int *)(*(int *)(param_3 + 8) + (iVar2 * 8));
    if (*(int *)(*(int *)(param_3 + 8) + 4 + (iVar2 * 8)) != 0) {
      *(int *)(param_1 + 8) = iVar1;
      __CallSettingFrame_12(*(undefined4 *)(*(int *)(param_3 + 8) + 4 + (iVar2 * 8)),param_1,0x103);
    }
  }
  FUN_66211b03();
  if (iVar2 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar2;
  return;
}



void FUN_66211b03(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (0 < p_Var1->_ProcessingThrow) {
    p_Var1 = __getptd();
    p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + -1;
  }
  return;
}


/*
Unable to decompile 'FUN_66211b1d'
Cause: Exception while decompiling 66211b1d: Decompiler process died

*/


undefined4 __cdecl FUN_66211bfe(byte *param_1,byte *param_2,byte *param_3)

{
  int iVar1;
  undefined4 uVar1;
  
  iVar1 = *(int *)(param_1 + 4);
  if (((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) ||
     (((*param_1 & 0x80) != 0 && ((*param_2 & 0x10) != 0)))) {
LAB_66211c5e:
    uVar1 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_66211c3d:
      if ((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
         ((((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)) &&
          (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))))) goto LAB_66211c5e;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_66211c3d;
    }
    uVar1 = 0;
  }
  return uVar1;
}



// Library Function - Single Match
//  __cfltcvt
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release,
// Visual Studio 2012 Release

errno_t __cdecl __cfltcvt(double *arg,char *buffer,size_t param_3,int format,int precision,int caps)

{
  errno_t eVar1;
  
  eVar1 = __cfltcvt_l(arg,buffer,param_3,format,precision,caps,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __cfltcvt_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release,
// Visual Studio 2012 Release

errno_t __cdecl
__cfltcvt_l(double *arg,char *buffer,size_t param_3,int format,int precision,int caps,
           _locale_t plocinfo)

{
  errno_t eVar1;
  
  if ((format == 0x65) || (format == 0x45)) {
    eVar1 = FUN_662121d7((undefined4 *)arg,buffer,param_3,precision,caps,&plocinfo->locinfo);
  }
  else {
    if (format == 0x66) {
      eVar1 = FUN_66212391((undefined4 *)arg,buffer,param_3,precision,&plocinfo->locinfo);
      return eVar1;
    }
    if ((format == 0x61) || (format == 0x41)) {
      eVar1 = FUN_66211d0c((uint *)arg,buffer,param_3,precision,caps,&plocinfo->locinfo);
    }
    else {
      eVar1 = FUN_66212452((undefined4 *)arg,buffer,param_3,precision,caps,&plocinfo->locinfo);
    }
  }
  return eVar1;
}



int __cdecl
FUN_66211d0c(uint *param_1,undefined *param_2,uint param_3,int param_4,int param_5,
            pthreadlocinfo *param_6)

{
  int *piVar1;
  uint uVar1;
  char *pcVar1;
  char *pcVar2;
  uint uVar2;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint uVar3;
  char *pcVar3;
  bool bVar1;
  ulonglong uVar4;
  undefined8 uVar5;
  int iVar1;
  int s30 [2];
  int s28;
  char s24;
  uint s1c;
  uint s18;
  int s14;
  char *s10;
  uint sc;
  int s8;
  
  sc = 0x3ff;
  s8 = 0x30;
  FUN_6620e53b(s30,param_6);
  if (param_4 < 0) {
    param_4 = 0;
  }
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar1 = __errno();
    iVar1 = 0x16;
  }
  else {
    *param_2 = 0;
    if ((param_4 + 0xbU) < param_3) {
      s18 = *param_1;
      if (((param_1[1] >> 0x14) & 0x7ff) == 0x7ff) {
        uVar1 = 0xffffffff;
        if (param_3 != 0xffffffff) {
          uVar1 = param_3 - 2;
        }
        iVar1 = FUN_66212068(param_1,param_2 + 2,uVar1,param_4,0);
        if (iVar1 == 0) {
          if (param_2[2] == '-') {
            *param_2 = 0x2d;
            param_2 = param_2 + 1;
          }
          *param_2 = 0x30;
          param_2[1] = (((param_5 == 0) - 1U) & 0xe0) + 0x78;
          pcVar1 = (char *)FUN_6620ece0(param_2 + 2,0x65);
          if (pcVar1 != (char *)0x0) {
            *pcVar1 = (((param_5 == 0) - 1U) & 0xe0) + 0x70;
            pcVar1[3] = '\0';
          }
          iVar1 = 0;
        }
        else {
          *param_2 = 0;
        }
        goto LAB_66212052;
      }
      if ((param_1[1] & 0x80000000) != 0) {
        *param_2 = 0x2d;
        param_2 = param_2 + 1;
      }
      *param_2 = 0x30;
      param_2[1] = (((param_5 == 0) - 1U) & 0xe0) + 0x78;
      iVar1 = (-(uint)(param_5 != 0) & 0xffffffe0) + 0x27;
      if ((param_1[1] & 0x7ff00000) == 0) {
        param_2[2] = 0x30;
        if ((*param_1 | (param_1[1] & 0xfffff)) == 0) {
          sc = 0;
        }
        else {
          sc = 0x3fe;
        }
      }
      else {
        param_2[2] = 0x31;
      }
      s10 = param_2 + 3;
      pcVar1 = param_2 + 4;
      if (param_4 == 0) {
        *s10 = '\0';
      }
      else {
        *s10 = ***(char ***)(s30[0] + 0x84);
      }
      s1c = param_1[1] & 0xfffff;
      s14 = iVar1;
      if ((s1c != 0) || (*param_1 != 0)) {
        param_2 = (undefined *)0xf0000;
        do {
          if (param_4 < 1) break;
          uVar4 = __aullshr((byte)s8,param_1[1] & (uint)param_2);
          uVar1 = (uint)(ushort)((short)uVar4 + 0x30);
          if (0x39 < uVar1) {
            uVar1 = uVar1 + iVar1;
          }
          *pcVar1 = (char)uVar1;
          pcVar1 = pcVar1 + 1;
          param_2 = (undefined *)((uint)param_2 >> 4);
          s8 = s8 + -4;
          param_4 = param_4 + -1;
        } while (-1 < (short)s8);
        if ((-1 < (short)s8) &&
           (uVar4 = __aullshr((byte)s8,param_1[1] & (uint)param_2), pcVar3 = pcVar1,
           8 < (ushort)uVar4)) {
          while( true ) {
            pcVar2 = pcVar3 + -1;
            if ((*pcVar2 != 'f') && (*pcVar2 != 'F')) break;
            *pcVar2 = '0';
            pcVar3 = pcVar2;
          }
          if (pcVar2 == s10) {
            pcVar3[-2] = pcVar3[-2] + '\x01';
          }
          else if (*pcVar2 == '9') {
            *pcVar2 = (char)s14 + ':';
          }
          else {
            *pcVar2 = *pcVar2 + '\x01';
          }
        }
      }
      if (0 < param_4) {
        FUN_6620d410(pcVar1,0x30,param_4);
        pcVar1 = pcVar1 + param_4;
      }
      if (*s10 == '\0') {
        pcVar1 = s10;
      }
      *pcVar1 = (((param_5 == 0) - 1U) & 0xe0) + 0x70;
      uVar4 = __aullshr(0x34,param_1[1]);
      uVar1 = (uint)(uVar4 & 0x7ff);
      uVar2 = uVar1 - sc;
      uVar1 = (uint)(uVar1 < sc);
      uVar3 = -uVar1;
      if (uVar1 == 0) {
        pcVar1[1] = '+';
      }
      else {
        pcVar1[1] = '-';
        bVar1 = uVar2 != 0;
        uVar2 = -uVar2;
        uVar3 = -(uVar3 + (bVar1));
      }
      pcVar2 = pcVar1 + 2;
      *pcVar2 = '0';
      pcVar3 = pcVar2;
      if (-1 < (int)uVar3) {
        if (((int)uVar3 < 1) && (uVar2 < 1000)) {
LAB_66212003:
          if (((int)uVar3 < 0) || (((int)uVar3 < 1 && (uVar2 < 100)))) goto LAB_66212022;
        }
        else {
          uVar5 = __alldvrm(uVar2,uVar3,1000,0);
          s1c = (uint)((ulonglong)uVar5 >> 0x20);
          *pcVar2 = (char)uVar5 + '0';
          pcVar3 = pcVar1 + 3;
          uVar2 = extraout_ECX;
          if (pcVar3 == pcVar2) goto LAB_66212003;
        }
        uVar5 = __alldvrm(uVar2,uVar3,100,0);
        s1c = (uint)((ulonglong)uVar5 >> 0x20);
        *pcVar3 = (char)uVar5 + '0';
        pcVar3 = pcVar3 + 1;
        uVar2 = extraout_ECX_00;
      }
LAB_66212022:
      if ((pcVar3 != pcVar2) || ((-1 < (int)uVar3 && ((0 < (int)uVar3 || (9 < uVar2)))))) {
        uVar5 = __alldvrm(uVar2,uVar3,10,0);
        *pcVar3 = (char)uVar5 + '0';
        pcVar3 = pcVar3 + 1;
        uVar2 = extraout_ECX_01;
      }
      iVar1 = 0;
      *pcVar3 = (char)uVar2 + '0';
      pcVar3[1] = '\0';
      goto LAB_66212052;
    }
    piVar1 = __errno();
    iVar1 = 0x22;
  }
  *piVar1 = iVar1;
  report_invalid_parameter();
LAB_66212052:
  if (s24 != '\0') {
    *(uint *)(s28 + 0x70) = *(uint *)(s28 + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



void __cdecl
FUN_66212068(undefined4 *param_1,undefined *param_2,uint param_3,int param_4,int param_5)

{
  FUN_662121d7(param_1,param_2,param_3,param_4,param_5,(pthreadlocinfo *)0x0);
  return;
}



int __cdecl
FUN_66212086(undefined *param_1,uint param_2,int param_3,int param_4,int *param_5,char param_6,
            pthreadlocinfo *param_7)

{
  code *pcVar1;
  int *piVar1;
  int iVar1;
  errno_t eVar1;
  int iVar2;
  undefined *puVar1;
  char *_Dst;
  int iVar3;
  int s14 [2];
  int sc;
  char s8;
  
  FUN_6620e53b(s14,param_7);
  if ((param_1 == (undefined *)0x0) || (param_2 == 0)) {
    piVar1 = __errno();
    iVar3 = 0x16;
  }
  else {
    iVar3 = 0;
    iVar1 = param_3;
    if (param_3 < 1) {
      iVar1 = 0;
    }
    if ((iVar1 + 9U) < param_2) {
      if (param_6 != '\0') {
        __shift(param_1 + ((*param_5 == 0x2d)),(uint)(0 < param_3));
      }
      puVar1 = param_1;
      if (*param_5 == 0x2d) {
        *param_1 = 0x2d;
        puVar1 = param_1 + 1;
      }
      if (0 < param_3) {
        *puVar1 = puVar1[1];
        puVar1 = puVar1 + 1;
        *puVar1 = *(undefined *)**(undefined4 **)(s14[0] + 0x84);
      }
      _Dst = puVar1 + (uint)(param_6 == '\0') + param_3;
      puVar1 = (undefined *)0xffffffff;
      if (param_2 != 0xffffffff) {
        puVar1 = param_1 + (param_2 - (int)_Dst);
      }
      eVar1 = _strcpy_s(_Dst,(rsize_t)puVar1,s_e_000_6621e7c4);
      if (eVar1 != 0) {
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        pcVar1 = (code *)swi(3);
        iVar1 = (*pcVar1)();
        return iVar1;
      }
      if (param_4 != 0) {
        *_Dst = 'E';
      }
      if (*(char *)param_5[3] != '0') {
        iVar1 = param_5[1] + -1;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
          _Dst[1] = '-';
        }
        if (99 < iVar1) {
          iVar2 = iVar1 / 100;
          iVar1 = iVar1 % 100;
          _Dst[2] = _Dst[2] + (char)iVar2;
        }
        if (9 < iVar1) {
          iVar2 = iVar1 / 10;
          iVar1 = iVar1 % 10;
          _Dst[3] = _Dst[3] + (char)iVar2;
        }
        _Dst[4] = _Dst[4] + (char)iVar1;
      }
      if (((DAT_6624c28c & 1) != 0) && (_Dst[2] == '0')) {
        FUN_6620dc00(_Dst + 2,_Dst + 3,3);
      }
      goto LAB_662121b7;
    }
    piVar1 = __errno();
    iVar3 = 0x22;
  }
  *piVar1 = iVar3;
  report_invalid_parameter();
LAB_662121b7:
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return iVar3;
}



void __cdecl
FUN_662121d7(undefined4 *param_1,undefined *param_2,uint param_3,int param_4,int param_5,
            pthreadlocinfo *param_6)

{
  int *piVar1;
  int iVar1;
  uint uVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar2;
  undefined uVar3;
  int in_stack_ffffffd0;
  char s20 [24];
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  FUN_66216539(*param_1,param_1[1],(int *)&stack0xffffffd0,s20,0x16);
  if (param_2 == (undefined *)0x0) {
    piVar1 = __errno();
    uVar3 = (undefined)in_stack_ffffffd0;
  }
  else {
    if (param_3 != 0) {
      uVar1 = 0xffffffff;
      if (param_3 != 0xffffffff) {
        uVar1 = (param_3 - ((in_stack_ffffffd0 == 0x2d))) - (uint)(0 < param_4);
      }
      iVar1 = FUN_66216277(param_2 + (uint)(0 < param_4) + (uint)(in_stack_ffffffd0 == 0x2d),uVar1,
                           param_4 + 1,(int)&stack0xffffffd0);
      uVar3 = (undefined)in_stack_ffffffd0;
      if (iVar1 == 0) {
        FUN_66212086(param_2,param_3,param_4,param_5,(int *)&stack0xffffffd0,'\0',param_6);
        uVar2 = extraout_DL_01;
      }
      else {
        *param_2 = 0;
        uVar2 = extraout_DL_00;
      }
      goto LAB_66212294;
    }
    piVar1 = __errno();
    uVar3 = (undefined)in_stack_ffffffd0;
  }
  *piVar1 = 0x16;
  report_invalid_parameter();
  uVar2 = extraout_DL;
LAB_66212294:
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,uVar2,uVar3);
  return;
}



undefined4 __cdecl
FUN_662122a5(char *param_1,int param_2,int param_3,int *param_4,char param_5,pthreadlocinfo *param_6
            )

{
  int iVar1;
  int *piVar1;
  undefined4 uVar1;
  char *pcVar1;
  int s18 [2];
  int s10;
  char sc;
  int s8;
  
  s8 = param_4[1] + -1;
  FUN_6620e53b(s18,param_6);
  if ((param_1 == (char *)0x0) || (param_2 == 0)) {
    piVar1 = __errno();
    uVar1 = 0x16;
    *piVar1 = 0x16;
    report_invalid_parameter();
  }
  else {
    uVar1 = 0;
    if ((param_5 != '\0') && (s8 == param_3)) {
      *(undefined2 *)(param_1 + (uint)(*param_4 == 0x2d) + s8) = 0x30;
    }
    if (*param_4 == 0x2d) {
      *param_1 = '-';
      param_1 = param_1 + 1;
    }
    if (param_4[1] < 1) {
      __shift(param_1,1);
      *param_1 = '0';
      pcVar1 = param_1 + 1;
    }
    else {
      pcVar1 = param_1 + param_4[1];
    }
    if (0 < param_3) {
      __shift(pcVar1,1);
      *pcVar1 = ***(char ***)(s18[0] + 0x84);
      iVar1 = param_4[1];
      if (iVar1 < 0) {
        if (param_5 == '\0') {
          if (SBORROW4(param_3,-iVar1) == (param_3 + iVar1) < 0) {
            param_3 = -iVar1;
          }
        }
        else {
          param_3 = -iVar1;
        }
        __shift(pcVar1 + 1,param_3);
        FUN_6620d410(pcVar1 + 1,0x30,param_3);
      }
    }
  }
  if (sc != '\0') {
    *(uint *)(s10 + 0x70) = *(uint *)(s10 + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



void __cdecl
FUN_66212391(undefined4 *param_1,char *param_2,int param_3,int param_4,pthreadlocinfo *param_5)

{
  int *piVar1;
  int iVar1;
  uint uVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar2;
  undefined uVar3;
  int in_stack_ffffffd0;
  int s2c;
  char s20 [24];
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  FUN_66216539(*param_1,param_1[1],(int *)&stack0xffffffd0,s20,0x16);
  if (param_2 == (char *)0x0) {
    piVar1 = __errno();
    uVar3 = (undefined)in_stack_ffffffd0;
    *piVar1 = 0x16;
    report_invalid_parameter();
    uVar2 = extraout_DL;
  }
  else if (param_3 == 0) {
    piVar1 = __errno();
    uVar3 = (undefined)in_stack_ffffffd0;
    *piVar1 = 0x16;
    report_invalid_parameter();
    uVar2 = extraout_DL_00;
  }
  else {
    uVar1 = 0xffffffff;
    if (param_3 != -1) {
      uVar1 = param_3 - (uint)(in_stack_ffffffd0 == 0x2d);
    }
    iVar1 = FUN_66216277(param_2 + ((in_stack_ffffffd0 == 0x2d)),uVar1,s2c + param_4,
                         (int)&stack0xffffffd0);
    uVar3 = (undefined)in_stack_ffffffd0;
    if (iVar1 == 0) {
      FUN_662122a5(param_2,param_3,param_4,(int *)&stack0xffffffd0,'\0',param_5);
      uVar2 = extraout_DL_02;
    }
    else {
      *param_2 = '\0';
      uVar2 = extraout_DL_01;
    }
  }
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,uVar2,uVar3);
  return;
}



// WARNING: Removing unreachable block (ram,0x66212505)
// WARNING: Removing unreachable block (ram,0x6621250c)

void __cdecl
FUN_66212452(undefined4 *param_1,char *param_2,uint param_3,int param_4,int param_5,
            pthreadlocinfo *param_6)

{
  int *piVar1;
  uint uVar1;
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined uVar2;
  undefined uVar3;
  int in_stack_ffffffcc;
  int s30;
  char s20 [24];
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  FUN_66216539(*param_1,param_1[1],(int *)&stack0xffffffcc,s20,0x16);
  if (param_2 == (char *)0x0) {
    piVar1 = __errno();
    uVar3 = (undefined)in_stack_ffffffcc;
    *piVar1 = 0x16;
    report_invalid_parameter();
    uVar2 = extraout_DL;
  }
  else if (param_3 == 0) {
    piVar1 = __errno();
    uVar3 = (undefined)in_stack_ffffffcc;
    *piVar1 = 0x16;
    report_invalid_parameter();
    uVar2 = extraout_DL_00;
  }
  else {
    uVar1 = 0xffffffff;
    if (param_3 != 0xffffffff) {
      uVar1 = param_3 - ((in_stack_ffffffcc == 0x2d));
    }
    iVar1 = FUN_66216277(param_2 + ((in_stack_ffffffcc == 0x2d)),uVar1,param_4,(int)&stack0xffffffcc
                        );
    uVar3 = (undefined)in_stack_ffffffcc;
    if (iVar1 == 0) {
      if (((s30 + -1) < -4) || (param_4 <= (s30 + -1))) {
        FUN_66212086(param_2,param_3,param_4,param_5,(int *)&stack0xffffffcc,'\x01',param_6);
        uVar2 = extraout_DL_03;
      }
      else {
        FUN_662122a5(param_2,param_3,param_4,(int *)&stack0xffffffcc,'\x01',param_6);
        uVar2 = extraout_DL_02;
      }
    }
    else {
      *param_2 = '\0';
      uVar2 = extraout_DL_01;
    }
  }
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,uVar2,uVar3);
  return;
}



void __cdecl FUN_66212551(char *param_1)

{
  FUN_66212562(param_1,(pthreadlocinfo *)0x0);
  return;
}



void __cdecl FUN_66212562(char *param_1,pthreadlocinfo *param_2)

{
  char cVar1;
  char *pcVar1;
  int s14 [2];
  int sc;
  char s8;
  char *pcVar2;
  
  FUN_6620e53b(s14,param_2);
  cVar1 = *param_1;
  if (cVar1 != '\0') {
    do {
      if (cVar1 == ***(char ***)(s14[0] + 0x84)) break;
      param_1 = param_1 + 1;
      cVar1 = *param_1;
    } while (cVar1 != '\0');
  }
  if (*param_1 != '\0') {
    do {
      param_1 = param_1 + 1;
      cVar1 = *param_1;
      pcVar1 = param_1;
      if ((cVar1 == '\0') || (cVar1 == 'e')) break;
    } while (cVar1 != 'E');
    do {
      pcVar2 = pcVar1;
      pcVar1 = pcVar2 + -1;
    } while (*pcVar1 == '0');
    if (*pcVar1 == ***(char ***)(s14[0] + 0x84)) {
      pcVar1 = pcVar2 + -2;
    }
    do {
      cVar1 = *param_1;
      pcVar1 = pcVar1 + 1;
      param_1 = param_1 + 1;
      *pcVar1 = cVar1;
    } while (cVar1 != '\0');
  }
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return;
}



void __cdecl FUN_662125e2(uint param_1,uint *param_2,char *param_3)

{
  FUN_662125fa(param_1,param_2,param_3,(pthreadlocinfo *)0x0);
  return;
}



void __cdecl FUN_662125fa(uint param_1,uint *param_2,char *param_3,pthreadlocinfo *param_4)

{
  uint sc;
  uint s8;
  
  if (param_1 == 0) {
    FUN_66216459(&param_1,param_3,param_4);
    *param_2 = param_1;
  }
  else {
    FUN_662163cb(&sc,param_3,param_4);
    *param_2 = sc;
    param_2[1] = s8;
  }
  return;
}



void __cdecl FUN_6621263c(byte *param_1)

{
  FUN_6621264d(param_1,(pthreadlocinfo *)0x0);
  return;
}



void __cdecl FUN_6621264d(byte *param_1,pthreadlocinfo *param_2)

{
  byte bVar1;
  int iVar1;
  byte bVar2;
  bool bVar3;
  int s14 [2];
  int sc;
  char s8;
  
  FUN_6620e53b(s14,param_2);
  iVar1 = _tolower((int)(char)*param_1);
  bVar3 = iVar1 == 0x65;
  while (!bVar3) {
    param_1 = param_1 + 1;
    iVar1 = _isdigit((uint)*param_1);
    bVar3 = iVar1 == 0;
  }
  iVar1 = _tolower((int)(char)*param_1);
  if (iVar1 == 0x78) {
    param_1 = param_1 + 2;
  }
  bVar2 = *param_1;
  *param_1 = ***(byte ***)(s14[0] + 0x84);
  do {
    param_1 = param_1 + 1;
    bVar1 = *param_1;
    *param_1 = bVar2;
    bVar2 = bVar1;
  } while (*param_1 != 0);
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  __positive
// 
// Library: Visual Studio 2012 Release

int __cdecl __positive(double *arg)

{
  if (0.0 < *arg != (*arg == 0.0)) {
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  __shift
// 
// Library: Visual Studio 2012 Release

void __cdecl __shift(char *param_1,int param_2)

{
  size_t sVar1;
  
  if (param_2 != 0) {
    sVar1 = _strlen(param_1);
    FUN_6620dc00(param_1 + param_2,param_1,sVar1 + 1);
  }
  return;
}



// Library Function - Single Match
//  __setdefaultprecision
// 
// Library: Visual Studio 2012 Release

void __setdefaultprecision(void)

{
  code *pcVar1;
  errno_t eVar1;
  
  eVar1 = __controlfp_s((uint *)0x0,0x10000,0x30000);
  if (eVar1 == 0) {
    return;
  }
  __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_6621272a(void)

{
  PVOID pvVar1;
  uint uVar1;
  
  uVar1 = 0;
  do {
    pvVar1 = EncodePointer(*(PVOID *)((int)&Ptr_6624a128 + uVar1));
    *(PVOID *)((int)&Ptr_6624a128 + uVar1) = pvVar1;
    uVar1 = uVar1 + 4;
  } while (uVar1 < 0x28);
  return;
}



// WARNING: Removing unreachable block (ram,0x66212841)
// WARNING: Removing unreachable block (ram,0x662128fd)
// WARNING: Removing unreachable block (ram,0x66212891)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_66212811(void)

{
  int *piVar1;
  uint *puVar1;
  int iVar1;
  BOOL BVar1;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  _DAT_6624b6fc = 0;
  DAT_6624a150 = DAT_6624a150 | 1;
  BVar1 = IsProcessorFeaturePresent(10);
  uVar1 = DAT_6624a150;
  if (BVar1 != 0) {
    _DAT_6624b6fc = 1;
    piVar1 = (int *)cpuid_basic_info(0);
    puVar1 = (uint *)cpuid_Version_info(1);
    uVar2 = puVar1[3];
    if ((((piVar1[2] ^ 0x49656e69U) | (piVar1[3] ^ 0x6c65746eU) | (piVar1[1] ^ 0x756e6547U)) == 0)
       && (((((uVar1 = *puVar1 & 0xfff3ff0, uVar1 == 0x106c0 || (uVar1 == 0x20660)) ||
             (uVar1 == 0x20670)) || ((uVar1 == 0x30650 || (uVar1 == 0x30660)))) ||
           (uVar1 == 0x30670)))) {
      DAT_6624b700 = DAT_6624b700 | 1;
    }
    if (*piVar1 < 7) {
      uVar3 = 0;
    }
    else {
      iVar1 = cpuid_Extended_Feature_Enumeration_info(7);
      uVar3 = *(uint *)(iVar1 + 4);
      if ((uVar3 & 0x200) != 0) {
        DAT_6624b700 = DAT_6624b700 | 2;
      }
    }
    uVar1 = DAT_6624a150 | 2;
    if ((uVar2 & 0x100000) != 0) {
      _DAT_6624b6fc = 2;
      uVar1 = DAT_6624a150 | 6;
      if (((uVar2 & 0x8000000) != 0) && ((uVar2 & 0x10000000) != 0)) {
        _DAT_6624b6fc = 3;
        uVar1 = DAT_6624a150 | 0xe;
        if ((uVar3 & 0x20) != 0) {
          _DAT_6624b6fc = 5;
          uVar1 = DAT_6624a150 | 0x2e;
        }
      }
    }
  }
  DAT_6624a150 = uVar1;
  return 0;
}



uint __cdecl
wide_character_to_integer(ushort *stringa_ptr,ushort **string,uint char_flags,uint param_4)

{
  int *exit_errno;
  uint chartypes;
  int char_digits;
  uint uVar1;
  uint chardigits2;
  uint uVar2;
  ushort *string_buffer;
  uint s8;
  ushort stringa;
  ushort *stringa_buffer;
  
  if (string != (ushort **)0x0) {
    *string = stringa_ptr;
  }
  if ((stringa_ptr == (ushort *)0x0) ||
     ((char_flags != 0 && (((int)char_flags < 2 || (0x24 < (int)char_flags)))))) {
    exit_errno = __errno();
    *exit_errno = 22;
    report_invalid_parameter();
    return 0;
  }
  stringa = *stringa_ptr;
  uVar2 = 0;
  stringa_buffer = stringa_ptr;
  while( true ) {
    string_buffer = stringa_buffer + 1;
    chartypes = get_char_types(stringa,8);
    if (chartypes == 0) break;
    stringa = *string_buffer;
    stringa_buffer = string_buffer;
  }
  if (stringa == 45) {
    param_4 = param_4 | 2;
LAB_662129fd:
    stringa = *string_buffer;
    string_buffer = stringa_buffer + 2;
  }
  else if (stringa == 0x2b) goto LAB_662129fd;
  chartypes = (uint)stringa;
  if (char_flags == 0) {
    char_digits = __wchartodigit(stringa);
    if (char_digits != 0) {
      char_flags = 10;
      goto LAB_66212a6d;
    }
    if ((*string_buffer != 0x78) && (*string_buffer != 0x58)) {
      char_flags = 8;
      goto LAB_66212a6d;
    }
    char_flags = 0x10;
  }
  if (((char_flags == 0x10) && (char_digits = __wchartodigit(stringa), char_digits == 0)) &&
     ((*string_buffer == 0x78 || (*string_buffer == 0x58)))) {
    chartypes = (uint)string_buffer[1];
    string_buffer = string_buffer + 2;
  }
LAB_66212a6d:
  uVar1 = (uint)(0xffffffff / (ulonglong)char_flags);
  s8 = param_4;
  do {
    stringa = (ushort)chartypes;
    chardigits2 = __wchartodigit(stringa);
    if (chardigits2 == 0xffffffff) {
      if (((stringa < 0x41) || (0x5a < stringa)) && (0x19 < (ushort)(stringa - 0x61))) {
LAB_66212aa8:
        string_buffer = string_buffer + -1;
        if ((s8 & 8) == 0) {
          if (string != (ushort **)0x0) {
            string_buffer = stringa_ptr;
          }
          uVar2 = 0;
        }
        else if (((s8 & 4) != 0) ||
                (((s8 & 1) == 0 &&
                 ((((s8 & 2) != 0 && (0x80000000 < uVar2)) ||
                  (((s8 & 2) == 0 && (0x7fffffff < uVar2)))))))) {
          exit_errno = __errno();
          *exit_errno = 0x22;
          if ((s8 & 1) == 0) {
            uVar2 = (((s8 & 2) != 0)) + 0x7fffffff;
          }
          else {
            uVar2 = 0xffffffff;
          }
        }
        if (string != (ushort **)0x0) {
          *string = string_buffer;
        }
        if ((s8 & 2) != 0) {
          uVar2 = -uVar2;
        }
        return uVar2;
      }
      if ((ushort)(stringa - 0x61) < 0x1a) {
        chartypes = chartypes - 0x20;
      }
      chardigits2 = chartypes - 0x37;
    }
    if (char_flags <= chardigits2) goto LAB_66212aa8;
    if ((uVar2 < uVar1) ||
       ((uVar2 == uVar1 && (chardigits2 <= (uint)(0xffffffff % (ulonglong)char_flags))))) {
      uVar2 = (uVar2 * char_flags) + chardigits2;
      s8 = s8 | 8;
    }
    else {
      s8 = s8 | 0xc;
      if (string == (ushort **)0x0) goto LAB_66212aa8;
    }
    chartypes = (uint)*string_buffer;
    string_buffer = string_buffer + 1;
  } while( true );
}



void __cdecl Wwide_character_to_integer(ushort *param_1,ushort **param_2,uint param_3)

{
                    // This is a wrapper
  wide_character_to_integer(param_1,param_2,param_3,0);
  return;
}



void __cdecl FUN_66212b83(int param_1,DWORD param_2,DWORD param_3)

{
  uint uVar1;
  BOOL BVar1;
  LONG LVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  undefined uVar3;
  
  uVar1 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  if (param_1 != -1) {
    FUN_662168b4();
  }
  FUN_6620d410();
  uVar3 = 0xdc;
  BVar1 = IsDebuggerPresent();
  LVar1 = ___crtUnhandledException((EXCEPTION_POINTERS *)&stack0xfffffcd4);
  uVar2 = extraout_DL;
  if (((LVar1 == 0) && (BVar1 == 0)) && (param_1 != -1)) {
    FUN_662168b4();
    uVar2 = extraout_DL_00;
  }
  FUN_6620f208(uVar1 ^ (uint)&stack0xfffffffc,uVar2,uVar3);
  return;
}



void __cdecl FUN_66212ca8(PVOID param_1)

{
  Ptr_6624b704 = param_1;
  return;
}



// Library Function - Single Match
//  __invalid_parameter
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void __invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,
                        uintptr_t param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)DecodePointer(Ptr_6624b704);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x66212cc9. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
  UNRECOVERED_JUMPTABLE = (code *)swi(3);
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void report_invalid_parameter(void)

{
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2012 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  code *pcVar1;
  BOOL BVar1;
  
  BVar1 = IsProcessorFeaturePresent(0x17);
  if (BVar1 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
  }
  FUN_66212b83(2,0xc0000417,1);
  ___crtTerminateProcess(0xc0000417);
  return;
}



uint __cdecl FUN_66212d1b(uint param_1,FILE *param_2)

{
  uint uVar1;
  char *pcVar1;
  FILE *_File;
  uint uVar2;
  int *piVar1;
  undefined **ppuVar1;
  int iVar1;
  undefined *puVar1;
  FILE *pFVar1;
  longlong lVar1;
  
  _File = param_2;
  uVar2 = __fileno(param_2);
  uVar1 = _File->_flag;
  if ((uVar1 & 0x82) == 0) {
    piVar1 = __errno();
    *piVar1 = 9;
LAB_66212d3f:
    _File->_flag = _File->_flag | 0x20;
    return 0xffffffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar1 = __errno();
    *piVar1 = 0x22;
    goto LAB_66212d3f;
  }
  pFVar1 = (FILE *)0x0;
  if ((uVar1 & 1) != 0) {
    _File->_cnt = 0;
    if ((uVar1 & 0x10) == 0) {
      _File->_flag = uVar1 | 0x20;
      return 0xffffffff;
    }
    _File->_ptr = _File->_base;
    _File->_flag = uVar1 & 0xfffffffe;
  }
  uVar1 = _File->_flag;
  _File->_cnt = 0;
  _File->_flag = (uVar1 & 0xffffffef) | 2;
  if (((uVar1 & 0x10c) == 0) &&
     (((ppuVar1 = FUN_66215abc(), _File != (FILE *)(ppuVar1 + 8) &&
       (ppuVar1 = FUN_66215abc(), _File != (FILE *)(ppuVar1 + 0x10))) ||
      (iVar1 = FUN_662168e0(uVar2), iVar1 == 0)))) {
    __getbuf(_File);
  }
  if ((_File->_flag & 0x108U) == 0) {
    param_2 = (FILE *)0x1;
    pFVar1 = (FILE *)FUN_66216934(uVar2,&param_1,1);
  }
  else {
    pcVar1 = _File->_base;
    param_2 = (FILE *)(_File->_ptr + -(int)pcVar1);
    _File->_ptr = pcVar1 + 1;
    _File->_cnt = _File->_bufsiz + -1;
    if ((int)param_2 < 1) {
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar1 = &DAT_66249f98;
      }
      else {
        puVar1 = (undefined *)(((uVar2 & 0x1f) * 0x40) + (&DAT_6624b5f0)[(int)uVar2 >> 5]);
      }
      if (((puVar1[4] & 0x20) != 0) && (lVar1 = FUN_66217288(uVar2,0,0,2), lVar1 == -1))
      goto LAB_66212e56;
    }
    else {
      pFVar1 = (FILE *)FUN_66216934(uVar2,pcVar1,param_2);
    }
    *_File->_base = (char)param_1;
  }
  if (pFVar1 == param_2) {
    return param_1 & 0xff;
  }
LAB_66212e56:
  _File->_flag = _File->_flag | 0x20;
  return 0xffffffff;
}



// WARNING: Could not reconcile some variable overlaps

void __cdecl FUN_66212e6a(int param_1,ushort *param_2,pthreadlocinfo *param_3,int **param_4)

{
  ushort uVar1;
  ushort *puVar1;
  int *piVar1;
  uint uVar2;
  undefined3 extraout_var;
  int iVar1;
  code *pcVar1;
  char *pcVar2;
  char *pcVar3;
  int extraout_ECX;
  undefined extraout_DL;
  undefined uVar3;
  undefined extraout_DL_00;
  uint uVar4;
  int *piVar2;
  int **ppiVar1;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  bool bVar1;
  longlong lVar1;
  undefined *puVar2;
  undefined4 uVar5;
  pthreadlocinfo *pptVar1;
  undefined uVar6;
  int *in_stack_fffffb74;
  uint s464;
  int s460;
  undefined4 s45c;
  int *s458;
  pthreadlocinfo s454 [2];
  int s44c;
  char s448;
  int s444;
  byte s440;
  undefined s43f;
  ushort s43c;
  short s43a;
  int s438;
  int *s434;
  int s430;
  int s42c;
  uint s428;
  int s424;
  int *s420;
  int *s41c;
  uint s418;
  int **s414;
  char *s410;
  ushort *s40c;
  int s408 [127];
  undefined4 s209;
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  s42c = param_1;
  s40c = param_2;
  uVar4 = 0;
  s414 = param_4;
  s460 = 0;
  piVar2 = (int *)0x0;
  s418 = 0;
  s434 = (int *)0x0;
  s41c = (int *)0x0;
  s428 = 0;
  s45c = 0;
  s444 = 0;
  s430 = 0;
  FUN_6620e53b(s454,param_3);
  piVar1 = __errno();
  uVar6 = SUB41(in_stack_fffffb74,0);
  if ((s42c == 0) || (s40c == (ushort *)0x0)) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    report_invalid_parameter();
    uVar3 = extraout_DL;
    if (s448 != '\0') {
      *(uint *)(s44c + 0x70) = *(uint *)(s44c + 0x70) & 0xfffffffd;
    }
  }
  else {
    uVar1 = *s40c;
    pcVar3 = (char *)0x0;
    s410 = (char *)0x0;
    s424 = 0;
    s438 = 0;
    s458 = (int *)0x0;
    piVar4 = (int *)PTR_DAT_6624adf0;
    puVar1 = s40c;
    while (s420 = (int *)(uint)uVar1, s40c = puVar1, PTR_DAT_6624adf0 = (undefined *)piVar4,
          uVar1 != 0) {
      uVar6 = SUB41(in_stack_fffffb74,0);
      s40c = puVar1 + 1;
      if (s424 < 0) break;
      if ((ushort)(uVar1 - 0x20) < 0x59) {
        uVar2 = (int)*(char *)(s420 + 0x19887db0) & 0xf;
      }
      else {
        uVar2 = 0;
      }
      s438 = (int)(char)(&DAT_6621f6e0)[(uVar2 * 8) + s438] >> 4;
      switch(s438) {
      case 0:
switchD_66212fd5_caseD_0:
        s430 = 1;
        _write_char(s420,s42c,&s424);
        pcVar3 = s410;
        break;
      case 1:
        s41c = (int *)0xffffffff;
        uVar4 = 0;
        s45c = 0;
        s444 = 0;
        s434 = (int *)0x0;
        s428 = 0;
        s418 = 0;
        s430 = 0;
        break;
      case 2:
        if (s420 == (int *)0x20) {
          uVar4 = uVar4 | 2;
          s418 = uVar4;
        }
        else if (s420 == (int *)0x23) {
          uVar4 = uVar4 | 0x80;
          s418 = uVar4;
        }
        else if (s420 == (int *)0x2b) {
          uVar4 = uVar4 | 1;
          s418 = uVar4;
        }
        else if (s420 == (int *)0x2d) {
          uVar4 = uVar4 | 4;
          s418 = uVar4;
        }
        else if (s420 == (int *)&DAT_30) {
          uVar4 = uVar4 | 8;
          s418 = uVar4;
        }
        break;
      case 3:
        if (uVar1 == 0x2a) {
          s434 = *s414;
          s414 = s414 + 1;
          if ((int)s434 < 0) {
            uVar4 = uVar4 | 4;
            s434 = (int *)-(int)s434;
            s418 = uVar4;
          }
        }
        else {
          s434 = (int *)((int)s420 + ((int)s434 * 10) + -0x30);
          pcVar3 = s410;
        }
        break;
      case 4:
        s41c = (int *)0x0;
        break;
      case 5:
        if (uVar1 == 0x2a) {
          s41c = *s414;
          s414 = s414 + 1;
          if ((int)s41c < 0) {
            s41c = (int *)0xffffffff;
          }
        }
        else {
          s41c = (int *)((int)s420 + ((int)s41c * 10) + -0x30);
          pcVar3 = s410;
        }
        break;
      case 6:
        if (s420 == (int *)0x49) {
          uVar1 = *s40c;
          if ((uVar1 == 0x36) && (puVar1[2] == 0x34)) {
            s40c = puVar1 + 3;
            uVar4 = uVar4 | 0x8000;
            s418 = uVar4;
          }
          else if ((uVar1 == 0x33) && (puVar1[2] == 0x32)) {
            s40c = puVar1 + 3;
            uVar4 = uVar4 & 0xffff7fff;
            s418 = uVar4;
          }
          else if (((((uVar1 != 100) && (uVar1 != 0x69)) && (uVar1 != 0x6f)) &&
                   ((uVar1 != 0x75 && (uVar1 != 0x78)))) && (uVar1 != 0x58)) {
            s438 = 0;
            goto switchD_66212fd5_caseD_0;
          }
        }
        else if (s420 == (int *)0x68) {
          uVar4 = uVar4 | 0x20;
          s418 = uVar4;
        }
        else if (s420 == (int *)0x6c) {
          if (*s40c == 0x6c) {
            s40c = puVar1 + 2;
            uVar4 = uVar4 | 0x1000;
            s418 = uVar4;
          }
          else {
            uVar4 = uVar4 | 0x10;
            s418 = uVar4;
          }
        }
        else if (s420 == (int *)0x77) {
          uVar4 = uVar4 | 0x800;
          s418 = uVar4;
        }
        break;
      case 7:
        if (s420 < (int *)0x65) {
          if (s420 == (int *)0x64) {
LAB_662134fe:
            uVar4 = uVar4 | 0x40;
            s418 = uVar4;
LAB_66213507:
            s420 = (int *)0xa;
LAB_66213511:
            if (((uVar4 & 0x8000) == 0) && ((uVar4 & 0x1000) == 0)) {
              if ((uVar4 & 0x20) == 0) {
                if ((uVar4 & 0x40) == 0) {
                  piVar4 = *s414;
                  piVar2 = (int *)0x0;
                  s414 = s414 + 1;
                  goto LAB_662136f3;
                }
                piVar4 = *s414;
              }
              else if ((uVar4 & 0x40) == 0) {
                piVar4 = (int *)(uint)*(ushort *)s414;
              }
              else {
                piVar4 = (int *)(int)*(short *)s414;
              }
              piVar2 = (int *)((int)piVar4 >> 0x1f);
              s414 = s414 + 1;
            }
            else {
              piVar4 = *s414;
              piVar2 = s414[1];
              s414 = s414 + 2;
            }
LAB_662136f3:
            if ((((uVar4 & 0x40) != 0) && ((int)piVar2 < 1)) && ((int)piVar2 < 0)) {
              bVar1 = piVar4 != (int *)0x0;
              piVar4 = (int *)-(int)piVar4;
              piVar2 = (int *)-(int)((int)piVar2 + (uint)bVar1);
              uVar4 = uVar4 | 0x100;
              s418 = uVar4;
            }
            if ((uVar4 & 0x9000) == 0) {
              piVar2 = (int *)0x0;
            }
            lVar1 = ((longlong)(int)piVar2 << 0x20) + (int)piVar4;
            if ((int)s41c < 0) {
              s41c = (int *)0x1;
            }
            else {
              s418 = uVar4 & 0xfffffff7;
              if (0x200 < (int)s41c) {
                s41c = (int *)0x200;
              }
            }
            if (((uint)piVar4 | (uint)piVar2) == 0) {
              s428 = (uint)piVar4 | (uint)piVar2;
            }
            piVar4 = &s209;
            while( true ) {
              piVar5 = (int *)((int)s41c + -1);
              if (((int)s41c < 1) && (lVar1 == 0)) break;
              s41c = piVar5;
              lVar1 = __aulldvrm((uint)lVar1,(uint)((ulonglong)lVar1 >> 0x20),(uint)s420,
                                 (int)s420 >> 0x1f);
              s410 = (char *)lVar1;
              iVar1 = extraout_ECX + 0x30;
              if (0x39 < iVar1) {
                iVar1 = iVar1 + s460;
              }
              *(char *)piVar4 = (char)iVar1;
              piVar4 = (int *)((int)piVar4 + -1);
            }
            pcVar3 = (char *)((int)&s209 + -(int)piVar4);
            piVar2 = (int *)((int)piVar4 + 1);
            uVar4 = s418;
            s41c = piVar5;
            s410 = pcVar3;
            if (((s418 & 0x200) != 0) && ((pcVar3 == (char *)0x0 || (*(char *)piVar2 != '0')))) {
              pcVar3 = (char *)((int)&s209 + -(int)piVar4 + 1);
              *(undefined *)piVar4 = 0x30;
              piVar2 = piVar4;
              s410 = pcVar3;
            }
          }
          else if (s420 < (int *)0x54) {
            if (s420 == (int *)0x53) {
              if ((uVar4 & 0x830) == 0) {
                uVar4 = uVar4 | 0x20;
                s418 = uVar4;
              }
              goto LAB_662132e8;
            }
            if (s420 != (int *)0x41) {
              if (s420 == (int *)0x43) {
                if ((uVar4 & 0x830) == 0) {
                  uVar4 = uVar4 | 0x20;
                  s418 = uVar4;
                }
LAB_6621339d:
                uVar1 = *(ushort *)s414;
                s464 = (uint)uVar1;
                s414 = s414 + 1;
                s430 = 1;
                if ((uVar4 & 0x20) == 0) {
                  s408[0]._0_2_ = uVar1;
                }
                else {
                  s440 = (byte)uVar1;
                  s43f = 0;
                  iVar1 = FUN_662175d8((ushort *)s408,&s440,s454[0]->mb_cur_max,s454);
                  if (iVar1 < 0) {
                    s444 = 1;
                  }
                }
                pcVar3 = (char *)0x1;
                piVar2 = s408;
                s410 = pcVar3;
                goto LAB_66213807;
              }
              if ((s420 != (int *)0x45) && (s420 != (int *)0x47)) goto LAB_66213807;
            }
            s420 = s420 + 8;
            s45c = 1;
LAB_66213282:
            uVar2 = uVar4 | 0x40;
            s410 = (char *)0x200;
            piVar4 = s408;
            s418 = uVar2;
            pcVar3 = s410;
            if ((int)s41c < 0) {
              s41c = (int *)0x6;
            }
            else if (s41c == (int *)0x0) {
              if ((short)s420 == 0x67) {
                s41c = (int *)0x1;
              }
            }
            else {
              if (0x200 < (int)s41c) {
                s41c = (int *)0x200;
              }
              if (0xa3 < (int)s41c) {
                pcVar3 = (char *)((int)s41c + 0x15d);
                s458 = (int *)FUN_662102f2((size_t)pcVar3);
                piVar4 = s458;
                if (s458 == (int *)0x0) {
                  s41c = (int *)0xa3;
                  piVar4 = s408;
                  pcVar3 = s410;
                }
              }
            }
            s410 = pcVar3;
            in_stack_fffffb74 = *s414;
            s414 = s414 + 2;
            pptVar1 = s454;
            iVar1 = (int)(char)s420;
            puVar2 = &stack0xfffffb74;
            piVar2 = piVar4;
            pcVar3 = s410;
            piVar5 = s41c;
            uVar5 = s45c;
            pcVar1 = (code *)DecodePointer(Ptr_6624a140);
            (*pcVar1)(puVar2,piVar2,pcVar3,iVar1,piVar5,uVar5,pptVar1);
            if (((uVar4 & 0x80) != 0) && (s41c == (int *)0x0)) {
              pptVar1 = s454;
              piVar2 = piVar4;
              pcVar1 = (code *)DecodePointer(Ptr_6624a14c);
              (*pcVar1)(piVar2,pptVar1);
            }
            if (((short)s420 == 0x67) && ((uVar4 & 0x80) == 0)) {
              pptVar1 = s454;
              piVar2 = piVar4;
              pcVar1 = (code *)DecodePointer(Ptr_6624a148);
              (*pcVar1)(piVar2,pptVar1);
            }
            ppiVar1 = s414;
            if (*(char *)piVar4 == '-') {
              s418 = uVar4 | 0x140;
              piVar4 = (int *)((int)piVar4 + 1);
              uVar2 = s418;
            }
LAB_66213462:
            s414 = ppiVar1;
            pcVar3 = (char *)_strlen((char *)piVar4);
            uVar4 = uVar2;
            piVar2 = piVar4;
            s410 = pcVar3;
          }
          else {
            if (s420 == (int *)0x58) goto LAB_66213660;
            if (s420 == (int *)0x5a) {
              piVar5 = *s414;
              ppiVar1 = s414 + 1;
              uVar2 = uVar4;
              if ((piVar5 == (int *)0x0) || (piVar2 = (int *)piVar5[1], piVar2 == (int *)0x0))
              goto LAB_66213462;
              if ((uVar4 & 0x800) != 0) {
                iVar1 = (int)*(short *)piVar5 - ((int)*(short *)piVar5 >> 0x1f);
                goto LAB_662137ff;
              }
              s430 = 0;
              pcVar3 = (char *)(int)*(short *)piVar5;
              s414 = ppiVar1;
              s410 = pcVar3;
            }
            else {
              if (s420 == (int *)0x61) goto LAB_66213282;
              if (s420 == (int *)0x63) goto LAB_6621339d;
            }
          }
LAB_66213807:
          if (s444 == 0) {
            if ((uVar4 & 0x40) != 0) {
              if ((uVar4 & 0x100) == 0) {
                if ((uVar4 & 1) == 0) {
                  if ((uVar4 & 2) != 0) {
                    s43c = 0x20;
                    s428 = 1;
                  }
                  goto LAB_6621383c;
                }
                s43c = 0x2b;
              }
              else {
                s43c = 0x2d;
              }
              s428 = 1;
            }
LAB_6621383c:
            pcVar3 = (char *)((int)s434 + (-s428 - (int)pcVar3));
            if ((uVar4 & 0xc) == 0) {
              _write_multi_char(0x20,(int)pcVar3,s42c,&s424);
            }
            FUN_66213ad0(&s43c,s428,s42c,&s424,piVar1);
            if (((uVar4 & 8) != 0) && ((uVar4 & 4) == 0)) {
              _write_multi_char(0x30,(int)pcVar3,s42c,&s424);
            }
            if ((s430 == 0) && (pcVar2 = s410, piVar4 = piVar2, 0 < (int)s410)) {
              do {
                pcVar2 = pcVar2 + -1;
                s420 = piVar4;
                iVar1 = FUN_662175d8((ushort *)&s464,(byte *)piVar4,s454[0]->mb_cur_max,s454);
                if (iVar1 < 1) {
                  s424 = -1;
                  break;
                }
                _write_char(s464,s42c,&s424);
                s420 = (int *)((int)s420 + iVar1);
                piVar4 = s420;
              } while (0 < (int)pcVar2);
            }
            else {
              FUN_66213ad0((ushort *)piVar2,(int)s410,s42c,&s424,piVar1);
            }
            if ((-1 < s424) && ((uVar4 & 4) != 0)) {
              _write_multi_char(0x20,(int)pcVar3,s42c,&s424);
            }
          }
        }
        else {
          if ((int *)0x70 < s420) {
            if (s420 == (int *)0x73) {
LAB_662132e8:
              piVar5 = (int *)0x7fffffff;
              if (s41c != (int *)0xffffffff) {
                piVar5 = s41c;
              }
              ppiVar1 = s414 + 1;
              piVar3 = *s414;
              if ((uVar4 & 0x20) == 0) {
                piVar2 = piVar3;
                if (piVar3 == (int *)0x0) {
                  piVar3 = (int *)PTR_DAT_6624adf4;
                  piVar2 = (int *)PTR_DAT_6624adf4;
                }
                for (; (piVar5 != (int *)0x0 &&
                       (piVar5 = (int *)((int)piVar5 + -1), *(short *)piVar3 != 0));
                    piVar3 = (int *)((int)piVar3 + 2)) {
                }
                iVar1 = (int)piVar3 - (int)piVar2;
LAB_662137ff:
                s414 = s414 + 1;
                s430 = 1;
                pcVar3 = (char *)(iVar1 >> 1);
                s410 = pcVar3;
              }
              else {
                if (piVar3 == (int *)0x0) {
                  piVar3 = piVar4;
                }
                s410 = (char *)0x0;
                s420 = piVar3;
                pcVar3 = (char *)0x0;
                piVar2 = piVar3;
                s414 = ppiVar1;
                if (0 < (int)piVar5) {
                  do {
                    pcVar3 = s410;
                    if (*(char *)s420 == '\0') break;
                    iVar1 = FUN_6620e813(*(char *)s420,s454);
                    if (iVar1 != 0) {
                      s420 = (int *)((int)s420 + 1);
                    }
                    s420 = (int *)((int)s420 + 1);
                    pcVar3 = s410 + 1;
                    s410 = pcVar3;
                  } while ((int)pcVar3 < (int)piVar5);
                }
              }
              goto LAB_66213807;
            }
            if (s420 == (int *)0x75) goto LAB_66213507;
            if (s420 != (int *)0x78) goto LAB_66213807;
            s460 = 0x27;
LAB_66213680:
            s420 = (int *)&DAT_10;
            if ((char)uVar4 < '\0') {
              s43a = (short)s460 + 0x51;
              s43c = 0x30;
              s428 = 2;
            }
            goto LAB_66213511;
          }
          if (s420 == (int *)0x70) {
            s41c = (int *)&DAT_8;
LAB_66213660:
            s460 = 7;
            goto LAB_66213680;
          }
          if (s420 < (int *)0x65) goto LAB_66213807;
          if (s420 < (int *)0x68) goto LAB_66213282;
          if (s420 == (int *)0x69) goto LAB_662134fe;
          if (s420 != (int *)0x6e) {
            if (s420 != (int *)0x6f) goto LAB_66213807;
            s420 = (int *)&DAT_8;
            if ((char)uVar4 < '\0') {
              uVar4 = uVar4 | 0x200;
              s418 = uVar4;
            }
            goto LAB_66213511;
          }
          piVar4 = *s414;
          s414 = s414 + 1;
          bVar1 = FUN_6621743d();
          uVar6 = SUB41(in_stack_fffffb74,0);
          if (((int)(int3)extraout_var << 8) + bVar1 == 0) {
            piVar2 = __errno();
            *piVar2 = 0x16;
            report_invalid_parameter();
            uVar3 = extraout_DL_00;
            if (s448 != '\0') {
              *(uint *)(s44c + 0x70) = *(uint *)(s44c + 0x70) & 0xfffffffd;
            }
            goto LAB_66213a11;
          }
          if ((uVar4 & 0x20) == 0) {
            *piVar4 = s424;
          }
          else {
            *(short *)piVar4 = (short)s424;
          }
          s444 = 1;
        }
        pcVar3 = s410;
        if (s458 != (int *)0x0) {
          FID_conflict__free(s458);
          s458 = (int *)0x0;
          pcVar3 = s410;
        }
      }
      uVar6 = SUB41(in_stack_fffffb74,0);
      piVar4 = (int *)PTR_DAT_6624adf0;
      puVar1 = s40c;
      uVar1 = *s40c;
    }
    uVar3 = (undefined)uVar1;
    if (s448 != '\0') {
      *(uint *)(s44c + 0x70) = *(uint *)(s44c + 0x70) & 0xfffffffd;
    }
  }
LAB_66213a11:
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,uVar3,uVar6);
  return;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_char(undefined4 param_1,int param_2,int *param_3)

{
  short sVar1;
  
  if (((*(byte *)(param_2 + 0xc) & 0x40) == 0) || (*(int *)(param_2 + 8) != 0)) {
    sVar1 = FUN_66217452(param_1,param_2);
    if (sVar1 == -1) {
      *param_3 = -1;
      return;
    }
  }
  *param_3 = *param_3 + 1;
  return;
}



// Library Function - Single Match
//  _write_multi_char
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_multi_char(undefined4 param_1,int param_2,int param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      _write_char(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



void __cdecl FUN_66213ad0(ushort *param_1,int param_2,int param_3,int *param_4,int *param_5)

{
  int iVar1;
  
  iVar1 = *param_5;
  if (((*(byte *)(param_3 + 0xc) & 0x40) == 0) || (*(int *)(param_3 + 8) != 0)) {
    *param_5 = 0;
    if (0 < param_2) {
      do {
        param_2 = param_2 + -1;
        _write_char((uint)*param_1,param_3,param_4);
        param_1 = param_1 + 1;
        if (*param_4 == -1) {
          if (*param_5 != 0x2a) break;
          _write_char(0x3f,param_3,param_4);
        }
      } while (0 < param_2);
      if (*param_5 != 0) {
        return;
      }
    }
    *param_5 = iVar1;
  }
  else {
    *param_4 = *param_4 + param_2;
  }
  return;
}



// Library Function - Single Match
//  ___doserrno
// 
// Library: Visual Studio 2012 Release

ulong * __cdecl ___doserrno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (ulong *)&DAT_6624a2c4;
  }
  return &p_Var1->_tdoserrno;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_errno_map_os_error
//  __dosmaperr
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

void __cdecl FID_conflict___dosmaperr(ulong param_1)

{
  ulong *puVar1;
  int iVar1;
  int *piVar1;
  
  puVar1 = ___doserrno();
  *puVar1 = param_1;
  iVar1 = __get_errno_from_oserr(param_1);
  piVar1 = __errno();
  *piVar1 = iVar1;
  return;
}



// Library Function - Single Match
//  __errno
// 
// Library: Visual Studio 2012 Release

int * __cdecl __errno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (int *)&DAT_6624a2c0;
  }
  return &p_Var1->_terrno;
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Library: Visual Studio 2012 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_6624a158)[uVar1 * 2]) {
      return (&DAT_6624a15c)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if ((param_1 - 0x13) < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < (param_1 - 0xbc)) & 0xe) + 8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2012 Release

void * __cdecl _malloc(size_t _Size)

{
  void *pvVar1;
  int iVar1;
  int *piVar1;
  SIZE_T dwBytes;
  
  if (_Size < 0xffffffe1) {
    do {
      if (hHeap_6624b5e8 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        HandleRuntimeErrorWithLogging(0x1e);
        FUN_6620f746(0xff);
      }
      dwBytes = _Size;
      if (_Size == 0) {
        dwBytes = 1;
      }
      pvVar1 = HeapAlloc(hHeap_6624b5e8,0,dwBytes);
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (_DAT_6624c294 == 0) {
        piVar1 = __errno();
        *piVar1 = 0xc;
        break;
      }
      iVar1 = __callnewh(_Size);
    } while (iVar1 != 0);
    piVar1 = __errno();
    *piVar1 = 0xc;
  }
  else {
    __callnewh(_Size);
    piVar1 = __errno();
    *piVar1 = 0xc;
    pvVar1 = (void *)0x0;
  }
  return pvVar1;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2012 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar1;
  
  pcVar1 = (code *)DecodePointer(Ptr_6624b708);
  if (pcVar1 != (code *)0x0) {
    iVar1 = (*pcVar1)(_Size);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



void __cdecl FUN_66213c89(PVOID param_1)

{
  Ptr_6624b708 = param_1;
  return;
}



void __cdecl FUN_66213c96(int *param_1)

{
  int *piVar1;
  int iVar1;
  int **ppiVar1;
  
  LOCK();
  *param_1 = *param_1 + 1;
  piVar1 = (int *)param_1[0x1e];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  piVar1 = (int *)param_1[0x20];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  piVar1 = (int *)param_1[0x1f];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  piVar1 = (int *)param_1[0x22];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  ppiVar1 = (int **)(param_1 + 7);
  iVar1 = 6;
  do {
    if ((ppiVar1[-2] != (int *)&DAT_6624a7ec) && (piVar1 = *ppiVar1, piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
    }
    if ((ppiVar1[-3] != (int *)0x0) && (piVar1 = ppiVar1[-1], piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
    }
    ppiVar1 = ppiVar1 + 4;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  LOCK();
  *(int *)(param_1[0x27] + 0xb0) = *(int *)(param_1[0x27] + 0xb0) + 1;
  return;
}



void __cdecl FUN_66213d2b(void *param_1)

{
  int *piVar1;
  undefined **ppuVar1;
  void *_Memory;
  void **ppvVar1;
  int **ppiVar1;
  
  _Memory = param_1;
  if ((((*(undefined ***)((int)param_1 + 0x84) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0x84) != &PTR_DAT_6624ae00)) &&
      (*(int **)((int)param_1 + 0x78) != (int *)0x0)) && (**(int **)((int)param_1 + 0x78) == 0)) {
    piVar1 = *(int **)((int)param_1 + 0x80);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      FID_conflict____acrt_locale_free_monetary(*(int *)((int)param_1 + 0x84));
    }
    piVar1 = *(int **)((int)param_1 + 0x7c);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      FID_conflict____free_lconv_num(*(void ***)((int)param_1 + 0x84));
    }
    FID_conflict__free(*(void **)((int)param_1 + 0x78));
    FID_conflict__free(*(void **)((int)param_1 + 0x84));
  }
  if ((*(int **)((int)param_1 + 0x88) != (int *)0x0) && (**(int **)((int)param_1 + 0x88) == 0)) {
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x8c) + -0xfe));
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x94) + -0x80));
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x98) + -0x80));
    FID_conflict__free(*(void **)((int)param_1 + 0x88));
  }
  ppuVar1 = *(undefined ***)((int)param_1 + 0x9c);
  if ((ppuVar1 != &PTR_DAT_6624a7f0) && (ppuVar1[0x2c] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar1);
    FID_conflict__free(*(void **)((int)param_1 + 0x9c));
  }
  ppvVar1 = (void **)((int)param_1 + 0xa0);
  param_1 = (void *)0x6;
  ppiVar1 = (int **)((int)_Memory + 0x1c);
  do {
    if (((ppiVar1[-2] != (int *)&DAT_6624a7ec) && (piVar1 = *ppiVar1, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      FID_conflict__free(*ppvVar1);
    }
    if (((ppiVar1[-3] != (int *)0x0) && (piVar1 = ppiVar1[-1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
    }
    ppvVar1 = ppvVar1 + 1;
    ppiVar1 = ppiVar1 + 4;
    param_1 = (void *)((int)param_1 + -1);
  } while (param_1 != (void *)0x0);
  FID_conflict__free(_Memory);
  return;
}



int * __cdecl FUN_66213e85(int *param_1)

{
  int *piVar1;
  int **ppiVar1;
  int iVar1;
  
  if (param_1 != (int *)0x0) {
    LOCK();
    *param_1 = *param_1 + -1;
    piVar1 = (int *)param_1[0x1e];
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = (int *)param_1[0x20];
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = (int *)param_1[0x1f];
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = (int *)param_1[0x22];
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    ppiVar1 = (int **)(param_1 + 7);
    iVar1 = 6;
    do {
      if ((ppiVar1[-2] != (int *)&DAT_6624a7ec) && (piVar1 = *ppiVar1, piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
      }
      if ((ppiVar1[-3] != (int *)0x0) && (piVar1 = ppiVar1[-1], piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
      }
      ppiVar1 = ppiVar1 + 4;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    LOCK();
    *(int *)(param_1[0x27] + 0xb0) = *(int *)(param_1[0x27] + 0xb0) + -1;
  }
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

pthreadlocinfo FUN_66213f25(void)

{
  _ptiddata p_Var1;
  pthreadlocinfo ptVar1;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_6624aa18) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    ptVar1 = (pthreadlocinfo)
             __updatetlocinfoEx_nolock((int **)&p_Var1->ptlocinfo,(int *)PTR_DAT_6624a954);
    FUN_66213f9c();
  }
  else {
    p_Var1 = __getptd();
    ptVar1 = p_Var1->ptlocinfo;
  }
  if (ptVar1 == (pthreadlocinfo)0x0) {
    __amsg_exit(0x20);
  }
  return ptVar1;
}



void FUN_66213f9c(void)

{
  leavecritical(0xc);
  return;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2019 Release

int * __cdecl __updatetlocinfoEx_nolock(int **param_1,int *param_2)

{
  int *piVar1;
  
  if ((param_2 == (int *)0x0) || (param_1 == (int **)0x0)) {
    param_2 = (int *)0x0;
  }
  else {
    piVar1 = *param_1;
    if (piVar1 != param_2) {
      *param_1 = param_2;
      FUN_66213c96(param_2);
      if (((piVar1 != (int *)0x0) && (FUN_66213e85(piVar1), *piVar1 == 0)) &&
         (piVar1 != (int *)&DAT_6624a958)) {
        FUN_66213d2b(piVar1);
      }
    }
  }
  return param_2;
}



// Library Function - Single Match
//  wchar_t const * __cdecl CPtoLocaleName(int)
// 
// Library: Visual Studio 2012 Release

wchar_t * __cdecl CPtoLocaleName(int param_1)

{
  if (param_1 == 0x3a4) {
    return (wchar_t *)PTR_u_ja_JP_6621e7cc;
  }
  if (param_1 == 0x3a8) {
    return (wchar_t *)PTR_u_zh_CN_6621e7d0;
  }
  if (param_1 == 0x3b5) {
    return (wchar_t *)PTR_u_ko_KR_6621e7d4;
  }
  if (param_1 != 0x3b6) {
    return (wchar_t *)0x0;
  }
  return (wchar_t *)PTR_u_zh_TW_6621e7d8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

UINT __cdecl FUN_66214048(UINT param_1)

{
  int s14 [2];
  int sc;
  char s8;
  
  FUN_6620e53b(s14,(pthreadlocinfo *)0x0);
  _DAT_6624b724 = 0;
  if (param_1 == 0xfffffffe) {
    _DAT_6624b724 = 1;
    param_1 = GetOEMCP();
  }
  else if (param_1 == 0xfffffffd) {
    _DAT_6624b724 = 1;
    param_1 = GetACP();
  }
  else if (param_1 == 0xfffffffc) {
    _DAT_6624b724 = 1;
    param_1 = *(UINT *)(s14[0] + 4);
  }
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return param_1;
}



void __cdecl FUN_662140b6(int param_1)

{
  int iVar1;
  undefined *puVar1;
  
  puVar1 = (undefined *)(param_1 + 0x18);
  FUN_6620d410(puVar1,0,0x101);
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x21c) = 0;
  iVar1 = 0x101;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  do {
    *puVar1 = puVar1[(int)&DAT_6624a4d0 - param_1];
    puVar1 = puVar1 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  puVar1 = (undefined *)(param_1 + 0x119);
  iVar1 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_6624a4d0 - param_1];
    puVar1 = puVar1 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct __crt_multibyte_data *)
// 
// Library: Visual Studio 2015 Release

void __cdecl setSBUpLow(__crt_multibyte_data *param_1)

{
  byte bVar1;
  __crt_multibyte_data _Var1;
  BOOL BVar1;
  uint uVar1;
  byte *pbVar1;
  char extraout_DL;
  char cVar1;
  __crt_multibyte_data *p_Var1;
  int in_stack_fffffadc;
  _cpinfo s51c;
  WORD s508 [256];
  __crt_multibyte_data s308 [256];
  __crt_multibyte_data s208 [256];
  CHAR s108 [256];
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  BVar1 = GetCPInfo(*(UINT *)(param_1 + 4),&s51c);
  if (BVar1 == 0) {
    uVar1 = 0;
    in_stack_fffffadc = -0x61 - (int)(param_1 + 0x119);
    do {
      p_Var1 = param_1 + uVar1 + 0x119;
      if ((p_Var1 + in_stack_fffffadc + 0x20) < (__crt_multibyte_data *)0x1a) {
        param_1[uVar1 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar1 + 0x19] | 0x10);
        _Var1 = (__crt_multibyte_data)((char)uVar1 + ' ');
LAB_6621427f:
        *p_Var1 = _Var1;
      }
      else {
        if ((p_Var1 + in_stack_fffffadc) < (__crt_multibyte_data *)0x1a) {
          param_1[uVar1 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar1 + 0x19] | 0x20);
          _Var1 = (__crt_multibyte_data)((char)uVar1 + -0x20);
          goto LAB_6621427f;
        }
        *p_Var1 = (__crt_multibyte_data)0x0;
      }
      cVar1 = (char)param_1 + '\x19';
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x100);
  }
  else {
    uVar1 = 0;
    do {
      s108[uVar1] = (CHAR)uVar1;
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x100);
    pbVar1 = s51c.LeadByte;
    s108[0] = ' ';
    while (s51c.LeadByte[0] != 0) {
      bVar1 = pbVar1[1];
      for (uVar1 = (uint)s51c.LeadByte[0]; (uVar1 <= (bVar1) && (uVar1 < 0x100)); uVar1 = uVar1 + 1)
      {
        s108[uVar1] = ' ';
      }
      pbVar1 = pbVar1 + 2;
      s51c.LeadByte[0] = *pbVar1;
    }
    FUN_66217f28((pthreadlocinfo *)0x0,1,s108,0x100,s508,*(UINT *)(param_1 + 4),0);
    FUN_66217dcc((pthreadlocinfo *)0x0,*(undefined4 *)(param_1 + 0x21c),0x100,s108,0x100,s208,0x100,
                 *(undefined4 *)(param_1 + 4),0);
    FUN_66217dcc((pthreadlocinfo *)0x0,*(undefined4 *)(param_1 + 0x21c),0x200,s108,0x100,s308,0x100,
                 *(undefined4 *)(param_1 + 4),0);
    uVar1 = 0;
    do {
      if ((s508[uVar1] & 1) == 0) {
        if ((s508[uVar1] & 2) != 0) {
          param_1[uVar1 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar1 + 0x19] | 0x20);
          _Var1 = s308[uVar1];
          goto LAB_66214226;
        }
        param_1[uVar1 + 0x119] = (__crt_multibyte_data)0x0;
      }
      else {
        param_1[uVar1 + 0x19] = (__crt_multibyte_data)((byte)param_1[uVar1 + 0x19] | 0x10);
        _Var1 = s208[uVar1];
LAB_66214226:
        param_1[uVar1 + 0x119] = _Var1;
      }
      uVar1 = uVar1 + 1;
      cVar1 = extraout_DL;
    } while (uVar1 < 0x100);
  }
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,cVar1,(char)in_stack_fffffadc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

pthreadmbcinfo FUN_662142a7(void)

{
  int iVar1;
  _ptiddata p_Var1;
  pthreadmbcinfo _Memory;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_6624aa18) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    _Memory = p_Var1->ptmbcinfo;
    if (_Memory != DAT_6624a6f4) {
      if (_Memory != (pthreadmbcinfo)0x0) {
        LOCK();
        iVar1 = _Memory->refcount + -1;
        _Memory->refcount = iVar1;
        if ((iVar1 == 0) && (_Memory != (pthreadmbcinfo)&DAT_6624a4d0)) {
          FID_conflict__free(_Memory);
        }
      }
      p_Var1->ptmbcinfo = DAT_6624a6f4;
      _Memory = DAT_6624a6f4;
      LOCK();
      DAT_6624a6f4->refcount = DAT_6624a6f4->refcount + 1;
    }
    FUN_66214344();
  }
  else {
    _Memory = p_Var1->ptmbcinfo;
  }
  if (_Memory == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return _Memory;
}



void FUN_66214344(void)

{
  leavecritical(0xd);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_6621434d(UINT param_1)

{
  _ptiddata p_Var1;
  UINT UVar1;
  pthreadmbcinfo ptVar1;
  int *piVar1;
  int iVar1;
  pthreadmbcinfo ptVar2;
  int iVar2;
  int iVar3;
  pthreadmbcinfo ptVar3;
  
  iVar3 = -1;
  p_Var1 = __getptd();
  FUN_662142a7();
  ptVar1 = p_Var1->ptmbcinfo;
  UVar1 = FUN_66214048(param_1);
  if (UVar1 == ptVar1->mbcodepage) {
    iVar3 = 0;
  }
  else {
    ptVar1 = (pthreadmbcinfo)FUN_662102f2(0x220);
    if (ptVar1 != (pthreadmbcinfo)0x0) {
      ptVar2 = p_Var1->ptmbcinfo;
      ptVar3 = ptVar1;
      for (iVar3 = 0x88; iVar3 != 0; iVar3 = iVar3 + -1) {
        ptVar3->refcount = ptVar2->refcount;
        ptVar2 = (pthreadmbcinfo)&ptVar2->mbcodepage;
        ptVar3 = (pthreadmbcinfo)&ptVar3->mbcodepage;
      }
      iVar2 = 0;
      ptVar1->refcount = 0;
      iVar3 = FUN_662144f5(UVar1,(__crt_multibyte_data *)ptVar1);
      if (iVar3 == 0) {
        LOCK();
        iVar1 = p_Var1->ptmbcinfo->refcount + -1;
        p_Var1->ptmbcinfo->refcount = iVar1;
        if ((iVar1 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_6624a4d0)) {
          FID_conflict__free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar1;
        LOCK();
        ptVar1->refcount = ptVar1->refcount + 1;
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_6624aa18 & 1) == 0)) {
          __lock(0xd);
          _DAT_6624b70c = ptVar1->mbcodepage;
          _DAT_6624b710 = ptVar1->ismbcodepage;
          _DAT_6624b720 = ptVar1->mblocalename;
          for (iVar1 = 0; iVar1 < 5; iVar1 = iVar1 + 1) {
            (&DAT_6624b714)[iVar1] = ptVar1->mbulinfo[iVar1];
          }
          for (iVar1 = 0; iVar1 < 0x101; iVar1 = iVar1 + 1) {
            (&DAT_6624a2c8)[iVar1] = ptVar1->mbctype[iVar1];
          }
          for (; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_6624a3d0)[iVar2] = ptVar1->mbcasemap[iVar2];
          }
          LOCK();
          iVar2 = DAT_6624a6f4->refcount + -1;
          DAT_6624a6f4->refcount = iVar2;
          if ((iVar2 == 0) && (DAT_6624a6f4 != (pthreadmbcinfo)&DAT_6624a4d0)) {
            FID_conflict__free(DAT_6624a6f4);
          }
          LOCK();
          DAT_6624a6f4 = ptVar1;
          ptVar1->refcount = ptVar1->refcount + 1;
          FUN_662144bf();
        }
      }
      else if (iVar3 == -1) {
        if (ptVar1 != (pthreadmbcinfo)&DAT_6624a4d0) {
          FID_conflict__free(ptVar1);
        }
        piVar1 = __errno();
        *piVar1 = 0x16;
      }
    }
  }
  return iVar3;
}



void FUN_662144bf(void)

{
  leavecritical(0xd);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_662144f5(UINT param_1,__crt_multibyte_data *param_2)

{
  byte bVar1;
  undefined2 uVar1;
  UINT CodePage;
  uint uVar2;
  BOOL BVar1;
  byte *pbVar1;
  __crt_multibyte_data *p_Var1;
  wchar_t *pwVar1;
  int iVar1;
  byte *pbVar2;
  undefined2 *puVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined uVar3;
  undefined2 *puVar2;
  uint uVar4;
  undefined uVar5;
  int in_stack_ffffffdc;
  int s20;
  _cpinfo s1c;
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  CodePage = FUN_66214048(param_1);
  uVar5 = (undefined)in_stack_ffffffdc;
  if (CodePage != 0) {
    uVar4 = 0;
    uVar2 = 0;
    s20 = 0;
LAB_66214531:
    if (*(UINT *)((int)&DAT_6624a6f8 + uVar2) != CodePage) goto code_r0x6621453d;
    FUN_6620d410(param_2 + 0x18,0,0x101);
    in_stack_ffffffdc = s20 * 0x30;
    pbVar1 = &DAT_6624a708 + in_stack_ffffffdc;
    do {
      bVar1 = *pbVar1;
      pbVar2 = pbVar1;
      while ((bVar1 != 0 && (bVar1 = pbVar2[1], bVar1 != 0))) {
        for (uVar2 = (uint)*pbVar2; (uVar2 <= (bVar1) && (uVar2 < 0x100)); uVar2 = uVar2 + 1) {
          param_2[uVar2 + 0x19] =
               (__crt_multibyte_data)((byte)param_2[uVar2 + 0x19] | (&DAT_6624a6f0)[uVar4]);
          bVar1 = pbVar2[1];
        }
        pbVar2 = pbVar2 + 2;
        bVar1 = *pbVar2;
      }
      uVar4 = uVar4 + 1;
      pbVar1 = pbVar1 + 8;
    } while (uVar4 < 4);
    *(UINT *)(param_2 + 4) = CodePage;
    *(undefined4 *)(param_2 + 8) = 1;
    pwVar1 = CPtoLocaleName(CodePage);
    *(wchar_t **)(param_2 + 0x21c) = pwVar1;
    puVar1 = (undefined2 *)(param_2 + 0xc);
    puVar2 = (undefined2 *)(&DAT_6624a6fc + in_stack_ffffffdc);
    iVar1 = 6;
    do {
      uVar1 = *puVar2;
      puVar2 = puVar2 + 1;
      *puVar1 = uVar1;
      puVar1 = puVar1 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    goto LAB_662146c6;
  }
  FUN_662140b6((int)param_2);
  uVar3 = extraout_DL_00;
LAB_662146d0:
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,uVar3,uVar5);
  return;
code_r0x6621453d:
  s20 = s20 + 1;
  uVar2 = uVar2 + 0x30;
  if (0xef < uVar2) goto code_r0x6621454b;
  goto LAB_66214531;
code_r0x6621454b:
  uVar3 = extraout_DL;
  if ((CodePage != 65000) && (CodePage != 0xfde9)) {
    BVar1 = IsValidCodePage(CodePage & 0xffff);
    uVar5 = (undefined)in_stack_ffffffdc;
    uVar3 = extraout_DL_01;
    if (BVar1 != 0) {
      BVar1 = GetCPInfo(CodePage,&s1c);
      uVar5 = (undefined)in_stack_ffffffdc;
      if (BVar1 == 0) {
        uVar3 = extraout_DL_02;
        if (_DAT_6624b724 != 0) {
          FUN_662140b6((int)param_2);
          uVar3 = extraout_DL_03;
        }
      }
      else {
        FUN_6620d410(param_2 + 0x18,0,0x101);
        *(UINT *)(param_2 + 4) = CodePage;
        *(undefined4 *)(param_2 + 0x21c) = 0;
        if (s1c.MaxCharSize < 2) {
          *(undefined4 *)(param_2 + 8) = 0;
        }
        else {
          pbVar1 = s1c.LeadByte;
          while ((s1c.LeadByte[0] != 0 && (bVar1 = pbVar1[1], bVar1 != 0))) {
            for (uVar2 = (uint)*pbVar1; uVar2 <= (bVar1); uVar2 = uVar2 + 1) {
              param_2[uVar2 + 0x19] = (__crt_multibyte_data)((byte)param_2[uVar2 + 0x19] | 4);
            }
            pbVar1 = pbVar1 + 2;
            s1c.LeadByte[0] = *pbVar1;
          }
          p_Var1 = param_2 + 0x1a;
          iVar1 = 0xfe;
          do {
            *p_Var1 = (__crt_multibyte_data)((byte)*p_Var1 | 8);
            p_Var1 = p_Var1 + 1;
            iVar1 = iVar1 + -1;
          } while (iVar1 != 0);
          pwVar1 = CPtoLocaleName(*(int *)(param_2 + 4));
          *(wchar_t **)(param_2 + 0x21c) = pwVar1;
          *(undefined4 *)(param_2 + 8) = 1;
        }
        *(undefined4 *)(param_2 + 0xc) = 0;
        *(undefined4 *)(param_2 + 0x10) = 0;
        *(undefined4 *)(param_2 + 0x14) = 0;
LAB_662146c6:
        uVar5 = (undefined)in_stack_ffffffdc;
        setSBUpLow(param_2);
        uVar3 = extraout_DL_04;
      }
    }
  }
  goto LAB_662146d0;
}



ushort __cdecl FUN_662146e0(int param_1,ushort param_2,pthreadlocinfo *param_3)

{
  int iVar1;
  pthreadlocinfo s1c [2];
  int s14;
  char s10;
  CHAR sc;
  CHAR sb;
  undefined sa;
  ushort s8 [2];
  
  FUN_6620e53b(s1c,param_3);
  if ((param_1 + 1U) < 0x101) {
    s8[0] = s1c[0]->pctype[param_1];
  }
  else {
    iVar1 = FUN_6620e813((param_1 >> 8) & 0xff,s1c);
    if (iVar1 == 0) {
      sb = '\0';
      iVar1 = 1;
      sc = (CHAR)param_1;
    }
    else {
      sa = 0;
      iVar1 = 2;
      sc = (CHAR)((uint)param_1 >> 8);
      sb = (CHAR)param_1;
    }
    iVar1 = FUN_66217f28(s1c,1,&sc,iVar1,s8,s1c[0]->lc_codepage,1);
    if (iVar1 == 0) {
      if (s10 != '\0') {
        *(uint *)(s14 + 0x70) = *(uint *)(s14 + 0x70) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (s10 != '\0') {
    *(uint *)(s14 + 0x70) = *(uint *)(s14 + 0x70) & 0xfffffffd;
  }
  return s8[0] & param_2;
}



void FUN_662147da(void)

{
  leavecritical(0xc);
  return;
}



uint __cdecl get_char_types(ushort string_ptr,uint allowed_flags)

{
  uint result_flags;
  BOOL character_types;
  uint chartype;
  
  if (string_ptr == 0xffff) {
    result_flags = 0;
  }
  else {
                    // ASCII characters are < 256
    if (string_ptr < 256) {
      result_flags = (uint)*(ushort *)(chartype_lookup + ((uint)string_ptr * 2));
    }
    else {
      character_types = GetStringTypeW(1,(LPCWSTR)&string_ptr,1,(LPWORD)&chartype);
      result_flags = -(uint)(character_types != 0) & chartype & 0xffff;
    }
    result_flags = result_flags & allowed_flags & 0xffff;
  }
  return result_flags;
}


/*
Unable to decompile '_strcmp'
Cause: Exception while decompiling 66214840: Decompiler process died

*/


// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  private: static void __cdecl type_info::_Type_info_dtor(class type_info *)
// 
// Library: Visual Studio 2012 Release

void __cdecl type_info::_Type_info_dtor(type_info *param_1)

{
  int *_Memory;
  int *piVar1;
  int *piVar2;
  
  __lock(0xe);
  _Memory = DAT_6624b730;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_6624b72c;
    do {
      piVar2 = piVar1;
      if (DAT_6624b730 == (int *)0x0) goto LAB_66214911;
      piVar1 = DAT_6624b730;
    } while (*DAT_6624b730 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_6624b730[1];
    FID_conflict__free(_Memory);
LAB_66214911:
    FID_conflict__free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_66214934();
  return;
}



void FUN_66214934(void)

{
  leavecritical(0xe);
  return;
}



uint __cdecl FUN_6621493d(uint param_1,pthreadlocinfo *param_2)

{
  int iVar1;
  uint uVar1;
  int s18 [2];
  int s10;
  char sc;
  ushort s8 [2];
  
  if ((ushort)param_1 == -1) {
    return 0xffff;
  }
  FUN_6620e53b(s18,param_2);
  if (*(LPCWSTR *)(s18[0] + 0xa8) == (LPCWSTR)0x0) {
    if ((ushort)((ushort)param_1 - 0x41) < 0x1a) {
      param_1 = (uint)(ushort)((ushort)param_1 + 0x20);
    }
    param_1 = param_1 & 0xffff;
LAB_6621499e:
    param_1 = param_1 & 0xffff;
  }
  else if ((ushort)param_1 < 0x100) {
    uVar1 = get_char_types((ushort)param_1,1);
    if (uVar1 == 0) goto LAB_6621499e;
    param_1 = (uint)*(byte *)(*(int *)(s18[0] + 0x94) + (param_1 & 0xffff));
  }
  else {
    iVar1 = ___crtLCMapStringW(*(LPCWSTR *)(s18[0] + 0xa8),0x100,(LPCWSTR)&param_1,1,(LPWSTR)s8,1);
    if (iVar1 != 0) {
      uVar1 = (uint)s8[0];
      goto LAB_662149dc;
    }
  }
  uVar1 = param_1 & 0xffff;
LAB_662149dc:
  if (sc != '\0') {
    *(uint *)(s10 + 0x70) = *(uint *)(s10 + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _CallDestructExceptionObject
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl _CallDestructExceptionObject(int *param_1,undefined4 param_2)

{
  BOOL BVar1;
  
  if ((*param_1 == -0x1f928c9d) && (PTR____DestructExceptionObject_6621e7a4 != (undefined *)0x0)) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_6621e7a4);
    if (BVar1 != 0) {
      (*(code *)PTR____DestructExceptionObject_6621e7a4)(param_1,param_2);
    }
  }
  return;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x66214a48,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind2(int param_1,uint param_2)

{
  uint uVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 s20;
  undefined *puStack28;
  undefined4 s18;
  int iStack20;
  
  iStack20 = param_1;
  puStack28 = &LAB_66214a50;
  s20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    s18 = *(undefined4 *)(*(int *)(param_1 + 8) + (uVar1 * 0xc));
    *(undefined4 *)(param_1 + 0xc) = s18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + (uVar1 * 0xc)) == 0) {
      __NLG_Notify(0x101);
      FUN_66214b64();
    }
  }
  *in_FS_OFFSET = s20;
  return;
}



// Library Function - Single Match
//  __NLG_Notify1
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

undefined4 __fastcall __NLG_Notify1(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_6624aa24 = in_EAX;
  DAT_6624aa28 = param_1;
  DAT_6624aa2c = unaff_EBP;
  return in_EAX;
}



// Library Function - Single Match
//  __NLG_Notify
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __NLG_Notify(ulong param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_6624aa24 = in_EAX;
  DAT_6624aa28 = param_1;
  DAT_6624aa2c = unaff_EBP;
  return;
}



void FUN_66214b64(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// Library Function - Single Match
//  _ValidateScopeTableHandlers
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl _ValidateScopeTableHandlers(PBYTE param_1,int param_2,int param_3)

{
  int *piVar1;
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var1;
  uint uVar1;
  uint uVar2;
  
  p_Var1 = (PIMAGE_SECTION_HEADER)0x0;
  uVar1 = 0xffffffff;
  if (param_3 != -1) {
    do {
      piVar1 = (int *)(param_2 + (param_3 * 0xc));
      uVar2 = (*(int *)(param_2 + 8 + (param_3 * 0xc)) - (int)param_1) & 0xfffff000;
      if (((uVar2 != uVar1) &&
          ((((uVar1 = uVar2, p_Var1 == (PIMAGE_SECTION_HEADER)0x0 ||
             (uVar2 < p_Var1->VirtualAddress)) || ((p_Var1->Misc + p_Var1->VirtualAddress) <= uVar2)
            ) && ((p_Var1 = __FindPESection(param_1,uVar2), p_Var1 == (PIMAGE_SECTION_HEADER)0x0 ||
                  ((p_Var1->Characteristics & 0x20000000) == 0)))))) ||
         (((iVar1 = piVar1[1], iVar1 != 0 &&
           ((uVar2 = (iVar1 - (int)param_1) & 0xfffff000, uVar2 != uVar1 &&
            ((uVar1 = uVar2, uVar2 < p_Var1->VirtualAddress ||
             ((p_Var1->Misc + p_Var1->VirtualAddress) <= uVar2)))))) &&
          ((p_Var1 = __FindPESection(param_1,uVar2), p_Var1 == (PIMAGE_SECTION_HEADER)0x0 ||
           ((p_Var1->Characteristics & 0x20000000) == 0)))))) {
        return 0;
      }
      param_3 = *piVar1;
    } while (param_3 != -1);
  }
  return 1;
}



// Library Function - Single Match
//  __ValidateEH3RN
// 
// Library: Visual Studio 2012 Release

undefined4 __cdecl __ValidateEH3RN(uint *param_1)

{
  PBYTE pBVar1;
  uint uVar1;
  uint *puVar1;
  BOOL BVar1;
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var1;
  SIZE_T SVar1;
  uint uVar2;
  uint *puVar2;
  PBYTE pBVar2;
  int iVar2;
  int **in_FS_OFFSET;
  bool bVar1;
  uint s5c;
  undefined s4c [24];
  DWORD s34;
  uint *s30;
  uint s2c;
  uint *s28;
  uint s24;
  uint s20;
  uint *s1c;
  int *s14;
  code *pcStack16;
  uint sc;
  undefined4 s8;
  
  pcStack16 = FUN_66210430;
  s14 = *in_FS_OFFSET;
  sc = DAT_6624a120 ^ 0x66223e90;
  s5c = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  s1c = &s5c;
  *in_FS_OFFSET = (int *)&s14;
  s30 = (uint *)param_1[2];
  if (((uint)s30 & 3) == 0) {
    puVar2 = (uint *)in_FS_OFFSET[6][2];
    if ((s30 < puVar2) || ((uint *)in_FS_OFFSET[6][1] <= s30)) {
      s20 = param_1[3];
      if (s20 != 0xffffffff) {
        s24 = 0;
        uVar2 = 0;
        puVar1 = s30;
        do {
          if ((*puVar1 != 0xffffffff) && (uVar2 <= *puVar1)) goto LAB_66214c74;
          if (puVar1[1] != 0) {
            s24 = 1;
          }
          uVar2 = uVar2 + 1;
          puVar1 = puVar1 + 3;
        } while (uVar2 <= s20);
        if ((s24 != 0) && (((uint *)param_1[-2] < puVar2 || (param_1 <= (uint *)param_1[-2]))))
        goto LAB_66214c74;
        uVar2 = (uint)s30 & 0xfffff000;
        for (iVar2 = 0; s2c = uVar2, s28 = s30, puVar2 = &s5c, iVar2 < DAT_6624b7b8;
            iVar2 = iVar2 + 1) {
          s24 = (&DAT_6624b738)[iVar2 * 2];
          pBVar2 = (PBYTE)(&DAT_6624b73c)[iVar2 * 2];
          if (s24 == uVar2) {
            s8 = 0;
            BVar1 = __ValidateImageBase(pBVar2);
            puVar2 = s1c;
            if (((BVar1 != 0) &&
                (iVar1 = _ValidateScopeTableHandlers(pBVar2,(int)s28,s20), puVar2 = s1c, iVar1 != 0)
                ) && (p_Var1 = __FindPESection(pBVar2,param_1[1] - (int)pBVar2),
                     iVar1 = DAT_6624b7bc, puVar2 = s1c, p_Var1 != (PIMAGE_SECTION_HEADER)0x0)) {
              if ((iVar2 < 1) || (DAT_6624b7bc = 1, iVar1 != 0)) goto LAB_66214f7b;
              iVar1 = DAT_6624b7b8;
              if ((&DAT_6624b738)[iVar2 * 2] != uVar2) goto joined_r0x66214da0;
              goto LAB_66214dd8;
            }
            break;
          }
        }
        s1c = puVar2;
        uVar1 = s20;
        puVar2 = s28;
        s8 = 0xfffffffe;
        SVar1 = VirtualQuery(s28,(PMEMORY_BASIC_INFORMATION)s4c,0x1c);
        if (SVar1 != 0) {
          if (s34 == 0x1000000) {
            s28 = (uint *)s4c._4_4_;
            BVar1 = __ValidateImageBase(s4c._4_4_);
            if (BVar1 != 0) {
              if (((((s4c[20] & 0xcc) != 0) &&
                   ((p_Var1 = __FindPESection((PBYTE)s28,(int)puVar2 - (int)s28),
                    p_Var1 == (PIMAGE_SECTION_HEADER)0x0 ||
                    ((p_Var1->Characteristics & 0x80000000) != 0)))) ||
                  (pBVar2 = (PBYTE)s28,
                  iVar2 = _ValidateScopeTableHandlers((PBYTE)s28,(int)puVar2,uVar1), iVar2 == 0)) ||
                 (p_Var1 = __FindPESection(pBVar2,param_1[1] - (int)pBVar2), iVar2 = DAT_6624b7bc,
                 p_Var1 == (PIMAGE_SECTION_HEADER)0x0)) goto LAB_66214c74;
              DAT_6624b7bc = 1;
              if (iVar2 == 0) {
                iVar2 = DAT_6624b7b8;
                if (0 < DAT_6624b7b8) {
                  puVar2 = &DAT_6624b730 + (DAT_6624b7b8 * 2);
                  do {
                    if (*puVar2 == uVar2) break;
                    iVar2 = iVar2 + -1;
                    puVar2 = puVar2 + -2;
                  } while (0 < iVar2);
                }
                if (iVar2 == 0) {
                  iVar2 = 0xf;
                  if (DAT_6624b7b8 < 0x10) {
                    iVar2 = DAT_6624b7b8;
                  }
                  if (-1 < iVar2) {
                    puVar2 = &DAT_6624b738;
                    iVar2 = iVar2 + 1;
                    do {
                      uVar1 = *puVar2;
                      pBVar2 = (PBYTE)puVar2[1];
                      *puVar2 = uVar2;
                      puVar2[1] = (uint)s4c._4_4_;
                      puVar2 = puVar2 + 2;
                      iVar2 = iVar2 + -1;
                      s4c._4_4_ = pBVar2;
                      uVar2 = uVar1;
                    } while (iVar2 != 0);
                  }
                  if (DAT_6624b7b8 < 0x10) {
                    DAT_6624b7b8 = DAT_6624b7b8 + 1;
                  }
                }
                else {
                  *(PBYTE *)(&DAT_6624b734 + (iVar2 * 8)) = s4c._4_4_;
                }
                DAT_6624b7bc = 0;
              }
              goto LAB_66214f7b;
            }
          }
          *in_FS_OFFSET = s14;
          return 0xffffffff;
        }
      }
LAB_66214f7b:
      *in_FS_OFFSET = s14;
      return 1;
    }
  }
LAB_66214c74:
  *in_FS_OFFSET = s14;
  return 0;
  while (iVar1 = iVar2, (&DAT_6624b738)[iVar2 * 2] != uVar2) {
joined_r0x66214da0:
    iVar2 = iVar1 + -1;
    if (iVar2 < 0) goto LAB_66214db1;
  }
  s24 = (&DAT_6624b738)[iVar2 * 2];
  pBVar2 = (PBYTE)(&DAT_6624b73c)[iVar2 * 2];
LAB_66214db1:
  bVar1 = iVar2 < 0;
  if (bVar1) {
    if (DAT_6624b7b8 < 0x10) {
      DAT_6624b7b8 = DAT_6624b7b8 + 1;
    }
    iVar2 = DAT_6624b7b8 + -1;
LAB_66214dd8:
    bVar1 = iVar2 < 0;
  }
  if (((iVar2 != 0) && !bVar1) && (-1 < iVar2)) {
    puVar2 = &DAT_6624b738;
    iVar2 = iVar2 + 1;
    do {
      uVar2 = *puVar2;
      pBVar1 = (PBYTE)puVar2[1];
      *puVar2 = s24;
      puVar2[1] = (uint)pBVar2;
      puVar2 = puVar2 + 2;
      iVar2 = iVar2 + -1;
      pBVar2 = pBVar1;
      s24 = uVar2;
    } while (iVar2 != 0);
  }
  DAT_6624b7bc = 0;
  goto LAB_66214f7b;
}



SIZE_T __cdecl get_allocated_block_size(LPCVOID param_1)

{
  int *piVar1;
  SIZE_T SVar1;
  
  if (param_1 == (LPCVOID)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
    return 0xffffffff;
  }
  SVar1 = HeapSize(hHeap_6624b5e8,0,param_1);
  return SVar1;
}



void __cdecl FUN_66214fc3(uint param_1,uint param_2)

{
  DAT_6624aa30 = (~param_2 & DAT_6624aa30) | (param_1 & param_2);
  return;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2012 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar1;
  BOOL BVar1;
  
  iVar1 = FUN_662156a1();
  if (iVar1 != 0) {
    FUN_662156ca(0x16);
  }
  if (((byte)DAT_6624aa30 & 2) != 0) {
    BVar1 = IsProcessorFeaturePresent(0x17);
    if (BVar1 != 0) {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)();
    }
    FUN_66212b83(3,0x40000015,1);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void __cdecl FUN_66215025(undefined4 param_1)

{
  DAT_6624b7c0 = param_1;
  return;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar1;
  int iVar1;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    if (_Src != (char *)0x0) {
      iVar1 = (int)_Dst - (int)_Src;
      do {
        cVar1 = *_Src;
        _Src[iVar1] = cVar1;
        _Src = _Src + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      piVar1 = __errno();
      iVar1 = 0x22;
      goto LAB_66215054;
    }
    *_Dst = '\0';
  }
  piVar1 = __errno();
  iVar1 = 0x16;
LAB_66215054:
  *piVar1 = iVar1;
  report_invalid_parameter();
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___raise_securityfailure
// 
// Library: Visual Studio 2012 Release

void __cdecl ___raise_securityfailure(EXCEPTION_POINTERS *param_1)

{
  _DAT_6624bae4 = IsDebuggerPresent();
  FUN_662168b4();
  ___crtUnhandledException(param_1);
  if (_DAT_6624bae4 == 0) {
    FUN_662168b4();
  }
  ___crtTerminateProcess(0xc0000409);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2012 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((&lpCriticalSection_6624aa38)[_File * 2] == (undefined *)0x0) {
    iVar1 = FUN_66215247(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&lpCriticalSection_6624aa38)[_File * 2]);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 __cdecl FUN_66215247(int param_1)

{
  LPCRITICAL_SECTION _Memory;
  int *piVar1;
  
  if (hHeap_6624b5e8 == (HANDLE)0x0) {
    __FF_MSGBANNER();
    HandleRuntimeErrorWithLogging(0x1e);
    FUN_6620f746(0xff);
  }
  if ((&lpCriticalSection_6624aa38)[param_1 * 2] == (undefined *)0x0) {
    _Memory = (LPCRITICAL_SECTION)FUN_662102f2(0x18);
    if (_Memory == (LPCRITICAL_SECTION)0x0) {
      piVar1 = __errno();
      *piVar1 = 0xc;
      return 0;
    }
    __lock(10);
    if ((&lpCriticalSection_6624aa38)[param_1 * 2] == (undefined *)0x0) {
      FUN_6620ff78(_Memory,4000,0);
      (&lpCriticalSection_6624aa38)[param_1 * 2] = (undefined *)_Memory;
    }
    else {
      FID_conflict__free(_Memory);
    }
    FUN_662152e7();
  }
  return 1;
}



void FUN_662152e7(void)

{
  leavecritical(10);
  return;
}



undefined4 FUN_662152f0(void)

{
  undefined **ppuVar1;
  LPCRITICAL_SECTION p_Var1;
  
  ppuVar1 = &lpCriticalSection_6624aa38;
  p_Var1 = (LPCRITICAL_SECTION)&DAT_6624bae8;
  do {
    if (((LPCRITICAL_SECTION *)ppuVar1)[1] == (LPCRITICAL_SECTION)0x1) {
      *ppuVar1 = (undefined *)p_Var1;
      p_Var1 = p_Var1 + 1;
      FUN_6620ff78((LPCRITICAL_SECTION)*ppuVar1,4000,0);
    }
    ppuVar1 = (undefined **)((LPCRITICAL_SECTION *)ppuVar1 + 2);
  } while ((int)ppuVar1 < 0x6624ab58);
  return 1;
}



void __cdecl leavecritical(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&lpCriticalSection_6624aa38)[param_1 * 2]);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 2012 Release

void __cdecl __FF_MSGBANNER(void)

{
  int iVar1;
  
  iVar1 = __set_error_mode(3);
  if (iVar1 != 1) {
    iVar1 = __set_error_mode(3);
    if (iVar1 != 0) {
      return;
    }
    if (_DAT_6624bc38 != 1) {
      return;
    }
  }
  HandleRuntimeErrorWithLogging(0xfc);
  HandleRuntimeErrorWithLogging(0xff);
  return;
}



// Library Function - Single Match
//  __GET_RTERRMSG
// 
// Library: Visual Studio 2012 Release

wchar_t * __cdecl __GET_RTERRMSG(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_6621ebf0)[uVar1 * 2]) {
      return (wchar_t *)(&PTR_u_R6002___floating_point_support_n_6621ebf4)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x17);
  return (wchar_t *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl HandleRuntimeErrorWithLogging(int param_1)

{
  code *pcVar1;
  wchar_t *_Src;
  int iVar1;
  errno_t eVar1;
  DWORD DVar1;
  size_t sVar1;
  HANDLE hFile;
  uint uVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined uVar2;
  LPDWORD lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  undefined in_stack_fffffe00;
  char s1fc [500];
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  _Src = __GET_RTERRMSG(param_1);
  uVar2 = extraout_DL;
  if (_Src != (wchar_t *)0x0) {
    iVar1 = __set_error_mode(3);
    if ((iVar1 == 1) || ((iVar1 = __set_error_mode(3), iVar1 == 0 && (_DAT_6624bc38 == 1)))) {
      hFile = GetStdHandle(0xfffffff4);
      uVar2 = extraout_DL_02;
      if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
        uVar1 = 0;
        do {
          s1fc[uVar1] = *(char *)(_Src + uVar1);
          if (_Src[uVar1] == L'\0') break;
          uVar1 = uVar1 + 1;
        } while (uVar1 < 500);
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = (LPDWORD)&stack0xfffffe00;
        s1fc[499] = 0;
        sVar1 = _strlen(s1fc);
        WriteFile(hFile,s1fc,sVar1,lpNumberOfBytesWritten,lpOverlapped);
        uVar2 = extraout_DL_03;
      }
    }
    else {
      uVar2 = extraout_DL_00;
      if (param_1 != 0xfc) {
        eVar1 = _wcscpy_s((wchar_t *)&DAT_6624bc40,0x314,u_Runtime_Error__Program__6621f588);
        if (eVar1 == 0) {
          _DAT_6624be7a = 0;
          DVar1 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&lpFilename_6624bc72,0x104);
          if ((DVar1 != 0) ||
             (eVar1 = _wcscpy_s((wchar_t *)&lpFilename_6624bc72,0x2fb,
                                u__program_name_unknown__6621f5bc), eVar1 == 0)) {
            sVar1 = _wcslen((wchar_t *)&lpFilename_6624bc72);
            if (0x3c < (sVar1 + 1)) {
              sVar1 = _wcslen((wchar_t *)&lpFilename_6624bc72);
              iVar1 = FUN_6620e91d((short *)(&DAT_6624bbfc + (sVar1 * 2)),
                                   0x2fb - ((int)((sVar1 * 2) + -0x76) >> 1),(short *)&DAT_6621f5ec,
                                   3);
              if (iVar1 != 0) goto LAB_6621554d;
            }
            eVar1 = _wcscat_s((wchar_t *)&DAT_6624bc40,0x314,(wchar_t *)&DAT_6621f5f4);
            if ((eVar1 == 0) && (eVar1 = _wcscat_s((wchar_t *)&DAT_6624bc40,0x314,_Src), eVar1 == 0)
               ) {
              FUN_662181f0((LPCWSTR)&DAT_6624bc40,u_Microsoft_Visual_C___Runtime_Lib_6621f600,
                           0x12010);
              uVar2 = extraout_DL_01;
              goto LAB_6621553d;
            }
          }
        }
LAB_6621554d:
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
  }
LAB_6621553d:
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,uVar2,in_stack_fffffe00);
  return;
}



// Library Function - Single Match
//  __FindPESection
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var1;
  uint uVar1;
  
  uVar1 = 0;
  iVar1 = *(int *)(pImageBase + 0x3c);
  p_Var1 = (PIMAGE_SECTION_HEADER)
           (pImageBase + (*(ushort *)(pImageBase + iVar1 + 0x14)) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var1->VirtualAddress <= rva) && (rva < (p_Var1->Misc + p_Var1->VirtualAddress))) {
        return p_Var1;
      }
      uVar1 = uVar1 + 1;
      p_Var1 = p_Var1 + 1;
    } while (uVar1 < (*(ushort *)(pImageBase + iVar1 + 6)));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2019 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  uint uVar1;
  BOOL BVar1;
  PIMAGE_SECTION_HEADER p_Var1;
  int **in_FS_OFFSET;
  int *s14;
  code *pcStack16;
  uint sc;
  undefined4 s8;
  
  pcStack16 = FUN_66210430;
  s14 = *in_FS_OFFSET;
  sc = DAT_6624a120 ^ 0x66223ed0;
  *in_FS_OFFSET = (int *)&s14;
  s8 = 0;
  BVar1 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_66200000);
  if (BVar1 != 0) {
    p_Var1 = __FindPESection((PBYTE)&IMAGE_DOS_HEADER_66200000,(DWORD_PTR)(pTarget + -0x66200000));
    if (p_Var1 != (PIMAGE_SECTION_HEADER)0x0) {
      uVar1 = p_Var1->Characteristics;
      *in_FS_OFFSET = s14;
      return ~(uVar1 >> 0x1f) & 1;
    }
  }
  *in_FS_OFFSET = s14;
  return 0;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Library: Visual Studio 2012 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  uint uVar1;
  
  if (*(short *)pImageBase != 0x5a4d) {
    return 0;
  }
  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550) {
    uVar1 = (uint)(*(short *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return uVar1;
}



void FUN_662156a1(void)

{
  DecodePointer(Ptr_6624c270);
  return;
}



void __cdecl FUN_662156ae(PVOID param_1)

{
  DAT_6624c268 = param_1;
  DAT_6624c26c = param_1;
  Ptr_6624c270 = param_1;
  DAT_6624c274 = param_1;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 __cdecl FUN_662156ca(int param_1)

{
  bool bVar1;
  uint uVar1;
  int *piVar1;
  PVOID Ptr;
  code *pcVar1;
  code *pcVar2;
  int iVar1;
  _ptiddata p_Var1;
  int s34;
  void *s30;
  PVOID *s20;
  
  s30 = (void *)0x0;
  s34 = 0;
  bVar1 = false;
  p_Var1 = (_ptiddata)0x0;
  if (param_1 < 0xc) {
    if (param_1 != 0xb) {
      if (param_1 == 2) {
        s20 = &DAT_6624c268;
        Ptr = DAT_6624c268;
        goto LAB_66215789;
      }
      if (param_1 != 4) {
        if (param_1 == 6) goto LAB_66215761;
        if (param_1 != 8) goto LAB_6621574f;
      }
    }
    p_Var1 = __getptd_noexit();
    if (p_Var1 == (_ptiddata)0x0) {
      return 0xffffffff;
    }
    uVar1 = FUN_66215885(param_1,(uint)p_Var1->_pxcptacttab);
    s20 = (PVOID *)(uVar1 + 8);
    pcVar1 = (code *)*s20;
  }
  else {
    if (param_1 == 0xf) {
      s20 = &DAT_6624c274;
      Ptr = DAT_6624c274;
    }
    else if (param_1 == 0x15) {
      s20 = &DAT_6624c26c;
      Ptr = DAT_6624c26c;
    }
    else {
      if (param_1 != 0x16) {
LAB_6621574f:
        piVar1 = __errno();
        *piVar1 = 0x16;
        report_invalid_parameter();
        return 0xffffffff;
      }
LAB_66215761:
      s20 = &Ptr_6624c270;
      Ptr = Ptr_6624c270;
    }
LAB_66215789:
    bVar1 = true;
    pcVar1 = (code *)DecodePointer(Ptr);
  }
  if (pcVar1 == (code *)0x1) {
    return 0;
  }
  if (pcVar1 == (code *)0x0) {
    __exit(3);
  }
  if (bVar1) {
    __lock(0);
  }
  if (((param_1 == 8) || (param_1 == 0xb)) || (param_1 == 4)) {
    s30 = p_Var1->_tpxcptinfoptrs;
    p_Var1->_tpxcptinfoptrs = (void *)0x0;
    if (param_1 == 8) {
      s34 = p_Var1->_tfpecode;
      p_Var1->_tfpecode = 0x8c;
      goto LAB_662157e8;
    }
  }
  else {
LAB_662157e8:
    iVar1 = DAT_6621e3e8;
    if (param_1 == 8) {
      for (; iVar1 < (DAT_6621e3ec + DAT_6621e3e8); iVar1 = iVar1 + 1) {
        *(undefined4 *)((int)p_Var1->_pxcptacttab + (iVar1 * 0xc) + 8) = 0;
      }
      goto LAB_66215827;
    }
  }
  pcVar2 = (code *)EncodePointer((PVOID)0x0);
  *s20 = pcVar2;
LAB_66215827:
  FUN_6621584b();
  if (param_1 == 8) {
    (*pcVar1)(8,p_Var1->_tfpecode);
  }
  else {
    (*pcVar1)(param_1);
    if ((param_1 != 0xb) && (param_1 != 4)) {
      return 0;
    }
  }
  p_Var1->_tpxcptinfoptrs = s30;
  if (param_1 == 8) {
    p_Var1->_tfpecode = s34;
  }
  return 0;
}



void FUN_6621584b(void)

{
  int unaff_EBX;
  
  if (unaff_EBX != 0) {
    leavecritical(0);
  }
  return;
}



uint __cdecl FUN_66215885(int param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = param_2;
  do {
    if (*(int *)(uVar1 + 4) == param_1) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < ((DAT_6621e3e0 * 0xc) + param_2));
  if ((((DAT_6621e3e0 * 0xc) + param_2) <= uVar1) || (*(int *)(uVar1 + 4) != param_1)) {
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_662158bf(undefined4 param_1)

{
  _DAT_6624c27c = param_1;
  return;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind4(uint *param_1,int param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack40;
  undefined *puStack36;
  uint s20;
  uint uStack28;
  int iStack24;
  uint *puStack20;
  
  puStack20 = param_1;
  iStack24 = param_2;
  uStack28 = param_3;
  puStack36 = &LAB_66215960;
  uStack40 = *in_FS_OFFSET;
  s20 = DAT_6624a120 ^ (uint)&uStack40;
  *in_FS_OFFSET = &uStack40;
  while( true ) {
    uVar1 = *(uint *)(param_2 + 0xc);
    if ((uVar1 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar1 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + (uVar1 * 0xc));
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_66214b64();
    }
  }
  *in_FS_OFFSET = uStack40;
  return;
}



void FUN_662159a6(int param_1)

{
  __local_unwind4(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x662159f0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void __fastcall FUN_662159f2(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  RtlUnwind(param_1,(PVOID)0x66215a06,param_2,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



undefined ** FUN_66215abc(void)

{
  return &PTR_DAT_6624ab60;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2012 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_6624ab60) || ((FILE *)&DAT_6624adc0 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)(_File + -0x331255b) >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Library: Visual Studio 2012 Release

void __cdecl __lock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    __lock(_Index + 0x10);
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) | 0x8000;
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)0x6624ab5f < _File) && (_File < (FILE *)0x6624adc1)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    leavecritical(((int)(_File + -0x331255b) >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2012 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) & 0xffff7fff;
    leavecritical(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _realloc
// 
// Library: Visual Studio 2012 Release

void * __cdecl _realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  LPVOID pvVar2;
  int iVar1;
  int *piVar1;
  DWORD DVar1;
  
  if (_Memory == (void *)0x0) {
    pvVar1 = _malloc(_NewSize);
    return pvVar1;
  }
  if (_NewSize == 0) {
    FID_conflict__free(_Memory);
  }
  else {
    do {
      if (0xffffffe0 < _NewSize) {
        __callnewh(_NewSize);
        piVar1 = __errno();
        *piVar1 = 0xc;
        return (void *)0x0;
      }
      if (_NewSize == 0) {
        _NewSize = 1;
      }
      pvVar2 = HeapReAlloc(hHeap_6624b5e8,0,_Memory,_NewSize);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      if (_DAT_6624c294 == 0) {
        piVar1 = __errno();
        DVar1 = GetLastError();
        iVar1 = __get_errno_from_oserr(DVar1);
        *piVar1 = iVar1;
        return (void *)0x0;
      }
      iVar1 = __callnewh(_NewSize);
    } while (iVar1 != 0);
    piVar1 = __errno();
    DVar1 = GetLastError();
    iVar1 = __get_errno_from_oserr(DVar1);
    *piVar1 = iVar1;
  }
  return (void *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __calloc_impl
// 
// Library: Visual Studio 2012 Release

LPVOID __cdecl __calloc_impl(uint param_1,uint param_2,int *param_3)

{
  int iVar1;
  LPVOID pvVar1;
  uint dwBytes;
  
  if ((param_1 == 0) || (param_2 <= (0xffffffe0 / param_1))) {
    dwBytes = param_1 * param_2;
    if (dwBytes == 0) {
      dwBytes = 1;
    }
    do {
      pvVar1 = (LPVOID)0x0;
      if ((dwBytes < 0xffffffe1) &&
         (pvVar1 = HeapAlloc(hHeap_6624b5e8,8,dwBytes), pvVar1 != (LPVOID)0x0)) {
        return pvVar1;
      }
      if (_DAT_6624c294 == 0) {
        if (param_3 != (int *)0x0) {
          *param_3 = 0xc;
          return pvVar1;
        }
        return pvVar1;
      }
      iVar1 = __callnewh(dwBytes);
    } while (iVar1 != 0);
    if (param_3 == (int *)0x0) {
      return (LPVOID)0x0;
    }
  }
  else {
    param_3 = __errno();
  }
  *param_3 = 0xc;
  return (LPVOID)0x0;
}



float10 __fastcall
FUN_66215e90(undefined4 param_1,int param_2,ushort param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float10 in_ST0;
  int s24;
  undefined4 uStack32;
  undefined4 uStack28;
  undefined4 uStack24;
  undefined4 s14;
  undefined4 s10;
  double dStack12;
  
  s14 = param_7;
  s10 = param_8;
  dStack12 = (double)in_ST0;
  uStack28 = param_5;
  uStack24 = param_6;
  uStack32 = param_1;
  __87except(param_2,&s24,&param_3);
  return (float10)dStack12;
}



// Library Function - Single Match
//  __startOneArgErrorHandling
// 
// Library: Visual Studio 2019 Release

float10 __fastcall
__startOneArgErrorHandling
          (undefined4 param_1,int param_2,ushort param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6)

{
  float10 in_ST0;
  int s24;
  undefined4 s20;
  undefined4 s1c;
  undefined4 s18;
  double sc;
  
  sc = (double)in_ST0;
  s1c = param_5;
  s18 = param_6;
  s20 = param_1;
  __87except(param_2,&s24,&param_3);
  return (float10)sc;
}



void FUN_66215f05(undefined4 param_1)

{
  return;
}



undefined4 FUN_66215f1c(void)

{
  uint in_EAX;
  
  if ((in_EAX & 0x80000) != 0) {
    return 7;
  }
  return 1;
}


/*
Unable to decompile 'FUN_66215f78'
Cause: Exception while decompiling 66215f78: Decompiler process died

*/


byte __cdecl FUN_6621607c(int param_1)

{
  return -(param_1 != 0) & 1;
}



ushort __cdecl FUN_6621608b(int param_1,pthreadlocinfo *param_2)

{
  ushort uVar1;
  pthreadlocinfo s14 [2];
  int sc;
  char s8;
  
  FUN_6620e53b(s14,param_2);
  if (s14[0]->mb_cur_max < 2) {
    uVar1 = s14[0]->pctype[param_1] & 4;
  }
  else {
    uVar1 = FUN_662146e0(param_1,4,s14);
  }
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _isdigit
// 
// Library: Visual Studio 2012 Release

int __cdecl _isdigit(int _C)

{
  ushort uVar1;
  undefined2 extraout_var;
  
  if (_DAT_6624b728 == 0) {
    return (*(ushort *)(PTR_DAT_6624a9e8 + (_C * 2))) & 4;
  }
  uVar1 = FUN_6621608b(_C,(pthreadlocinfo *)0x0);
  return ((int)(short)extraout_var << 0x10) + uVar1;
}



uint __cdecl FUN_66216108(uint param_1,pthreadlocinfo *param_2)

{
  ushort uVar1;
  undefined2 extraout_var;
  uint uVar2;
  int iVar1;
  int *piVar1;
  undefined4 uVar3;
  pthreadlocinfo s1c [2];
  int s14;
  char s10;
  byte sc;
  undefined sb;
  undefined s8;
  undefined s7;
  undefined s6;
  
  FUN_6620e53b(s1c,param_2);
  if (param_1 < 0x100) {
    if (s1c[0]->mb_cur_max < 2) {
      uVar2 = (s1c[0]->pctype[param_1]) & 1;
    }
    else {
      uVar1 = FUN_662146e0(param_1,1,s1c);
      uVar2 = ((int)(short)extraout_var << 0x10) + uVar1;
    }
    if (uVar2 == 0) {
      if (s10 != '\0') {
        *(uint *)(s14 + 0x70) = *(uint *)(s14 + 0x70) & 0xfffffffd;
      }
    }
    else {
      param_1 = (uint)s1c[0]->pclmap[param_1];
      if (s10 != '\0') {
        *(uint *)(s14 + 0x70) = *(uint *)(s14 + 0x70) & 0xfffffffd;
      }
    }
  }
  else {
    if ((s1c[0]->mb_cur_max < 2) ||
       (iVar1 = FUN_6620e813(((int)param_1 >> 8) & 0xff,s1c), iVar1 == 0)) {
      piVar1 = __errno();
      uVar3 = 1;
      *piVar1 = 0x2a;
      s7 = 0;
      s8 = (char)param_1;
    }
    else {
      s6 = 0;
      uVar3 = 2;
      s8 = (char)(param_1 >> 8);
      s7 = (char)param_1;
    }
    iVar1 = FUN_66217dcc(s1c,s1c[0]->locale_name[2],0x100,&s8,uVar3,&sc,3,s1c[0]->lc_codepage,1);
    if (iVar1 == 0) {
      if (s10 != '\0') {
        *(uint *)(s14 + 0x70) = *(uint *)(s14 + 0x70) & 0xfffffffd;
      }
    }
    else if (iVar1 == 1) {
      param_1 = (uint)sc;
      if (s10 != '\0') {
        *(uint *)(s14 + 0x70) = *(uint *)(s14 + 0x70) & 0xfffffffd;
      }
    }
    else {
      param_1 = (uint)(ushort)(((short)(char)sc << 8) + sb);
      if (s10 != '\0') {
        *(uint *)(s14 + 0x70) = *(uint *)(s14 + 0x70) & 0xfffffffd;
      }
    }
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _tolower
// 
// Library: Visual Studio 2012 Release

int __cdecl _tolower(int _C)

{
  uint uVar1;
  
  if (_DAT_6624b728 == 0) {
    if ((_C - 0x41U) < 0x1a) {
      _C = _C + 0x20;
    }
    return _C;
  }
  uVar1 = FUN_66216108(_C,(pthreadlocinfo *)0x0);
  return uVar1;
}



int __cdecl FUN_66216277(char *param_1,uint param_2,int param_3,int param_4)

{
  char *_Str;
  int *piVar1;
  char *pcVar1;
  size_t sVar1;
  char cVar1;
  char *pcVar2;
  int iVar1;
  
  pcVar2 = *(char **)(param_4 + 0xc);
  if ((param_1 == (char *)0x0) || (param_2 == 0)) {
    piVar1 = __errno();
    iVar1 = 0x16;
  }
  else {
    *param_1 = '\0';
    iVar1 = param_3;
    if (param_3 < 1) {
      iVar1 = 0;
    }
    if ((iVar1 + 1U) < param_2) {
      *param_1 = '0';
      _Str = param_1 + 1;
      pcVar1 = _Str;
      if (0 < param_3) {
        do {
          cVar1 = *pcVar2;
          if (cVar1 == '\0') {
            cVar1 = '0';
          }
          else {
            pcVar2 = pcVar2 + 1;
          }
          *pcVar1 = cVar1;
          pcVar1 = pcVar1 + 1;
          param_3 = param_3 + -1;
        } while (0 < param_3);
      }
      *pcVar1 = '\0';
      if ((-1 < param_3) && ('4' < *pcVar2)) {
        while (pcVar1 = pcVar1 + -1, *pcVar1 == '9') {
          *pcVar1 = '0';
        }
        *pcVar1 = *pcVar1 + '\x01';
      }
      if (*param_1 == '1') {
        *(int *)(param_4 + 4) = *(int *)(param_4 + 4) + 1;
      }
      else {
        sVar1 = _strlen(_Str);
        FUN_6620dc00(param_1,_Str,sVar1 + 1);
      }
      return 0;
    }
    piVar1 = __errno();
    iVar1 = 0x22;
  }
  *piVar1 = iVar1;
  report_invalid_parameter();
  return iVar1;
}



void __cdecl FUN_66216327(uint *param_1,char *param_2,pthreadlocinfo *param_3,char **param_4)

{
  undefined extraout_DL;
  undefined in_stack_ffffffd0;
  int s28;
  char s24;
  char *s1c;
  uint *s18;
  ushort s14 [6];
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  s18 = param_1;
  FUN_6620e53b(&stack0xffffffd0,param_3);
  FUN_662191f7(s14,&s1c,param_2,0,0,0,0,(int *)&stack0xffffffd0);
  if (param_4 != (char **)0x0) {
    *param_4 = s1c;
  }
  FUN_66218c85(s14,s18);
  if (s24 != '\0') {
    *(uint *)(s28 + 0x70) = *(uint *)(s28 + 0x70) & 0xfffffffd;
  }
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,extraout_DL,in_stack_ffffffd0);
  return;
}



void __cdecl FUN_662163cb(uint *param_1,char *param_2,pthreadlocinfo *param_3)

{
  undefined extraout_DL;
  undefined in_stack_ffffffd4;
  int s24;
  char s20;
  char *s1c;
  undefined4 s18;
  ushort s14 [6];
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  FUN_6620e53b(&stack0xffffffd4,param_3);
  s18 = FUN_662191f7(s14,&s1c,param_2,0,0,0,0,(int *)&stack0xffffffd4);
  FUN_66218713(s14,param_1);
  if (s20 != '\0') {
    *(uint *)(s24 + 0x70) = *(uint *)(s24 + 0x70) & 0xfffffffd;
  }
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,extraout_DL,in_stack_ffffffd4);
  return;
}



void __cdecl FUN_66216459(uint *param_1,char *param_2,pthreadlocinfo *param_3)

{
  FUN_66216327(param_1,param_2,param_3,(char **)0x0);
  return;
}



void __cdecl FUN_66216471(uint *param_1,uint *param_2)

{
  uint uVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  ushort uVar6;
  
  uVar4 = 0x80000000;
  uVar1 = *param_2;
  uVar6 = *(ushort *)((int)param_2 + 6) & 0x8000;
  uVar2 = *(ushort *)((int)param_2 + 6) >> 4;
  uVar3 = uVar2 & 0x7ff;
  if ((uVar2 & 0x7ff) == 0) {
    if (((param_2[1] & 0xfffff) == 0) && (uVar1 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      *(ushort *)(param_1 + 2) = uVar6;
      return;
    }
    uVar3 = uVar3 + 0x3c01;
    uVar4 = 0;
  }
  else if (uVar3 == 0x7ff) {
    uVar3 = 0x7fff;
  }
  else {
    uVar3 = uVar3 + 0x3c00;
  }
  uVar5 = (uVar1 >> 0x15) | ((param_2[1] & 0xfffff) << 0xb) | uVar4;
  param_1[1] = uVar5;
  *param_1 = uVar1 << 0xb;
  if (uVar4 == 0) {
    do {
      uVar3 = uVar3 - 1;
      uVar5 = (uVar5 * 2) | (*param_1 >> 0x1f);
      *param_1 = *param_1 * 2;
    } while (-1 < (int)uVar5);
    param_1[1] = uVar5;
  }
  *(ushort *)(param_1 + 2) = uVar6 | uVar3;
  return;
}



void __cdecl
FUN_66216539(uint param_1,undefined4 param_2,int *param_3,char *param_4,rsize_t param_5)

{
  code *pcVar1;
  int *piVar1;
  char *_Dst;
  int iVar1;
  errno_t eVar1;
  undefined extraout_DL;
  undefined4 in_stack_ffffffb0;
  undefined2 uVar1;
  undefined uVar2;
  uint in_stack_ffffffcc;
  undefined4 uStack48;
  undefined2 uStack44;
  short s24;
  char s22;
  char s20 [24];
  uint s8;
  
  _Dst = param_4;
  piVar1 = param_3;
  uVar1 = (undefined2)((uint)in_stack_ffffffb0 >> 0x10);
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  FUN_66216471((uint *)&stack0xffffffcc,&param_1);
  iVar1 = FUN_6621999f(in_stack_ffffffcc,uStack48,((int)(short)uVar1 << 0x10) + uStack44,0x11,0,&s24
                      );
  uVar2 = (undefined)in_stack_ffffffcc;
  piVar1[2] = iVar1;
  *piVar1 = (int)s22;
  piVar1[1] = (int)s24;
  eVar1 = _strcpy_s(_Dst,param_5,s20);
  if (eVar1 == 0) {
    piVar1[3] = (int)_Dst;
    FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,extraout_DL,uVar2);
    return;
  }
  __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __alldvrm
// 
// Library: Visual Studio

undefined8 __alldvrm(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar1;
  uint uVar2;
  int iVar1;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  bool bVar1;
  char cVar1;
  uint uVar7;
  
  cVar1 = (int)param_2 < 0;
  if ((bool)cVar1) {
    bVar1 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar1 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar1 = cVar1 + '\x01';
    bVar1 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar1 - param_4;
  }
  uVar2 = param_1;
  uVar3 = param_3;
  uVar4 = param_2;
  uVar7 = param_4;
  if (param_4 == 0) {
    uVar2 = param_2 / param_3;
    iVar1 = (int)(((((ulonglong)param_2 % (ulonglong)param_3) << 0x20) | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar6 = uVar7 >> 1;
      uVar3 = (uVar3 >> 1) | ((uint)((uVar7 & 1) != 0) << 0x1f);
      uVar5 = uVar4 >> 1;
      uVar2 = (uVar2 >> 1) | ((uint)((uVar4 & 1) != 0) << 0x1f);
      uVar4 = uVar5;
      uVar7 = uVar6;
    } while (uVar6 != 0);
    uVar1 = (ulonglong)(((longlong)(int)uVar5 << 0x20) + uVar2) / (ulonglong)uVar3;
    iVar1 = (int)uVar1;
    lVar1 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar2 = (uint)((ulonglong)lVar1 >> 0x20);
    uVar3 = uVar2 + (iVar1 * param_4);
    if (((CARRY4(uVar2,iVar1 * param_4)) || (param_2 < uVar3)) ||
       ((param_2 <= uVar3 && (param_1 < (uint)lVar1)))) {
      iVar1 = iVar1 + -1;
    }
    uVar2 = 0;
  }
  if (cVar1 == '\x01') {
    bVar1 = iVar1 != 0;
    iVar1 = -iVar1;
    uVar2 = -(uint)bVar1 - uVar2;
  }
  return ((longlong)(int)uVar2 << 0x20) + iVar1;
}


/*
Unable to decompile '__controlfp_s'
Cause: Exception while decompiling 662166af: Decompiler process died

*/


// Library Function - Single Match
//  __wchartodigit
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2019 Release

int __cdecl __wchartodigit(ushort param_1)

{
  ushort uVar1;
  int iVar1;
  
  if (0x2f < param_1) {
    if (param_1 < 0x3a) {
      return (param_1) - 0x30;
    }
    iVar1 = 0xff10;
    if (param_1 < 0xff10) {
      iVar1 = 0x660;
      if (param_1 < 0x660) {
        return -1;
      }
      if (param_1 < 0x66a) goto LAB_66216759;
      iVar1 = 0x6f0;
      if (param_1 < 0x6f0) {
        return -1;
      }
      if (param_1 < 0x6fa) goto LAB_66216759;
      iVar1 = 0x966;
      if (param_1 < 0x966) {
        return -1;
      }
      if (param_1 < 0x970) goto LAB_66216759;
      iVar1 = 0x9e6;
      if (param_1 < 0x9e6) {
        return -1;
      }
      if (param_1 < 0x9f0) goto LAB_66216759;
      iVar1 = 0xa66;
      if (param_1 < 0xa66) {
        return -1;
      }
      if (param_1 < 0xa70) goto LAB_66216759;
      iVar1 = 0xae6;
      if (param_1 < 0xae6) {
        return -1;
      }
      if (param_1 < 0xaf0) goto LAB_66216759;
      iVar1 = 0xb66;
      if (param_1 < 0xb66) {
        return -1;
      }
      if (param_1 < 0xb70) goto LAB_66216759;
      iVar1 = 0xc66;
      if (param_1 < 0xc66) {
        return -1;
      }
      if (param_1 < 0xc70) goto LAB_66216759;
      iVar1 = 0xce6;
      if (param_1 < 0xce6) {
        return -1;
      }
      if (param_1 < 0xcf0) goto LAB_66216759;
      iVar1 = 0xd66;
      if (param_1 < 0xd66) {
        return -1;
      }
      if (param_1 < 0xd70) goto LAB_66216759;
      iVar1 = 0xe50;
      if (param_1 < 0xe50) {
        return -1;
      }
      if (param_1 < 0xe5a) goto LAB_66216759;
      iVar1 = 0xed0;
      if (param_1 < 0xed0) {
        return -1;
      }
      if (param_1 < 0xeda) goto LAB_66216759;
      iVar1 = 0xf20;
      if (param_1 < 0xf20) {
        return -1;
      }
      if (param_1 < 0xf2a) goto LAB_66216759;
      iVar1 = 0x1040;
      if (param_1 < 0x1040) {
        return -1;
      }
      if (param_1 < 0x104a) goto LAB_66216759;
      iVar1 = 0x17e0;
      if (param_1 < 0x17e0) {
        return -1;
      }
      if (param_1 < 0x17ea) goto LAB_66216759;
      iVar1 = 0x1810;
      if (param_1 < 0x1810) {
        return -1;
      }
      uVar1 = 0x181a;
    }
    else {
      uVar1 = 0xff1a;
    }
    if (param_1 < uVar1) {
LAB_66216759:
      return (uint)param_1 - iVar1;
    }
  }
  return -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_662168b4(void)

{
  _DAT_6624c2f8 = 0;
  return;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2012 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
    return -1;
  }
  return _File->_file;
}


/*
Unable to decompile 'FUN_662168e0'
Cause: Exception while decompiling 662168e0: Decompiler process died

*/

/*
Unable to decompile 'FUN_66216934'
Cause: Exception while decompiling 66216934: Decompiler process died

*/


void FUN_662169fb(void)

{
  FUN_6621a93b();
  return;
}


/*
Unable to decompile 'FUN_66216a23'
Cause: Exception while decompiling 66216a23: Decompiler process died

*/

/*
Unable to decompile 'FUN_66217288'
Cause: Exception while decompiling 66217288: Decompiler process died

*/


void FUN_6621735a(void)

{
  FUN_6621a93b();
  return;
}


/*
Unable to decompile 'FUN_66217384'
Cause: Exception while decompiling 66217384: Decompiler process died

*/


// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2012 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_6624c288 = _DAT_6624c288 + 1;
  pcVar1 = (char *)FUN_662102f2(0x1000);
  _File->_base = pcVar1;
  if (pcVar1 == (char *)0x0) {
    _File->_flag = _File->_flag | 4;
    _File->_base = (char *)&_File->_charbuf;
    _File->_bufsiz = 2;
  }
  else {
    _File->_flag = _File->_flag | 8;
    _File->_bufsiz = 0x1000;
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_6621743d(void)

{
  return _DAT_6624c290 == (DAT_6624a120 | 1);
}


/*
Unable to decompile 'FUN_66217452'
Cause: Exception while decompiling 66217452: Decompiler process died

*/


undefined4 __cdecl FUN_662175d8(ushort *param_1,byte *param_2,uint param_3,pthreadlocinfo *param_4)

{
  uint uVar1;
  int iVar1;
  int *piVar1;
  undefined4 uVar2;
  int s14 [2];
  int sc;
  char s8;
  
  if ((param_2 == (byte *)0x0) || (param_3 == 0)) {
    return 0;
  }
  if (*param_2 == 0) {
    if (param_1 == (ushort *)0x0) {
      return 0;
    }
    *param_1 = 0;
    return 0;
  }
  FUN_6620e53b(s14,param_4);
  if (*(int *)(s14[0] + 0xa8) == 0) {
    if (param_1 != (ushort *)0x0) {
      *param_1 = (ushort)*param_2;
    }
    uVar2 = 1;
    goto LAB_662176b8;
  }
  iVar1 = FUN_6620e813(*param_2,s14);
  if (iVar1 == 0) {
    uVar2 = 1;
    iVar1 = MultiByteToWideChar(*(UINT *)(s14[0] + 4),9,(LPCSTR)param_2,1,(LPWSTR)param_1,
                                (uint)(param_1 != (ushort *)0x0));
    if (iVar1 != 0) goto LAB_662176b8;
LAB_662176aa:
    piVar1 = __errno();
    uVar2 = 0xffffffff;
    *piVar1 = 0x2a;
  }
  else {
    if (*(int *)(s14[0] + 0x74) < 2) {
LAB_66217677:
      uVar1 = *(uint *)(s14[0] + 0x74);
LAB_6621767a:
      if ((param_3 < uVar1) || (param_2[1] == 0)) goto LAB_662176aa;
    }
    else {
      uVar1 = *(uint *)(s14[0] + 0x74);
      if ((int)param_3 < (int)*(uint *)(s14[0] + 0x74)) goto LAB_6621767a;
      iVar1 = MultiByteToWideChar(*(UINT *)(s14[0] + 4),9,(LPCSTR)param_2,*(int *)(s14[0] + 0x74),
                                  (LPWSTR)param_1,(uint)(param_1 != (ushort *)0x0));
      if (iVar1 == 0) goto LAB_66217677;
    }
    uVar2 = *(undefined4 *)(s14[0] + 0x74);
  }
LAB_662176b8:
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
    return uVar2;
  }
  return uVar2;
}



void __cdecl FUN_662176cd(ushort *param_1,byte *param_2,uint param_3)

{
  FUN_662175d8(param_1,param_2,param_3,(pthreadlocinfo *)0x0);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_locale_free_monetary
//  ___free_lconv_mon
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

void __cdecl FID_conflict____acrt_locale_free_monetary(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_6624ae0c) {
      FID_conflict__free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_6624ae10) {
      FID_conflict__free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_6624ae14) {
      FID_conflict__free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_6624ae18) {
      FID_conflict__free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_6624ae1c) {
      FID_conflict__free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_6624ae20) {
      FID_conflict__free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_6624ae24) {
      FID_conflict__free(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_6624ae38) {
      FID_conflict__free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_6624ae3c) {
      FID_conflict__free(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_6624ae40) {
      FID_conflict__free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_6624ae44) {
      FID_conflict__free(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_6624ae48) {
      FID_conflict__free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_6624ae4c) {
      FID_conflict__free(*(undefined **)(param_1 + 0x4c));
    }
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_locale_free_numeric
//  ___free_lconv_num
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

void __cdecl FID_conflict____free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_6624ae00) {
      FID_conflict__free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_6624ae04) {
      FID_conflict__free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_6624ae08) {
      FID_conflict__free(param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_6624ae30) {
      FID_conflict__free(param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_6624ae34) {
      FID_conflict__free(param_1[0xd]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lc_time
// 
// Library: Visual Studio 2012 Release

void __cdecl ___free_lc_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    FID_conflict__free(param_1[1]);
    FID_conflict__free(param_1[2]);
    FID_conflict__free(param_1[3]);
    FID_conflict__free(param_1[4]);
    FID_conflict__free(param_1[5]);
    FID_conflict__free(param_1[6]);
    FID_conflict__free(*param_1);
    FID_conflict__free(param_1[8]);
    FID_conflict__free(param_1[9]);
    FID_conflict__free(param_1[10]);
    FID_conflict__free(param_1[0xb]);
    FID_conflict__free(param_1[0xc]);
    FID_conflict__free(param_1[0xd]);
    FID_conflict__free(param_1[7]);
    FID_conflict__free(param_1[0xe]);
    FID_conflict__free(param_1[0xf]);
    FID_conflict__free(param_1[0x10]);
    FID_conflict__free(param_1[0x11]);
    FID_conflict__free(param_1[0x12]);
    FID_conflict__free(param_1[0x13]);
    FID_conflict__free(param_1[0x14]);
    FID_conflict__free(param_1[0x15]);
    FID_conflict__free(param_1[0x16]);
    FID_conflict__free(param_1[0x17]);
    FID_conflict__free(param_1[0x18]);
    FID_conflict__free(param_1[0x19]);
    FID_conflict__free(param_1[0x1a]);
    FID_conflict__free(param_1[0x1b]);
    FID_conflict__free(param_1[0x1c]);
    FID_conflict__free(param_1[0x1d]);
    FID_conflict__free(param_1[0x1e]);
    FID_conflict__free(param_1[0x1f]);
    FID_conflict__free(param_1[0x20]);
    FID_conflict__free(param_1[0x21]);
    FID_conflict__free(param_1[0x22]);
    FID_conflict__free(param_1[0x23]);
    FID_conflict__free(param_1[0x24]);
    FID_conflict__free(param_1[0x25]);
    FID_conflict__free(param_1[0x26]);
    FID_conflict__free(param_1[0x27]);
    FID_conflict__free(param_1[0x28]);
    FID_conflict__free(param_1[0x29]);
    FID_conflict__free(param_1[0x2a]);
    FID_conflict__free(param_1[0x2e]);
    FID_conflict__free(param_1[0x2f]);
    FID_conflict__free(param_1[0x30]);
    FID_conflict__free(param_1[0x31]);
    FID_conflict__free(param_1[0x32]);
    FID_conflict__free(param_1[0x33]);
    FID_conflict__free(param_1[0x2d]);
    FID_conflict__free(param_1[0x35]);
    FID_conflict__free(param_1[0x36]);
    FID_conflict__free(param_1[0x37]);
    FID_conflict__free(param_1[0x38]);
    FID_conflict__free(param_1[0x39]);
    FID_conflict__free(param_1[0x3a]);
    FID_conflict__free(param_1[0x34]);
    FID_conflict__free(param_1[0x3b]);
    FID_conflict__free(param_1[0x3c]);
    FID_conflict__free(param_1[0x3d]);
    FID_conflict__free(param_1[0x3e]);
    FID_conflict__free(param_1[0x3f]);
    FID_conflict__free(param_1[0x40]);
    FID_conflict__free(param_1[0x41]);
    FID_conflict__free(param_1[0x42]);
    FID_conflict__free(param_1[0x43]);
    FID_conflict__free(param_1[0x44]);
    FID_conflict__free(param_1[0x45]);
    FID_conflict__free(param_1[0x46]);
    FID_conflict__free(param_1[0x47]);
    FID_conflict__free(param_1[0x48]);
    FID_conflict__free(param_1[0x49]);
    FID_conflict__free(param_1[0x4a]);
    FID_conflict__free(param_1[0x4b]);
    FID_conflict__free(param_1[0x4c]);
    FID_conflict__free(param_1[0x4d]);
    FID_conflict__free(param_1[0x4e]);
    FID_conflict__free(param_1[0x4f]);
    FID_conflict__free(param_1[0x50]);
    FID_conflict__free(param_1[0x51]);
    FID_conflict__free(param_1[0x52]);
    FID_conflict__free(param_1[0x53]);
    FID_conflict__free(param_1[0x54]);
    FID_conflict__free(param_1[0x55]);
    FID_conflict__free(param_1[0x56]);
    FID_conflict__free(param_1[0x57]);
    FID_conflict__free(param_1[0x58]);
  }
  return;
}


/*
Unable to decompile 'FUN_66217bc8'
Cause: Exception while decompiling 66217bc8: Decompiler process died

*/


void __cdecl
FUN_66217dcc(pthreadlocinfo *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
            undefined4 param_9)

{
  undefined s14 [8];
  int sc;
  char s8;
  
  FUN_6620e53b(s14,param_1);
  FUN_66217bc8(s14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return;
}



void __cdecl FUN_66217e12(int param_1)

{
  if ((param_1 != 0) && (*(int *)(param_1 + -8) == 0xdddd)) {
    FID_conflict__free((int *)(param_1 + -8));
  }
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe

void __cdecl
FUN_66217e30(int *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,UINT param_6,
            int param_7)

{
  uint _Size;
  uint uVar1;
  uint cchWideChar;
  undefined4 *puVar1;
  int cchSrc;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  undefined extraout_DL_01;
  
  uVar1 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  if (param_6 == 0) {
    param_6 = *(UINT *)(*param_1 + 4);
  }
  cchWideChar = MultiByteToWideChar(param_6,((uint)(param_7 != 0) * 8) + 1,param_3,param_4,
                                    (LPWSTR)0x0,0);
  uVar2 = extraout_DL;
  if (cchWideChar == 0) goto LAB_66217f14;
  if ((((int)cchWideChar < 1) || (0x7ffffff0 < cchWideChar)) ||
     (((cchWideChar * 2) + 8) <= (cchWideChar * 2))) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    _Size = (cchWideChar * 2) + 8;
    if (_Size < 0x401) {
      puVar1 = (undefined4 *)&stack0xffffffec;
      if ((undefined *)register0x00000010 == (undefined *)0x14) goto LAB_66217f14;
    }
    else {
      puVar1 = (undefined4 *)_malloc(_Size);
      uVar2 = extraout_DL_00;
      if (puVar1 == (undefined4 *)0x0) goto LAB_66217f14;
      *puVar1 = 0xdddd;
    }
    puVar1 = puVar1 + 2;
  }
  if (puVar1 != (undefined4 *)0x0) {
    FUN_6620d410(puVar1,0,cchWideChar * 2);
    cchSrc = MultiByteToWideChar(param_6,1,param_3,param_4,(LPWSTR)puVar1,cchWideChar);
    if (cchSrc != 0) {
      GetStringTypeW(param_2,(LPCWSTR)puVar1,cchSrc,param_5);
    }
    FUN_66217e12((int)puVar1);
    uVar2 = extraout_DL_01;
  }
LAB_66217f14:
  FUN_6620f208(uVar1 ^ (uint)&stack0xfffffffc,uVar2,(char)uVar1);
  return;
}



void __cdecl
FUN_66217f28(pthreadlocinfo *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,
            UINT param_6,int param_7)

{
  int s14 [2];
  int sc;
  char s8;
  
  FUN_6620e53b(s14,param_1);
  FUN_66217e30(s14,param_2,param_3,param_4,param_5,param_6,param_7);
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar1;
  wchar_t *pwVar1;
  int iVar1;
  int iStack16;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar1 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        if (*pwVar1 == L'\0') break;
        pwVar1 = pwVar1 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        iVar1 = (int)pwVar1 - (int)_Src;
        do {
          wVar1 = *_Src;
          *(wchar_t *)(iVar1 + (int)_Src) = wVar1;
          _Src = _Src + 1;
          if (wVar1 == L'\0') break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0) {
          return 0;
        }
        *_Dst = L'\0';
        piVar1 = __errno();
        iStack16 = 0x22;
        goto LAB_66217f8e;
      }
    }
    *_Dst = L'\0';
  }
  piVar1 = __errno();
  iStack16 = 0x16;
LAB_66217f8e:
  *piVar1 = iStack16;
  report_invalid_parameter();
  return iStack16;
}



// Library Function - Single Match
//  _wcscpy_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar1;
  int iVar1;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    if (_Src != (wchar_t *)0x0) {
      iVar1 = (int)_Dst - (int)_Src;
      do {
        wVar1 = *_Src;
        *(wchar_t *)(iVar1 + (int)_Src) = wVar1;
        _Src = _Src + 1;
        if (wVar1 == L'\0') break;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        return 0;
      }
      *_Dst = L'\0';
      piVar1 = __errno();
      iVar1 = 0x22;
      goto LAB_66217ff9;
    }
    *_Dst = L'\0';
  }
  piVar1 = __errno();
  iVar1 = 0x16;
LAB_66217ff9:
  *piVar1 = iVar1;
  report_invalid_parameter();
  return iVar1;
}



// Library Function - Single Match
//  _wcsnlen
// 
// Library: Visual Studio 2012 Release

size_t __cdecl _wcsnlen(wchar_t *_Src,size_t _MaxCount)

{
  uint uVar1;
  
  uVar1 = 0;
  if (_MaxCount != 0) {
    do {
      if (*_Src == L'\0') {
        return uVar1;
      }
      uVar1 = uVar1 + 1;
      _Src = _Src + 1;
    } while (uVar1 < _MaxCount);
  }
  return uVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  int __cdecl GetTableIndexFromLocaleName(wchar_t const *)
//  int __cdecl ATL::_AtlGetTableIndexFromLocaleName(wchar_t const *)
//  _GetTableIndexFromLocaleName
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl FID_conflict_GetTableIndexFromLocaleName(wchar_t *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar2 = 0xe3;
  do {
    iVar3 = (iVar2 + iVar4) / 2;
    iVar1 = __wcsnicmp(param_1,*(wchar_t **)((iVar3 * 8) + 0x662206d8),0x55);
    if (iVar1 == 0) {
      return *(undefined4 *)((iVar3 * 8) + 0x662206dc);
    }
    if (iVar1 < 0) {
      iVar2 = iVar3 + -1;
    }
    else {
      iVar4 = iVar3 + 1;
    }
  } while (iVar4 <= iVar2);
  return 0xffffffff;
}



// Library Function - Multiple Matches With Different Base Names
//  unsigned long __cdecl ATL::_AtlDownlevelLocaleNameToLCID(wchar_t const *)
//  ___acrt_DownlevelLocaleNameToLCID
//  ___crtDownlevelLocaleNameToLCID
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl FID_conflict__AtlDownlevelLocaleNameToLCID(wchar_t *param_1)

{
  uint uVar1;
  
  if (param_1 != (wchar_t *)0x0) {
    uVar1 = FID_conflict_GetTableIndexFromLocaleName(param_1);
    if ((-1 < (int)uVar1) && (uVar1 < 0xe4)) {
      return *(undefined4 *)(&DAT_6621ffb8 + (uVar1 * 8));
    }
  }
  return 0;
}



void __cdecl
FUN_662180c7(wchar_t *param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,int param_6)

{
  LCID Locale;
  
  if ((code *)(DAT_6624d390 ^ DAT_6624a120) != (code *)0x0) {
    (*(code *)(DAT_6624d390 ^ DAT_6624a120))(param_1,param_2,param_3,param_4,param_5,param_6,0,0,0);
    return;
  }
  Locale = FID_conflict__AtlDownlevelLocaleNameToLCID(param_1);
  LCMapStringW(Locale,param_2,param_3,param_4,param_5,param_6);
  return;
}



// Library Function - Single Match
//  __wcsnicmp
// 
// Library: Visual Studio 2019 Release

int __cdecl __wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  ushort uVar1;
  int iVar1;
  ushort uVar2;
  
  iVar1 = 0;
  if (_MaxCount != 0) {
    iVar1 = (int)_Str1 - (int)_Str2;
    do {
      uVar2 = *(ushort *)(iVar1 + (int)_Str2);
      if ((0x40 < uVar2) && (uVar2 < 0x5b)) {
        uVar2 = uVar2 + 0x20;
      }
      uVar1 = *_Str2;
      if ((0x40 < uVar1) && (uVar1 < 0x5b)) {
        uVar1 = uVar1 + 0x20;
      }
      _Str2 = (wchar_t *)((ushort *)_Str2 + 1);
      _MaxCount = _MaxCount - 1;
    } while (((_MaxCount != 0) && (uVar2 != 0)) && (uVar2 == uVar1));
    iVar1 = (uint)uVar2 - (uint)uVar1;
  }
  return iVar1;
}



// Library Function - Single Match
//  ___crtLCMapStringW
// 
// Library: Visual Studio 2012 Release

int __cdecl
___crtLCMapStringW(LPCWSTR _LocaleName,DWORD _DWMapFlag,LPCWSTR _LpSrcStr,int _CchSrc,
                  LPWSTR _LpDestStr,int _CchDest)

{
  int iVar1;
  
  if (0 < _CchSrc) {
    _CchSrc = _wcsnlen(_LpSrcStr,_CchSrc);
  }
  iVar1 = FUN_662180c7(_LocaleName,_DWMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest);
  return iVar1;
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 2012 Release

int __cdecl __set_error_mode(int _Mode)

{
  int iVar1;
  int *piVar1;
  
  iVar1 = DAT_6624c2e0;
  if (_Mode < 0) {
LAB_662181db:
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
    return -1;
  }
  if (_Mode < 3) {
    DAT_6624c2e0 = _Mode;
  }
  else if (_Mode != 3) goto LAB_662181db;
  return iVar1;
}



void __cdecl FUN_662181f0(LPCWSTR param_1,undefined4 param_2,uint param_3)

{
  bool bVar1;
  PVOID pvVar1;
  undefined3 extraout_var;
  HMODULE hModule;
  DWORD DVar1;
  FARPROC pFVar1;
  BOOL BVar1;
  code *pcVar1;
  code *pcVar2;
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined uVar1;
  int iVar2;
  undefined in_stack_ffffffd8;
  undefined s14 [8];
  byte sc;
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  iVar2 = 0;
  pvVar1 = EncodePointer((PVOID)0x0);
  bVar1 = FUN_6620ffa6();
  iVar1 = ((int)(int3)extraout_var << 8) + bVar1;
  if (Ptr_6624c2e4 == (PVOID)0x0) {
    hModule = LoadLibraryExW(u_USER32_DLL_66222774,(HANDLE)0x0,0x800);
    if (((hModule == (HMODULE)0x0) &&
        ((DVar1 = GetLastError(), uVar1 = extraout_DL, DVar1 != 0x57 ||
         (hModule = LoadLibraryExW(u_USER32_DLL_66222774,(HANDLE)0x0,0), uVar1 = extraout_DL_00,
         hModule == (HMODULE)0x0)))) ||
       (pFVar1 = GetProcAddress(hModule,s_MessageBoxW_6622278c), uVar1 = extraout_DL_01,
       pFVar1 == (FARPROC)0x0)) goto LAB_662183c5;
    Ptr_6624c2e4 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetActiveWindow_66222798);
    DAT_6624c2e8 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetLastActivePopup_662227a8);
    DAT_6624c2ec = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetUserObjectInformationW_662227bc);
    Ptr_6624c2f4 = EncodePointer(pFVar1);
    if (Ptr_6624c2f4 != (PVOID)0x0) {
      pFVar1 = GetProcAddress(hModule,s_GetProcessWindowStation_662227d8);
      DAT_6624c2f0 = EncodePointer(pFVar1);
    }
  }
  BVar1 = IsDebuggerPresent();
  if (BVar1 == 0) {
    if (iVar1 != 0) {
      DecodePointer(Ptr_6624c2e4);
      uVar1 = extraout_DL_04;
      goto LAB_662183c5;
    }
  }
  else {
    uVar1 = extraout_DL_02;
    if (param_1 != (LPCWSTR)0x0) {
      OutputDebugStringW(param_1);
      uVar1 = extraout_DL_03;
    }
    if (iVar1 != 0) goto LAB_662183c5;
  }
  if ((DAT_6624c2f0 == pvVar1) || (Ptr_6624c2f4 == pvVar1)) {
LAB_6621837b:
    if ((((DAT_6624c2e8 != pvVar1) &&
         (pcVar1 = (code *)DecodePointer(DAT_6624c2e8), pcVar1 != (code *)0x0)) &&
        (iVar2 = (*pcVar1)(), iVar2 != 0)) &&
       ((DAT_6624c2ec != pvVar1 &&
        (pcVar1 = (code *)DecodePointer(DAT_6624c2ec), pcVar1 != (code *)0x0)))) {
      iVar2 = (*pcVar1)(iVar2);
    }
  }
  else {
    pcVar1 = (code *)DecodePointer(DAT_6624c2f0);
    pcVar2 = (code *)DecodePointer(Ptr_6624c2f4);
    if (((pcVar1 == (code *)0x0) || (pcVar2 == (code *)0x0)) ||
       (((iVar1 = (*pcVar1)(), iVar1 != 0 &&
         (iVar1 = (*pcVar2)(iVar1,1,s14,0xc,&stack0xffffffd8), iVar1 != 0)) && ((sc & 1) != 0))))
    goto LAB_6621837b;
    param_3 = param_3 | 0x200000;
  }
  pcVar1 = (code *)DecodePointer(Ptr_6624c2e4);
  uVar1 = extraout_DL_05;
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)(iVar2,param_1,param_2,param_3);
    uVar1 = extraout_DL_06;
  }
LAB_662183c5:
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,uVar1,in_stack_ffffffd8);
  return;
}



int __cdecl FUN_662183d6(FILE *param_1)

{
  int iVar1;
  
  if (param_1 == (FILE *)0x0) {
    iVar1 = _flsall(0);
  }
  else {
    iVar1 = FUN_6621841c(param_1);
    if (iVar1 == 0) {
      if ((param_1->_flag & 0x4000U) == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = __fileno(param_1);
        iVar1 = FUN_6621acac(iVar1);
        iVar1 = -(uint)(iVar1 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



undefined4 __cdecl FUN_6621841c(FILE *param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar1;
  int iVar3;
  char *pcVar1;
  
  uVar1 = 0;
  if (((((byte)param_1->_flag & 3) == 2) && ((param_1->_flag & 0x108U) != 0)) &&
     (iVar3 = (int)param_1->_ptr - (int)param_1->_base, 0 < iVar3)) {
    pcVar1 = param_1->_base;
    iVar2 = iVar3;
    iVar1 = __fileno(param_1);
    iVar2 = FUN_66216934(iVar1,pcVar1,iVar2);
    if (iVar2 == iVar3) {
      if ((char)param_1->_flag < '\0') {
        param_1->_flag = param_1->_flag & 0xfffffffd;
      }
    }
    else {
      param_1->_flag = param_1->_flag | 0x20;
      uVar1 = 0xffffffff;
    }
  }
  param_1->_cnt = 0;
  param_1->_ptr = param_1->_base;
  return uVar1;
}



void FUN_66218480(void)

{
  _flsall(1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _flsall
// 
// Library: Visual Studio 2012 Release

int __cdecl _flsall(int param_1)

{
  void *_File;
  FILE *pFVar1;
  int iVar1;
  int _Index;
  int iVar2;
  int s28;
  
  iVar2 = 0;
  s28 = 0;
  __lock(1);
  for (_Index = 0; _Index < DAT_6624d304; _Index = _Index + 1) {
    _File = *(void **)(DAT_6624d300 + (_Index * 4));
    if ((_File != (void *)0x0) && ((*(byte *)((int)_File + 0xc) & 0x83) != 0)) {
      __lock_file2(_Index,_File);
      pFVar1 = *(FILE **)(DAT_6624d300 + (_Index * 4));
      if ((*(byte *)&pFVar1->_flag & 0x83) != 0) {
        if (param_1 == 1) {
          iVar1 = FUN_662183d6(pFVar1);
          if (iVar1 != -1) {
            iVar2 = iVar2 + 1;
          }
        }
        else if ((param_1 == 0) && ((*(byte *)&pFVar1->_flag & 2) != 0)) {
          iVar1 = FUN_662183d6(pFVar1);
          if (iVar1 == -1) {
            s28 = -1;
          }
        }
      }
      FUN_66218531();
    }
  }
  FUN_66218564();
  if (param_1 != 1) {
    iVar2 = s28;
  }
  return iVar2;
}



void FUN_66218531(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_6624d300 + (unaff_ESI * 4)));
  return;
}



void FUN_66218564(void)

{
  leavecritical(1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int FUN_6621856d(void)

{
  FILE *pFVar1;
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  __lock(1);
  for (iVar2 = 3; iVar2 < DAT_6624d304; iVar2 = iVar2 + 1) {
    pFVar1 = *(FILE **)(DAT_6624d300 + (iVar2 * 4));
    if (pFVar1 != (FILE *)0x0) {
      if ((*(byte *)&pFVar1->_flag & 0x83) != 0) {
        iVar1 = FUN_6621ae01(pFVar1);
        if (iVar1 != -1) {
          iVar3 = iVar3 + 1;
        }
      }
      if (0x13 < iVar2) {
        DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_6624d300 + (iVar2 * 4)) + 0x20));
        FID_conflict__free(*(void **)(DAT_6624d300 + (iVar2 * 4)));
        *(undefined4 *)(DAT_6624d300 + (iVar2 * 4)) = 0;
      }
    }
  }
  FUN_66218601();
  return iVar3;
}



void FUN_66218601(void)

{
  leavecritical(1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __87except
// 
// Library: Visual Studio 2019 Release

void __cdecl __87except(int param_1,int *param_2,ushort *param_3)

{
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar1;
  undefined4 uVar2;
  undefined in_stack_ffffff60;
  uint uStack156;
  undefined auStack152 [48];
  undefined8 uStack104;
  uint uStack88;
  uint uStack28;
  
  uStack28 = DAT_6624a120 ^ (uint)&stack0xffffffe8;
  uStack156 = (uint)*param_3;
  iVar1 = *param_2;
  if (iVar1 == 1) {
LAB_66218670:
    uVar2 = 8;
  }
  else if (iVar1 == 2) {
    uVar2 = 4;
  }
  else if (iVar1 == 3) {
    uVar2 = 0x11;
  }
  else if (iVar1 == 4) {
    uVar2 = 0x12;
  }
  else {
    if (iVar1 == 5) goto LAB_66218670;
    if (iVar1 == 7) {
      *param_2 = 1;
      goto LAB_662186d2;
    }
    if (iVar1 != 8) goto LAB_662186d2;
    uVar2 = 0x10;
  }
  iVar1 = __handle_exc(uVar2,param_2 + 6,uStack156);
  if (iVar1 == 0) {
    if (((param_1 == 0x10) || (param_1 == 0x16)) || (param_1 == 0x1d)) {
      uStack104 = *(undefined8 *)(param_2 + 4);
      uStack88 = (uStack88 & 0xffffffe3) | 3;
    }
    else {
      uStack88 = uStack88 & 0xfffffffe;
    }
    __raise_exc(auStack152,&uStack156,uVar2,param_1,param_2 + 2,param_2 + 6);
  }
LAB_662186d2:
  __ctrlfp(uStack156,0xffff);
  if (((*param_2 == 8) || (_DAT_6624ade0 != 0)) ||
     (iVar1 = returnzero(), uVar1 = extraout_DL, iVar1 == 0)) {
    __set_errno_from_matherr(*param_2);
    uVar1 = extraout_DL_00;
  }
  FUN_6620f208(uStack28 ^ (uint)&stack0xffffffe8,uVar1,in_stack_ffffff60);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_66218713(ushort *param_1,uint *param_2)

{
  ushort uVar1;
  ushort uVar2;
  byte bVar1;
  bool bVar2;
  bool bVar3;
  int iVar1;
  uint uVar3;
  byte bVar4;
  uint uVar4;
  uint *puVar1;
  uint uVar5;
  uint *puVar2;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar6;
  uint uVar7;
  int s38;
  uint s24;
  uint s14 [4];
  
  s14[3] = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  uVar1 = param_1[5];
  iVar3 = 0;
  uVar5 = (uVar1) & 0x7fff;
  uVar6 = *(uint *)(param_1 + 3);
  puVar2 = (uint *)(uVar5 - 0x3fff);
  s14[0] = uVar6;
  uVar7 = *(uint *)(param_1 + 1);
  s14[1] = uVar7;
  uVar2 = *param_1;
  s14[2] = (uint)uVar2 << 0x10;
  bVar1 = (byte)DAT_6624ae68;
  if (puVar2 == (uint *)0xffffc001) {
    iVar4 = 0;
    iVar3 = 0;
    do {
      if (s14[iVar3] != 0) {
        s14[0] = 0;
        s14[1] = 0;
        s14[2] = 0;
        goto LAB_66218788;
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < 3);
  }
  else {
    iVar1 = DAT_6624ae64 + -1;
    bVar3 = false;
    iVar4 = (int)(((DAT_6624ae64 >> 0x1f) & 0x1fU) + DAT_6624ae64) >> 5;
    bVar4 = 0x1f - ((byte)DAT_6624ae64 & 0x1f);
    if ((s14[iVar4] & (1 << (bVar4 & 0x1f))) != 0) {
      uVar3 = s14[iVar4] & ~(-1 << (bVar4 & 0x1f));
      iVar2 = iVar4;
      while (uVar3 == 0) {
        iVar2 = iVar2 + 1;
        if (2 < iVar2) goto LAB_66218888;
        uVar3 = s14[iVar2];
      }
      iVar2 = (int)(((iVar1 >> 0x1f) & 0x1fU) + iVar1) >> 5;
      bVar3 = false;
      uVar3 = 1 << ((0x1f - ((byte)iVar1 & 0x1f)) & 0x1f);
      uVar4 = uVar3 + s14[iVar2];
      bVar2 = false;
      if ((uVar4 < s14[iVar2]) || (uVar4 < uVar3)) {
        bVar2 = true;
        bVar3 = true;
      }
      s14[iVar2] = uVar4;
      while ((iVar2 = iVar2 + -1, -1 < iVar2 && (bVar2))) {
        bVar2 = false;
        bVar3 = false;
        uVar3 = s14[iVar2] + 1;
        if ((uVar3 < s14[iVar2]) || (uVar3 == 0)) {
          bVar2 = true;
          bVar3 = true;
        }
        s14[iVar2] = uVar3;
      }
    }
LAB_66218888:
    s14[iVar4] = s14[iVar4] & (-1 << (bVar4 & 0x1f));
    iVar4 = iVar4 + 1;
    if (iVar4 < 3) {
      puVar1 = s14 + iVar4;
      for (iVar2 = 3 - iVar4; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar1 = 0;
        puVar1 = puVar1 + 1;
      }
    }
    puVar1 = puVar2;
    if (bVar3) {
      puVar1 = (uint *)(uVar5 - 0x3ffe);
    }
    if ((int)puVar1 < ((int)DAT_6624ae60 - DAT_6624ae64)) {
      s14[0] = 0;
      s14[1] = 0;
      s14[2] = 0;
      puVar2 = DAT_6624ae60;
    }
    else {
      if ((int)DAT_6624ae60 < (int)puVar1) {
        if ((int)puVar1 < _DAT_6624ae5c) {
          s14[0] = s14[0] & 0x7fffffff;
          iVar4 = DAT_6624ae70 + (int)puVar1;
          iVar3 = (int)(DAT_6624ae68 + ((DAT_6624ae68 >> 0x1f) & 0x1fU)) >> 5;
          bVar4 = bVar1 & 0x1f;
          s24 = 0;
          iVar1 = 0;
          do {
            uVar6 = (s14[iVar1] >> bVar4) | s24;
            s24 = (s14[iVar1] & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
            s14[iVar1] = uVar6;
            iVar1 = iVar1 + 1;
          } while (iVar1 < 3);
          puVar2 = s14 + (2 - iVar3);
          iVar1 = 2;
          do {
            if (iVar1 < iVar3) {
              s14[iVar1] = 0;
            }
            else {
              s14[iVar1] = *puVar2;
            }
            puVar2 = puVar2 + -1;
            iVar1 = iVar1 + -1;
          } while (-1 < iVar1);
        }
        else {
          s14[1] = 0;
          s14[2] = 0;
          s14[0] = 0x80000000;
          iVar4 = (int)(DAT_6624ae68 + ((DAT_6624ae68 >> 0x1f) & 0x1fU)) >> 5;
          bVar4 = bVar1 & 0x1f;
          s24 = 0;
          do {
            uVar6 = (s14[iVar3] >> bVar4) | s24;
            s24 = (s14[iVar3] & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
            s14[iVar3] = uVar6;
            iVar3 = iVar3 + 1;
          } while (iVar3 < 3);
          puVar2 = s14 + (2 - iVar4);
          iVar3 = 2;
          do {
            if (iVar3 < iVar4) {
              s14[iVar3] = 0;
            }
            else {
              s14[iVar3] = *puVar2;
            }
            puVar2 = puVar2 + -1;
            iVar3 = iVar3 + -1;
          } while (-1 < iVar3);
          iVar4 = DAT_6624ae70 + _DAT_6624ae5c;
        }
        goto LAB_66218c39;
      }
      iVar2 = (int)DAT_6624ae60 - (int)puVar2;
      s14[0] = uVar6;
      iVar4 = (int)(iVar2 + ((iVar2 >> 0x1f) & 0x1fU)) >> 5;
      s14[1] = uVar7;
      s14[2] = (uint)uVar2 << 0x10;
      bVar4 = (byte)iVar2 & 0x1f;
      s24 = 0;
      do {
        uVar6 = (s14[iVar3] >> bVar4) | s24;
        s24 = (s14[iVar3] & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
        s14[iVar3] = uVar6;
        iVar3 = iVar3 + 1;
      } while (iVar3 < 3);
      puVar2 = s14 + (2 - iVar4);
      iVar3 = 2;
      do {
        if (iVar3 < iVar4) {
          s14[iVar3] = 0;
        }
        else {
          s14[iVar3] = *puVar2;
        }
        puVar2 = puVar2 + -1;
        iVar3 = iVar3 + -1;
      } while (-1 < iVar3);
      iVar3 = (int)(((DAT_6624ae64 >> 0x1f) & 0x1fU) + DAT_6624ae64) >> 5;
      bVar4 = 0x1f - ((byte)DAT_6624ae64 & 0x1f);
      if ((s14[iVar3] & (1 << (bVar4 & 0x1f))) != 0) {
        uVar6 = s14[iVar3] & ~(-1 << (bVar4 & 0x1f));
        iVar4 = iVar3;
        while (uVar6 == 0) {
          iVar4 = iVar4 + 1;
          if (2 < iVar4) goto LAB_66218a43;
          uVar6 = s14[iVar4];
        }
        iVar4 = (int)(((iVar1 >> 0x1f) & 0x1fU) + iVar1) >> 5;
        uVar6 = 1 << ((0x1f - ((byte)iVar1 & 0x1f)) & 0x1f);
        bVar3 = false;
        uVar7 = uVar6 + s14[iVar4];
        if ((uVar7 < s14[iVar4]) || (uVar7 < uVar6)) {
          bVar3 = true;
        }
        s14[iVar4] = uVar7;
        while ((iVar4 = iVar4 + -1, -1 < iVar4 && (bVar3))) {
          bVar3 = false;
          uVar6 = s14[iVar4] + 1;
          if ((uVar6 < s14[iVar4]) || (uVar6 == 0)) {
            bVar3 = true;
          }
          s14[iVar4] = uVar6;
        }
      }
LAB_66218a43:
      s14[iVar3] = s14[iVar3] & (-1 << (bVar4 & 0x1f));
      iVar3 = iVar3 + 1;
      if (iVar3 < 3) {
        puVar2 = s14 + iVar3;
        for (iVar4 = 3 - iVar3; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar2 = 0;
          puVar2 = puVar2 + 1;
        }
      }
      iVar4 = DAT_6624ae68 + 1;
      iVar3 = (int)(iVar4 + ((iVar4 >> 0x1f) & 0x1fU)) >> 5;
      bVar4 = (byte)iVar4 & 0x1f;
      s24 = 0;
      s38 = 0;
      do {
        uVar6 = s14[s38];
        s14[s38] = (uVar6 >> bVar4) | s24;
        s24 = (uVar6 & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
        s38 = s38 + 1;
      } while (s38 < 3);
      puVar2 = s14 + (2 - iVar3);
      iVar4 = 2;
      do {
        if (iVar4 < iVar3) {
          s14[iVar4] = 0;
        }
        else {
          s14[iVar4] = *puVar2;
        }
        puVar2 = puVar2 + -1;
        iVar4 = iVar4 + -1;
      } while (-1 < iVar4);
    }
LAB_66218788:
    iVar4 = 0;
  }
LAB_66218c39:
  uVar6 = (iVar4 << ((0x1f - bVar1) & 0x1f)) | (-(uint)((uVar1 & 0x8000) != 0) & 0x80000000) |
          s14[0];
  if (DAT_6624ae6c == 0x40) {
    param_2[1] = uVar6;
    *param_2 = s14[1];
  }
  else if (DAT_6624ae6c == 0x20) {
    *param_2 = uVar6;
  }
  FUN_6620f208(s14[3] ^ (uint)&stack0xfffffffc,(char)puVar2,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_66218c85(ushort *param_1,uint *param_2)

{
  ushort uVar1;
  ushort uVar2;
  byte bVar1;
  bool bVar2;
  bool bVar3;
  int iVar1;
  uint uVar3;
  byte bVar4;
  uint uVar4;
  uint *puVar1;
  uint uVar5;
  uint *puVar2;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar6;
  uint uVar7;
  int s38;
  uint s24;
  uint s14 [4];
  
  s14[3] = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  uVar1 = param_1[5];
  iVar3 = 0;
  uVar5 = (uVar1) & 0x7fff;
  uVar6 = *(uint *)(param_1 + 3);
  puVar2 = (uint *)(uVar5 - 0x3fff);
  s14[0] = uVar6;
  uVar7 = *(uint *)(param_1 + 1);
  s14[1] = uVar7;
  uVar2 = *param_1;
  s14[2] = (uint)uVar2 << 0x10;
  bVar1 = (byte)DAT_6624ae80;
  if (puVar2 == (uint *)0xffffc001) {
    iVar4 = 0;
    iVar3 = 0;
    do {
      if (s14[iVar3] != 0) {
        s14[0] = 0;
        s14[1] = 0;
        s14[2] = 0;
        goto LAB_66218cfa;
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < 3);
  }
  else {
    iVar1 = DAT_6624ae7c + -1;
    bVar3 = false;
    iVar4 = (int)(((DAT_6624ae7c >> 0x1f) & 0x1fU) + DAT_6624ae7c) >> 5;
    bVar4 = 0x1f - ((byte)DAT_6624ae7c & 0x1f);
    if ((s14[iVar4] & (1 << (bVar4 & 0x1f))) != 0) {
      uVar3 = s14[iVar4] & ~(-1 << (bVar4 & 0x1f));
      iVar2 = iVar4;
      while (uVar3 == 0) {
        iVar2 = iVar2 + 1;
        if (2 < iVar2) goto LAB_66218dfa;
        uVar3 = s14[iVar2];
      }
      iVar2 = (int)(((iVar1 >> 0x1f) & 0x1fU) + iVar1) >> 5;
      bVar3 = false;
      uVar3 = 1 << ((0x1f - ((byte)iVar1 & 0x1f)) & 0x1f);
      uVar4 = uVar3 + s14[iVar2];
      bVar2 = false;
      if ((uVar4 < s14[iVar2]) || (uVar4 < uVar3)) {
        bVar2 = true;
        bVar3 = true;
      }
      s14[iVar2] = uVar4;
      while ((iVar2 = iVar2 + -1, -1 < iVar2 && (bVar2))) {
        bVar2 = false;
        bVar3 = false;
        uVar3 = s14[iVar2] + 1;
        if ((uVar3 < s14[iVar2]) || (uVar3 == 0)) {
          bVar2 = true;
          bVar3 = true;
        }
        s14[iVar2] = uVar3;
      }
    }
LAB_66218dfa:
    s14[iVar4] = s14[iVar4] & (-1 << (bVar4 & 0x1f));
    iVar4 = iVar4 + 1;
    if (iVar4 < 3) {
      puVar1 = s14 + iVar4;
      for (iVar2 = 3 - iVar4; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar1 = 0;
        puVar1 = puVar1 + 1;
      }
    }
    puVar1 = puVar2;
    if (bVar3) {
      puVar1 = (uint *)(uVar5 - 0x3ffe);
    }
    if ((int)puVar1 < ((int)DAT_6624ae78 - DAT_6624ae7c)) {
      s14[0] = 0;
      s14[1] = 0;
      s14[2] = 0;
      puVar2 = DAT_6624ae78;
    }
    else {
      if ((int)DAT_6624ae78 < (int)puVar1) {
        if ((int)puVar1 < _DAT_6624ae74) {
          s14[0] = s14[0] & 0x7fffffff;
          iVar4 = DAT_6624ae88 + (int)puVar1;
          iVar3 = (int)(DAT_6624ae80 + ((DAT_6624ae80 >> 0x1f) & 0x1fU)) >> 5;
          bVar4 = bVar1 & 0x1f;
          s24 = 0;
          iVar1 = 0;
          do {
            uVar6 = (s14[iVar1] >> bVar4) | s24;
            s24 = (s14[iVar1] & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
            s14[iVar1] = uVar6;
            iVar1 = iVar1 + 1;
          } while (iVar1 < 3);
          puVar2 = s14 + (2 - iVar3);
          iVar1 = 2;
          do {
            if (iVar1 < iVar3) {
              s14[iVar1] = 0;
            }
            else {
              s14[iVar1] = *puVar2;
            }
            puVar2 = puVar2 + -1;
            iVar1 = iVar1 + -1;
          } while (-1 < iVar1);
        }
        else {
          s14[1] = 0;
          s14[2] = 0;
          s14[0] = 0x80000000;
          iVar4 = (int)(DAT_6624ae80 + ((DAT_6624ae80 >> 0x1f) & 0x1fU)) >> 5;
          bVar4 = bVar1 & 0x1f;
          s24 = 0;
          do {
            uVar6 = (s14[iVar3] >> bVar4) | s24;
            s24 = (s14[iVar3] & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
            s14[iVar3] = uVar6;
            iVar3 = iVar3 + 1;
          } while (iVar3 < 3);
          puVar2 = s14 + (2 - iVar4);
          iVar3 = 2;
          do {
            if (iVar3 < iVar4) {
              s14[iVar3] = 0;
            }
            else {
              s14[iVar3] = *puVar2;
            }
            puVar2 = puVar2 + -1;
            iVar3 = iVar3 + -1;
          } while (-1 < iVar3);
          iVar4 = DAT_6624ae88 + _DAT_6624ae74;
        }
        goto LAB_662191ab;
      }
      iVar2 = (int)DAT_6624ae78 - (int)puVar2;
      s14[0] = uVar6;
      iVar4 = (int)(iVar2 + ((iVar2 >> 0x1f) & 0x1fU)) >> 5;
      s14[1] = uVar7;
      s14[2] = (uint)uVar2 << 0x10;
      bVar4 = (byte)iVar2 & 0x1f;
      s24 = 0;
      do {
        uVar6 = (s14[iVar3] >> bVar4) | s24;
        s24 = (s14[iVar3] & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
        s14[iVar3] = uVar6;
        iVar3 = iVar3 + 1;
      } while (iVar3 < 3);
      puVar2 = s14 + (2 - iVar4);
      iVar3 = 2;
      do {
        if (iVar3 < iVar4) {
          s14[iVar3] = 0;
        }
        else {
          s14[iVar3] = *puVar2;
        }
        puVar2 = puVar2 + -1;
        iVar3 = iVar3 + -1;
      } while (-1 < iVar3);
      iVar3 = (int)(((DAT_6624ae7c >> 0x1f) & 0x1fU) + DAT_6624ae7c) >> 5;
      bVar4 = 0x1f - ((byte)DAT_6624ae7c & 0x1f);
      if ((s14[iVar3] & (1 << (bVar4 & 0x1f))) != 0) {
        uVar6 = s14[iVar3] & ~(-1 << (bVar4 & 0x1f));
        iVar4 = iVar3;
        while (uVar6 == 0) {
          iVar4 = iVar4 + 1;
          if (2 < iVar4) goto LAB_66218fb5;
          uVar6 = s14[iVar4];
        }
        iVar4 = (int)(((iVar1 >> 0x1f) & 0x1fU) + iVar1) >> 5;
        uVar6 = 1 << ((0x1f - ((byte)iVar1 & 0x1f)) & 0x1f);
        bVar3 = false;
        uVar7 = uVar6 + s14[iVar4];
        if ((uVar7 < s14[iVar4]) || (uVar7 < uVar6)) {
          bVar3 = true;
        }
        s14[iVar4] = uVar7;
        while ((iVar4 = iVar4 + -1, -1 < iVar4 && (bVar3))) {
          bVar3 = false;
          uVar6 = s14[iVar4] + 1;
          if ((uVar6 < s14[iVar4]) || (uVar6 == 0)) {
            bVar3 = true;
          }
          s14[iVar4] = uVar6;
        }
      }
LAB_66218fb5:
      s14[iVar3] = s14[iVar3] & (-1 << (bVar4 & 0x1f));
      iVar3 = iVar3 + 1;
      if (iVar3 < 3) {
        puVar2 = s14 + iVar3;
        for (iVar4 = 3 - iVar3; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar2 = 0;
          puVar2 = puVar2 + 1;
        }
      }
      iVar4 = DAT_6624ae80 + 1;
      iVar3 = (int)(iVar4 + ((iVar4 >> 0x1f) & 0x1fU)) >> 5;
      bVar4 = (byte)iVar4 & 0x1f;
      s24 = 0;
      s38 = 0;
      do {
        uVar6 = s14[s38];
        s14[s38] = (uVar6 >> bVar4) | s24;
        s24 = (uVar6 & ~(-1 << bVar4)) << ((0x20 - bVar4) & 0x1f);
        s38 = s38 + 1;
      } while (s38 < 3);
      puVar2 = s14 + (2 - iVar3);
      iVar4 = 2;
      do {
        if (iVar4 < iVar3) {
          s14[iVar4] = 0;
        }
        else {
          s14[iVar4] = *puVar2;
        }
        puVar2 = puVar2 + -1;
        iVar4 = iVar4 + -1;
      } while (-1 < iVar4);
    }
LAB_66218cfa:
    iVar4 = 0;
  }
LAB_662191ab:
  uVar6 = (iVar4 << ((0x1f - bVar1) & 0x1f)) | (-(uint)((uVar1 & 0x8000) != 0) & 0x80000000) |
          s14[0];
  if (DAT_6624ae84 == 0x40) {
    param_2[1] = uVar6;
    *param_2 = s14[1];
  }
  else if (DAT_6624ae84 == 0x20) {
    *param_2 = uVar6;
  }
  FUN_6620f208(s14[3] ^ (uint)&stack0xfffffffc,(char)puVar2,0);
  return;
}



void __cdecl
FUN_662191f7(ushort *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            int param_7,int *param_8)

{
  char cVar1;
  uint uVar1;
  bool bVar1;
  bool bVar2;
  bool bVar3;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  ushort uVar5;
  int iVar1;
  int *piVar1;
  uint uVar6;
  int iVar2;
  ushort uVar7;
  undefined **ppuVar1;
  undefined **ppuVar2;
  undefined4 extraout_EDX;
  char *pcVar1;
  undefined **ppuVar3;
  ushort *puVar1;
  undefined4 uVar8;
  ushort uVar9;
  int iVar3;
  uint uVar10;
  uint uVar11;
  ushort *puVar2;
  undefined4 uVar12;
  ushort uVar13;
  char *pcVar2;
  int iVar4;
  uint uVar14;
  int s70;
  uint s6c;
  undefined **s68;
  char s59;
  int s58;
  char *s54;
  uint s50;
  undefined2 s4c;
  undefined2 uStack74;
  undefined2 uStack72;
  undefined2 uStack70;
  undefined *s44;
  undefined4 s40;
  ushort uStack60;
  undefined2 uStack58;
  ushort uStack56;
  ushort uStack54;
  byte s30;
  undefined uStack47;
  ushort uStack46;
  ushort s2c [4];
  char s24 [23];
  char sd;
  uint s8;
  
  s8 = DAT_6624a120 ^ (uint)&stack0xfffffffc;
  s70 = 1;
  iVar1 = 0;
  uVar2 = 0;
  pcVar2 = s24;
  s50 = 0;
  bVar1 = false;
  bVar3 = false;
  bVar2 = false;
  s58 = 0;
  if (param_8 != (int *)0x0) {
    s54 = param_3;
    for (; (((cVar1 = *param_3, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\n')) ||
           (cVar1 == '\r')); param_3 = param_3 + 1) {
    }
LAB_66219277:
    pcVar1 = param_3;
    iVar3 = 0;
    s59 = *pcVar1;
    param_3 = pcVar1 + 1;
    switch(iVar1) {
    case 0:
      if (8 < (byte)(s59 - 0x31U)) {
        if (s59 == ***(char ***)(*param_8 + 0x84)) {
LAB_662192ab:
          iVar1 = 5;
        }
        else if (s59 == '+') {
          iVar1 = 2;
          uVar2 = 0;
        }
        else if (s59 == '-') {
          iVar1 = 2;
          uVar2 = 0x8000;
        }
        else {
          if (s59 != '0') goto LAB_66219553;
LAB_662192c5:
          iVar1 = 1;
        }
        goto LAB_66219277;
      }
      break;
    case 1:
      bVar1 = true;
      if (8 < (byte)(s59 - 0x31U)) {
        if (s59 == ***(char ***)(*param_8 + 0x84)) goto LAB_662192fd;
        if ((s59 != '+') && (s59 != '-')) {
          if (s59 != '0') goto LAB_66219310;
          goto LAB_662192c5;
        }
        goto LAB_66219331;
      }
      break;
    case 2:
      if (8 < (byte)(s59 - 0x31U)) {
        if (s59 == ***(char ***)(*param_8 + 0x84)) goto LAB_662192ab;
        pcVar1 = s54;
        if (s59 == '0') goto LAB_662192c5;
        goto LAB_66219557;
      }
      break;
    case 3:
      while (('/' < s59 && (s59 < ':'))) {
        if (s50 < 0x19) {
          s50 = s50 + 1;
          *pcVar2 = s59 + -0x30;
          pcVar2 = pcVar2 + 1;
        }
        else {
          s58 = s58 + 1;
        }
        s59 = *param_3;
        param_3 = param_3 + 1;
      }
      if (s59 != ***(char ***)(*param_8 + 0x84)) {
        if ((s59 == '+') || (s59 == '-')) goto LAB_66219331;
LAB_66219310:
        bVar1 = true;
        iVar3 = 0;
        if (('C' < s59) && ((s59 < 'F' || ((byte)(s59 + 0x9cU) < 2)))) goto LAB_6621932a;
        goto LAB_66219553;
      }
LAB_662192fd:
      bVar1 = true;
      iVar1 = 4;
      goto LAB_66219277;
    case 4:
      bVar1 = true;
      bVar3 = true;
      if (s50 == 0) {
        while (s59 == '0') {
          s58 = s58 + -1;
          s59 = *param_3;
          param_3 = param_3 + 1;
        }
      }
      while (('/' < s59 && (s59 < ':'))) {
        if (s50 < 0x19) {
          s50 = s50 + 1;
          *pcVar2 = s59 + -0x30;
          pcVar2 = pcVar2 + 1;
          s58 = s58 + -1;
        }
        s59 = *param_3;
        param_3 = param_3 + 1;
      }
      iVar3 = 0;
      if ((s59 == '+') || (s59 == '-')) {
LAB_66219331:
        bVar1 = true;
        iVar1 = 0xb;
        param_3 = param_3 + -1;
      }
      else {
        if ((s59 < 'D') || (('E' < s59 && (1 < (byte)(s59 + 0x9cU))))) {
          pcVar1 = param_3 + -1;
          goto LAB_66219557;
        }
LAB_6621932a:
        bVar1 = true;
        iVar1 = 6;
      }
      goto LAB_66219277;
    case 5:
      bVar3 = true;
      pcVar1 = s54;
      if ((byte)(s59 - 0x30U) < 10) {
        iVar1 = 4;
        goto LAB_66219296;
      }
      goto LAB_66219557;
    case 6:
      s54 = pcVar1 + -1;
      if ((byte)(s59 - 0x31U) < 9) goto LAB_66219474;
      if (s59 == '+') goto LAB_662194a5;
      if (s59 == '-') {
        iVar1 = 7;
        s70 = -1;
      }
      else {
LAB_6621948a:
        pcVar1 = s54;
        if (s59 != '0') goto LAB_66219557;
        iVar1 = 8;
      }
      goto LAB_66219277;
    case 7:
      if (8 < (byte)(s59 - 0x31U)) goto LAB_6621948a;
      goto LAB_66219474;
    case 8:
      bVar2 = true;
      while (s59 == '0') {
        s59 = *param_3;
        param_3 = param_3 + 1;
      }
      if ((byte)(s59 - 0x31U) < 9) {
LAB_66219474:
        iVar1 = 9;
        goto LAB_66219296;
      }
      goto LAB_66219553;
    case 9:
      iVar3 = 0;
      bVar2 = true;
      goto LAB_66219535;
    default:
      goto switchD_66219286_caseD_a;
    case 0xb:
      if (param_7 != 0) {
        s54 = pcVar1;
        if (s59 == '+') {
LAB_662194a5:
          iVar1 = 7;
        }
        else {
          if (s59 != '-') goto LAB_66219557;
          s70 = -1;
          iVar1 = 7;
        }
        goto LAB_66219277;
      }
      iVar1 = 10;
      param_3 = pcVar1;
switchD_66219286_caseD_a:
      pcVar1 = param_3;
      if (iVar1 != 10) goto LAB_66219277;
      goto LAB_66219557;
    }
    iVar1 = 3;
LAB_66219296:
    param_3 = param_3 + -1;
    goto LAB_66219277;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  report_invalid_parameter();
  uVar8 = extraout_EDX;
  goto LAB_6621995e;
LAB_66219535:
  if ((s59 < '0') || ('9' < s59)) goto LAB_6621954e;
  iVar3 = (s59) + -0x30 + (iVar3 * 10);
  if (iVar3 < 0x1451) {
    s59 = *param_3;
    param_3 = param_3 + 1;
    goto LAB_66219535;
  }
  iVar3 = 0x1451;
LAB_6621954e:
  while (('/' < s59 && (s59 < ':'))) {
    s59 = *param_3;
    param_3 = param_3 + 1;
  }
LAB_66219553:
  pcVar1 = param_3 + -1;
LAB_66219557:
  *param_2 = pcVar1;
  if (bVar1) {
    if (0x18 < s50) {
      if ('\x04' < sd) {
        sd = sd + '\x01';
      }
      pcVar2 = pcVar2 + -1;
      s58 = s58 + 1;
      s50 = 0x18;
    }
    if (s50 == 0) {
      uVar7 = 0;
      uVar9 = 0;
      uVar12 = 0;
      uVar8 = 0;
    }
    else {
      pcVar2 = pcVar2 + -1;
      cVar1 = *pcVar2;
      while (cVar1 == '\0') {
        s50 = s50 - 1;
        s58 = s58 + 1;
        pcVar2 = pcVar2 + -1;
        cVar1 = *pcVar2;
      }
      FUN_6621ae78(s24,s50,&s40);
      if (s70 < 0) {
        iVar3 = -iVar3;
      }
      uVar10 = iVar3 + s58;
      if (!bVar2) {
        uVar10 = uVar10 + param_5;
      }
      if (!bVar3) {
        uVar10 = uVar10 - param_6;
      }
      if (0x1450 < (int)uVar10) {
        uVar9 = 0x7fff;
        uVar12 = 0x80000000;
        goto LAB_66219944;
      }
      if ((int)uVar10 < -0x1450) {
        uVar7 = 0;
        uVar9 = 0;
        uVar12 = 0;
        uVar8 = 0;
      }
      else {
        ppuVar3 = &PTR_DAT_6624ae40;
        if (uVar10 != 0) {
          if ((int)uVar10 < 0) {
            uVar10 = -uVar10;
            ppuVar3 = (undefined **)0x6624afa0;
          }
          if (param_4 == 0) {
            s40._0_2_ = 0;
          }
LAB_662198fd:
          do {
            iVar1 = 0;
            if (uVar10 == 0) break;
            ppuVar3 = ppuVar3 + 0x15;
            uVar11 = (int)uVar10 >> 3;
            uVar6 = uVar10 & 7;
            uVar10 = uVar11;
            if (uVar6 != 0) {
              ppuVar1 = ppuVar3 + (uVar6 * 3);
              ppuVar2 = ppuVar1;
              if (0x7fff < *(ushort *)ppuVar1) {
                ppuVar2 = (undefined **)&s4c;
                s4c = SUB42(*ppuVar1,0);
                uStack74 = (undefined2)((uint)*ppuVar1 >> 0x10);
                uStack72 = SUB42(ppuVar1[1],0);
                uStack70 = (undefined2)((uint)ppuVar1[1] >> 0x10);
                s44 = ppuVar1[2];
                iVar3 = ((int)(short)uStack72 << 0x10) + uStack74 + -1;
                uStack74 = (undefined2)iVar3;
                uStack72 = (undefined2)((uint)iVar3 >> 0x10);
              }
              uVar7 = (*(ushort *)((int)ppuVar2 + 10) ^ uStack54) & 0x8000;
              s30 = 0;
              uStack47 = 0;
              uStack46 = 0;
              uVar5 = uStack54 & 0x7fff;
              s2c[0] = 0;
              uVar13 = *(ushort *)((int)ppuVar2 + 10) & 0x7fff;
              uVar9 = uVar13 + uVar5;
              s2c[1] = uStack46;
              s2c[2] = s2c[0];
              s2c[3] = uStack46;
              if (((uVar5 < 0x7fff) && (uVar13 < 0x7fff)) && (uVar9 < 0xbffe)) {
                uVar3 = s2c[0];
                uVar4 = uStack46;
                if (0x3fbf < uVar9) {
                  if (((uVar5 == 0) &&
                      (uVar9 = uVar9 + 1,
                      ((((int)(short)uStack54 << 0x10) + uStack56) & 0x7fffffffU) == 0)) &&
                     ((((int)(short)uStack58 << 0x10) + uStack60 == 0 &&
                      (((int)(short)s40._2_2_ << 0x10) + (ushort)s40 == 0)))) {
                    uStack54 = 0;
                    goto LAB_662198fd;
                  }
                  if (((uVar13 != 0) || (uVar9 = uVar9 + 1, ((uint)ppuVar2[2] & 0x7fffffff) != 0))
                     || ((ppuVar2[1] != (undefined *)0x0 ||
                         (uVar3 = s2c[0], uVar4 = uStack46, *ppuVar2 != (undefined *)0x0)))) {
                    puVar1 = s2c;
                    s6c = 5;
                    iVar3 = iVar1;
                    do {
                      if (0 < (int)s6c) {
                        puVar2 = (ushort *)((int)&s40 + (iVar3 * 2));
                        s68 = ppuVar2 + 2;
                        iVar4 = s6c;
                        do {
                          uVar6 = ((uint)*puVar2 * (uint)*(ushort *)s68) + *(int *)(puVar1 + -2);
                          if ((uVar6 < *(uint *)(puVar1 + -2)) ||
                             (iVar2 = iVar1, uVar6 < ((uint)*puVar2 * (uint)*(ushort *)s68))) {
                            iVar2 = 1;
                          }
                          *(uint *)(puVar1 + -2) = uVar6;
                          if (iVar2 != 0) {
                            *puVar1 = *puVar1 + 1;
                          }
                          s68 = (undefined **)((int)s68 + -2);
                          puVar2 = puVar2 + 1;
                          iVar4 = iVar4 + -1;
                        } while (0 < iVar4);
                      }
                      puVar1 = puVar1 + 1;
                      iVar3 = iVar3 + 1;
                      s6c = s6c + -1;
                    } while (0 < (int)s6c);
                    s54 = (char *)(((int)(short)s2c[3] << 0x10) + s2c[2]);
                    uVar9 = uVar9 + 0xc002;
                    uVar6 = ((int)(short)uStack46 << 0x10) + ((short)(char)uStack47 << 8) + s30;
                    if ((short)uVar9 < 1) {
LAB_662197cc:
                      uVar9 = uVar9 - 1;
                      if (-1 < (short)uVar9) goto LAB_66219835;
                      s6c = (uint)(ushort)-uVar9;
                      uVar9 = 0;
                      uVar11 = (uint)s54;
                      do {
                        if ((s30 & 1) != 0) {
                          iVar1 = iVar1 + 1;
                        }
                        uVar1 = ((int)(short)s2c[1] << 0x10) + s2c[0];
                        s2c[1] = (s2c[1] >> 1) | (ushort)((uVar11 << 0x1f) >> 0x10);
                        uVar14 = uVar6 >> 1;
                        s54 = (char *)(uVar11 >> 1);
                        uVar6 = uVar14 | (uVar1 << 0x1f);
                        s6c = s6c - 1;
                        s2c[2] = (ushort)s54;
                        s2c[3] = (ushort)(uVar11 >> 0x11);
                        s2c[0] = (ushort)(uVar1 >> 1);
                        s30 = (byte)uVar14;
                        uStack47 = (undefined)(uVar14 >> 8);
                        uStack46 = (ushort)(uVar6 >> 0x10);
                        uVar11 = (uint)s54;
                      } while (s6c != 0);
                      if (iVar1 == 0) goto LAB_66219835;
                      uVar5 = (ushort)uVar14 | 1;
                      s30 = (byte)uVar5;
                      uVar6 = uVar14 | 1;
                    }
                    else {
                      do {
                        if ((int)s54 < 0) break;
                        iVar3 = (((int)(short)s2c[1] << 0x10) + s2c[0]) * 2;
                        uVar5 = s2c[1] >> 0xf;
                        s2c[0] = (ushort)iVar3 | (ushort)(uVar6 >> 0x1f);
                        uVar6 = uVar6 * 2;
                        s2c[1] = (ushort)((uint)iVar3 >> 0x10);
                        uVar11 = (int)s54 * 2;
                        s30 = (byte)uVar6;
                        uStack47 = (undefined)(uVar6 >> 8);
                        uStack46 = (ushort)(uVar6 >> 0x10);
                        s54 = (char *)(uVar11 | (uVar5));
                        uVar9 = uVar9 - 1;
                        s2c[2] = (ushort)s54;
                        s2c[3] = (ushort)(uVar11 >> 0x10);
                      } while (0 < (short)uVar9);
                      if ((short)uVar9 < 1) goto LAB_662197cc;
LAB_66219835:
                      uVar5 = ((short)(char)uStack47 << 8) + s30;
                    }
                    if ((0x8000 < uVar5) || ((uVar6 & 0x1ffff) == 0x18000)) {
                      iVar1 = ((int)(short)s2c[0] << 0x10) + uStack46;
                      if (iVar1 == -1) {
                        iVar1 = ((int)(short)s2c[2] << 0x10) + s2c[1];
                        uStack46 = 0;
                        s2c[0] = 0;
                        if (iVar1 == -1) {
                          s2c[1] = 0;
                          s2c[2] = 0;
                          if (s2c[3] == 0xffff) {
                            s2c[3] = 0x8000;
                            uVar9 = uVar9 + 1;
                          }
                          else {
                            s2c[3] = s2c[3] + 1;
                          }
                        }
                        else {
                          iVar1 = iVar1 + 1;
                          s2c[1] = (ushort)iVar1;
                          s2c[2] = (ushort)((uint)iVar1 >> 0x10);
                        }
                        s54 = (char *)(((int)(short)s2c[3] << 0x10) + s2c[2]);
                      }
                      else {
                        iVar1 = iVar1 + 1;
                        uStack46 = (ushort)iVar1;
                        s2c[0] = (ushort)((uint)iVar1 >> 0x10);
                      }
                    }
                    if (uVar9 < 0x7fff) {
                      s40._0_2_ = uStack46;
                      s40._2_2_ = s2c[0];
                      uStack60 = s2c[1];
                      uStack58 = SUB42(s54,0);
                      uStack56 = (ushort)((uint)s54 >> 0x10);
                      uStack54 = uVar9 | uVar7;
                    }
                    else {
                      uStack60 = 0;
                      uStack58 = 0;
                      s40._0_2_ = 0;
                      s40._2_2_ = 0;
                      iVar1 = ((((uVar7 == 0)) - 1) & 0x80000000) + 0x7fff8000;
                      uStack56 = (ushort)iVar1;
                      uStack54 = (ushort)((uint)iVar1 >> 0x10);
                    }
                    goto LAB_662198fd;
                  }
                }
              }
              else {
                iVar1 = ((((uVar7 == 0)) - 1) & 0x80000000) + 0x7fff8000;
                uStack56 = (ushort)iVar1;
                uStack54 = (ushort)((uint)iVar1 >> 0x10);
                uVar3 = uStack56;
                uVar4 = uStack54;
              }
              uStack54 = uVar4;
              uStack56 = uVar3;
              uStack60 = 0;
              uStack58 = 0;
              s40._0_2_ = 0;
              s40._2_2_ = 0;
            }
          } while( true );
        }
        uVar8 = ((int)(short)uStack60 << 0x10) + s40._2_2_;
        uVar12 = ((int)(short)uStack56 << 0x10) + uStack58;
        uVar9 = uStack54;
        uVar7 = (ushort)s40;
      }
    }
  }
  else {
    uVar9 = 0;
    uVar12 = 0;
LAB_66219944:
    uVar7 = 0;
    uVar8 = 0;
  }
  param_1[5] = uVar9 | uVar2;
  *param_1 = uVar7;
  *(undefined4 *)(param_1 + 1) = uVar8;
  *(undefined4 *)(param_1 + 3) = uVar12;
LAB_6621995e:
  FUN_6620f208(s8 ^ (uint)&stack0xfffffffc,(char)uVar8,(char)param_1);
  return;
}


/*
Unable to decompile 'FUN_6621999f'
Cause: Exception while decompiling 6621999f: Decompiler process died

*/

/*
Unable to decompile '___hw_cw_sse2'
Cause: Exception while decompiling 6621a373: Decompiler process died

*/

/*
Unable to decompile 'FUN_6621a41c'
Cause: Exception while decompiling 6621a41c: Decompiler process died

*/

/*
Unable to decompile '__hw_cw'
Cause: Exception while decompiling 6621a71e: Decompiler process died

*/

/*
Unable to decompile 'FUN_6621a7c0'
Cause: Exception while decompiling 6621a7c0: Decompiler process died

*/


void FUN_6621a845(void)

{
  leavecritical(10);
  return;
}


/*
Unable to decompile 'FUN_6621a84e'
Cause: Exception while decompiling 6621a84e: Decompiler process died

*/

/*
Unable to decompile 'FUN_6621a8d4'
Cause: Exception while decompiling 6621a8d4: Decompiler process died

*/

/*
Unable to decompile 'FUN_6621a93b'
Cause: Exception while decompiling 6621a93b: Decompiler process died

*/


// Library Function - Single Match
//  __putwch_nolock
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  DWORD s8;
  
  if (DAT_6624b15c == (HANDLE)0xfffffffe) {
    ___dcrt_lowio_initialize_console_output();
  }
  if ((DAT_6624b15c == (HANDLE)0xffffffff) ||
     (BVar1 = WriteConsoleW(DAT_6624b15c,&_WCh,1,&s8,(LPVOID)0x0), BVar1 == 0)) {
    _WCh = 0xffff;
  }
  return _WCh;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio

void __alloca_probe(void)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined4 auStack4096 [1024];
  
  puVar2 = (undefined4 *)
           (((int)&stack0x00000000 - (int)in_EAX) & ~-(uint)(register0x00000010 < in_EAX));
  for (puVar1 = auStack4096; puVar2 < puVar1; puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



int __cdecl
FUN_6621a9db(int *param_1,LPSTR param_2,uint param_3,ushort param_4,pthreadlocinfo *param_5)

{
  LPSTR lpMultiByteStr;
  uint cbMultiByte;
  int *piVar1;
  int iVar1;
  DWORD DVar1;
  int iVar2;
  int s14 [2];
  int sc;
  char s8;
  
  cbMultiByte = param_3;
  lpMultiByteStr = param_2;
  if ((param_2 == (LPSTR)0x0) && (param_3 != 0)) {
    if (param_1 != (int *)0x0) {
      *param_1 = 0;
    }
    return 0;
  }
  if (param_1 != (int *)0x0) {
    *param_1 = -1;
  }
  if (0x7fffffff < param_3) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
    return 0x16;
  }
  FUN_6620e53b(s14,param_5);
  iVar2 = 0;
  if (*(int *)(s14[0] + 0xa8) == 0) {
    if (param_4 < 0x100) {
      if (lpMultiByteStr != (LPSTR)0x0) {
        if (cbMultiByte == 0) goto LAB_6621aaeb;
        *lpMultiByteStr = (CHAR)param_4;
      }
      if (param_1 != (int *)0x0) {
        *param_1 = 1;
      }
      goto LAB_6621aa6e;
    }
    if ((lpMultiByteStr != (LPSTR)0x0) && (cbMultiByte != 0)) {
      FUN_6620d410(lpMultiByteStr,0,cbMultiByte);
    }
  }
  else {
    param_2 = (LPSTR)0x0;
    iVar1 = WideCharToMultiByte(*(UINT *)(s14[0] + 4),0,(LPCWSTR)&param_4,1,lpMultiByteStr,
                                cbMultiByte,(LPCSTR)0x0,(LPBOOL)&param_2);
    if (iVar1 == 0) {
      DVar1 = GetLastError();
      if (DVar1 == 0x7a) {
        if ((lpMultiByteStr != (LPSTR)0x0) && (cbMultiByte != 0)) {
          FUN_6620d410(lpMultiByteStr,0,cbMultiByte);
        }
LAB_6621aaeb:
        piVar1 = __errno();
        iVar2 = 0x22;
        *piVar1 = 0x22;
        report_invalid_parameter();
        goto LAB_6621aa6e;
      }
    }
    else if (param_2 == (LPSTR)0x0) {
      if (param_1 != (int *)0x0) {
        *param_1 = iVar1;
      }
      goto LAB_6621aa6e;
    }
  }
  piVar1 = __errno();
  *piVar1 = 0x2a;
  piVar1 = __errno();
  iVar2 = *piVar1;
LAB_6621aa6e:
  if (s8 != '\0') {
    *(uint *)(sc + 0x70) = *(uint *)(sc + 0x70) & 0xfffffffd;
  }
  return iVar2;
}



void __cdecl FUN_6621aaff(int *param_1,LPSTR param_2,uint param_3,ushort param_4)

{
  FUN_6621a9db(param_1,param_2,param_3,param_4,(pthreadlocinfo *)0x0);
  return;
}


/*
Unable to decompile 'FUN_6621ab1a'
Cause: Exception while decompiling 6621ab1a: Decompiler process died

*/


// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio

uint __alloca_probe_16(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = (4 - in_EAX) & 0xf;
  return (in_EAX + uVar1) | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_8
// 
// Library: Visual Studio

uint __alloca_probe_8(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = (4 - in_EAX) & 7;
  return (in_EAX + uVar1) | -(uint)CARRY4(in_EAX,uVar1);
}


/*
Unable to decompile 'FUN_6621acac'
Cause: Exception while decompiling 6621acac: Decompiler process died

*/


void FUN_6621ad74(void)

{
  FUN_6621a93b();
  return;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2012 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  int *piVar1;
  int iVar1;
  int iVar2;
  
  iVar2 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
    iVar2 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar2 = FUN_6621841c(_File);
      __freebuf(_File);
      iVar1 = __fileno(_File);
      iVar1 = FUN_6621b08e(iVar1);
      if (iVar1 < 0) {
        iVar2 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        FID_conflict__free(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    _File->_flag = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int __cdecl FUN_6621ae01(FILE *param_1)

{
  int *piVar1;
  int iVar1;
  
  iVar1 = -1;
  if (param_1 == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    report_invalid_parameter();
  }
  else if ((*(byte *)&param_1->_flag & 0x40) == 0) {
    __lock_file(param_1);
    iVar1 = __fclose_nolock(param_1);
    FUN_6621ae70();
  }
  else {
    param_1->_flag = 0;
  }
  return iVar1;
}



void FUN_6621ae70(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



void __cdecl FUN_6621ae78(char *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  bool bVar1;
  uint *puVar1;
  short sVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar2;
  uint uVar6;
  uint uVar7;
  uint s10;
  uint sc;
  
  puVar1 = param_3;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    param_3 = (uint *)0x0;
    s10 = 0;
    sc = 0;
    do {
      uVar4 = *puVar1;
      uVar3 = puVar1[1];
      uVar6 = puVar1[2];
      uVar1 = s10 * 4;
      uVar5 = ((((int)param_3 * 2) | (s10 >> 0x1f)) * 2) | ((s10 * 2) >> 0x1f);
      *puVar1 = uVar1;
      uVar7 = (((sc * 2) | ((uint)param_3 >> 0x1f)) * 2) | ((uint)((int)param_3 * 2) >> 0x1f);
      puVar1[1] = uVar5;
      uVar2 = uVar4 + uVar1;
      puVar1[2] = uVar7;
      bVar1 = false;
      if ((uVar2 < uVar1) || (uVar2 < uVar4)) {
        bVar1 = true;
      }
      *puVar1 = uVar2;
      uVar4 = uVar5;
      if (bVar1) {
        bVar1 = false;
        uVar4 = uVar5 + 1;
        if ((uVar4 < uVar5) || (uVar4 == 0)) {
          bVar1 = true;
        }
        puVar1[1] = uVar4;
        if (bVar1) {
          uVar7 = uVar7 + 1;
          puVar1[2] = uVar7;
        }
      }
      bVar1 = false;
      uVar1 = uVar4 + uVar3;
      if ((uVar1 < uVar4) || (uVar1 < uVar3)) {
        bVar1 = true;
      }
      puVar1[1] = uVar1;
      if (bVar1) {
        uVar7 = uVar7 + 1;
        puVar1[2] = uVar7;
      }
      uVar4 = uVar2 * 2;
      puVar2 = (uint *)((uVar1 * 2) | (uVar2 >> 0x1f));
      sc = ((uVar7 + uVar6) * 2) | (uVar1 >> 0x1f);
      *puVar1 = uVar4;
      puVar1[1] = (uint)puVar2;
      puVar1[2] = sc;
      s10 = uVar4 + (int)*param_1;
      if ((s10 < uVar4) || (s10 < (uint)(int)*param_1)) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
      *puVar1 = s10;
      param_3 = puVar2;
      if (bVar1) {
        bVar1 = false;
        param_3 = (uint *)((int)puVar2 + 1);
        if ((param_3 < puVar2) || (param_3 == (uint *)0x0)) {
          bVar1 = true;
        }
        puVar1[1] = (uint)param_3;
        if (bVar1) {
          sc = sc + 1;
          puVar1[2] = sc;
        }
      }
      param_2 = param_2 + -1;
      puVar1[1] = (uint)param_3;
      param_1 = param_1 + 1;
      puVar1[2] = sc;
    } while (param_2 != 0);
  }
  sVar1 = 0x404e;
  if (puVar1[2] == 0) {
    uVar4 = puVar1[1];
    sVar1 = 0x404e;
    do {
      uVar3 = (uVar4 << 0x10) | (*puVar1 >> 0x10);
      uVar6 = uVar4 >> 0x10;
      sVar1 = sVar1 + -0x10;
      *puVar1 = *puVar1 << 0x10;
      uVar4 = uVar3;
    } while (uVar6 == 0);
    puVar1[1] = uVar3;
    puVar1[2] = uVar6;
  }
  uVar4 = puVar1[2];
  if ((uVar4 & 0x8000) == 0) {
    uVar3 = *puVar1;
    uVar6 = puVar1[1];
    do {
      uVar2 = (uVar6 * 2) | (uVar3 >> 0x1f);
      uVar1 = uVar4 * 2;
      uVar4 = uVar1 | (uVar6 >> 0x1f);
      sVar1 = sVar1 + -1;
      uVar3 = uVar3 * 2;
      uVar6 = uVar2;
    } while ((uVar1 & 0x8000) == 0);
    *puVar1 = uVar3;
    puVar1[1] = uVar2;
    puVar1[2] = uVar4;
  }
  *(short *)((int)puVar1 + 10) = sVar1;
  return;
}



// Library Function - Single Match
//  ___dcrt_lowio_initialize_console_output
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

void ___dcrt_lowio_initialize_console_output(void)

{
  DAT_6624b15c = CreateFileW(u_CONOUT__66222810,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                             (HANDLE)0x0);
  return;
}


/*
Unable to decompile 'FUN_6621b08e'
Cause: Exception while decompiling 6621b08e: Decompiler process died

*/


void FUN_6621b141(void)

{
  FUN_6621a93b();
  return;
}


/*
Unable to decompile 'FUN_6621b169'
Cause: Exception while decompiling 6621b169: Decompiler process died

*/


// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2012 Release

void __cdecl __freebuf(FILE *_File)

{
  if (((*(byte *)&_File->_flag & 0x83) != 0) && ((*(byte *)&_File->_flag & 8) != 0)) {
    FID_conflict__free(_File->_base);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x6621b234. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x6621b23a. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



void FUN_6621bb80(void)

{
  int **_Memory;
  undefined4 *in_FS_OFFSET;
  int *s18;
  undefined s11;
  undefined4 s10;
  undefined *puStack12;
  undefined4 s8;
  
  puStack12 = &LAB_6621ba48;
  s10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &s10;
  s8 = 1;
  FUN_6620a9a0(&DAT_6624b4d8,&s18,(int **)*DAT_6624b4d8,DAT_6624b4d8);
  _Memory = DAT_6624b4d8;
  s8 = 0xffffffff;
  FUN_6620b910(&s11);
  FUN_66207c50();
  FUN_6620b910(&s11);
  FUN_66207c50();
  FUN_6620b910(&s11);
  FUN_66207c50();
  FUN_6620b910(&s11);
  FID_conflict__free(_Memory);
  *in_FS_OFFSET = s10;
  return;
}


