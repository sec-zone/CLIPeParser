#include "Parser.h"
#include <cmath>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>

bool parseDosHeader(std::ifstream* pPeFile, IMAGE_DOS_HEADER& dosHeader) {
    pPeFile->read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (!*pPeFile) return false;
    return dosHeader.e_magic == IMAGE_DOS_SIGNATURE;
}



bool parseNtHeader(std::ifstream* pPeFile, DWORD ntOffset,
    IMAGE_FILE_HEADER& fileHeader) {
    pPeFile->seekg(ntOffset, std::ios_base::beg);
    if (!*pPeFile) return false;

    DWORD signature = 0;
    pPeFile->read(reinterpret_cast<char*>(&signature), sizeof(DWORD));
    if (!*pPeFile || signature != IMAGE_NT_SIGNATURE)
        return false;

    pPeFile->read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    return static_cast<bool>(*pPeFile);
}


bool parseOptionalHeader32(std::ifstream* pPeFile, DWORD ntOffset,
    IMAGE_OPTIONAL_HEADER32& optionalHeader32) {
    DWORD offset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    pPeFile->seekg(offset, std::ios_base::beg);
    pPeFile->read(reinterpret_cast<char*>(&optionalHeader32),
        sizeof(IMAGE_OPTIONAL_HEADER32));
    return static_cast<bool>(*pPeFile);
}

bool parseOptionalHeader64(std::ifstream* pPeFile, DWORD ntOffset,
    IMAGE_OPTIONAL_HEADER64& optionalHeader64) {
    DWORD offset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    pPeFile->seekg(offset, std::ios_base::beg);
    pPeFile->read(reinterpret_cast<char*>(&optionalHeader64),
        sizeof(IMAGE_OPTIONAL_HEADER64));
    return static_cast<bool>(*pPeFile);
}



bool parseSectionHeaders(std::ifstream* pPeFile, DWORD ntOffset,
    WORD numSections,
    std::vector<IMAGE_SECTION_HEADER>& sections) {
 
    DWORD fileHeaderOffset = ntOffset + sizeof(DWORD);
    pPeFile->seekg(fileHeaderOffset, std::ios_base::beg);
    if (!*pPeFile) return false;

    IMAGE_FILE_HEADER fh;
    pPeFile->read(reinterpret_cast<char*>(&fh), sizeof(IMAGE_FILE_HEADER));
    if (!*pPeFile) return false;

    DWORD sectionOffset = fileHeaderOffset
        + sizeof(IMAGE_FILE_HEADER)
        + fh.SizeOfOptionalHeader;
    pPeFile->seekg(sectionOffset, std::ios_base::beg);
    if (!*pPeFile) return false;

    sections.resize(numSections);
    for (WORD i = 0; i < numSections; ++i) {
        pPeFile->read(reinterpret_cast<char*>(&sections[i]),
            sizeof(IMAGE_SECTION_HEADER));
        if (!*pPeFile) {
            sections.resize(i); // preserve successfully-read entries
            return false;
        }
    }
    return true;
}


IMAGE_OPTIONAL_HEADER64 convertOptionalHeader32To64(
    const IMAGE_OPTIONAL_HEADER32& h32) {

    IMAGE_OPTIONAL_HEADER64 h64 = {};

    // Fields that are bigger in PE32+
    h64.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; // 0x20B
    h64.ImageBase = static_cast<ULONGLONG>(h32.ImageBase);
    h64.SizeOfStackReserve = static_cast<ULONGLONG>(h32.SizeOfStackReserve);
    h64.SizeOfStackCommit = static_cast<ULONGLONG>(h32.SizeOfStackCommit);
    h64.SizeOfHeapReserve = static_cast<ULONGLONG>(h32.SizeOfHeapReserve);
    h64.SizeOfHeapCommit = static_cast<ULONGLONG>(h32.SizeOfHeapCommit);

    // Fields identical in both formats
    h64.MajorLinkerVersion = h32.MajorLinkerVersion;
    h64.MinorLinkerVersion = h32.MinorLinkerVersion;
    h64.SizeOfCode = h32.SizeOfCode;
    h64.SizeOfInitializedData = h32.SizeOfInitializedData;
    h64.SizeOfUninitializedData = h32.SizeOfUninitializedData;
    h64.AddressOfEntryPoint = h32.AddressOfEntryPoint;
    h64.BaseOfCode = h32.BaseOfCode;
    h64.SectionAlignment = h32.SectionAlignment;
    h64.FileAlignment = h32.FileAlignment;
    h64.MajorOperatingSystemVersion = h32.MajorOperatingSystemVersion;
    h64.MinorOperatingSystemVersion = h32.MinorOperatingSystemVersion;
    h64.MajorImageVersion = h32.MajorImageVersion;
    h64.MinorImageVersion = h32.MinorImageVersion;
    h64.MajorSubsystemVersion = h32.MajorSubsystemVersion;
    h64.MinorSubsystemVersion = h32.MinorSubsystemVersion;
    h64.Win32VersionValue = h32.Win32VersionValue;
    h64.SizeOfImage = h32.SizeOfImage;
    h64.SizeOfHeaders = h32.SizeOfHeaders;
    h64.CheckSum = h32.CheckSum;
    h64.Subsystem = h32.Subsystem;
    h64.DllCharacteristics = h32.DllCharacteristics;
    h64.LoaderFlags = h32.LoaderFlags;
    h64.NumberOfRvaAndSizes = h32.NumberOfRvaAndSizes;

    static_assert(sizeof(h32.DataDirectory) == sizeof(h64.DataDirectory),
        "DataDirectory size mismatch between PE32 and PE32+");
    std::memcpy(h64.DataDirectory, h32.DataDirectory,
        sizeof(h64.DataDirectory));

    return h64;
}


DWORD rvaToOffset(const std::vector<IMAGE_SECTION_HEADER>& sections, DWORD rva) {
    for (const auto& sec : sections) {
        DWORD start = sec.VirtualAddress;
        DWORD end = start + sec.Misc.VirtualSize;
        if (rva >= start && rva < end)
            return sec.PointerToRawData + (rva - start);
    }
    return 0; // caller must treat 0 as invalid
}


std::string readStringFromFile(std::ifstream* pPeFile, DWORD offset) {
    auto savedPos = pPeFile->tellg();
    pPeFile->seekg(offset, std::ios_base::beg);

    std::string result;
    char c;
    while (pPeFile->get(c) && c != '\0')
        result += c;

    pPeFile->seekg(savedPos);
    return result;
}


// File-local helper; intentionally NOT declared in the header
static IMAGE_IMPORT_DESCRIPTOR readImportDescriptor(std::ifstream* pPeFile,
    DWORD rawOffset) {
    IMAGE_IMPORT_DESCRIPTOR desc = {};
    pPeFile->seekg(rawOffset, std::ios_base::beg);
    pPeFile->read(reinterpret_cast<char*>(&desc), sizeof(desc));
    return desc;
}

std::vector<ImportsTableSt> parseImportTables(
    std::ifstream* pPeFile,
    const std::vector<IMAGE_SECTION_HEADER>& sections,
    DWORD rawOffsetOfImportDescriptor,
    bool is64Bit)
{
    std::vector<ImportsTableSt> result;

    while (true) {
        auto desc = readImportDescriptor(pPeFile, rawOffsetOfImportDescriptor);

        if (desc.Name == 0)
            return result;

        ImportsTableSt entry;
        entry.dllName = readStringFromFile(pPeFile,
            rvaToOffset(sections, desc.Name));

        // Prefer ILT (OriginalFirstThunk) — unaffected by binding.
        // Fall back to IAT (FirstThunk) for packed images that zero the ILT.
        DWORD iltRva = desc.OriginalFirstThunk
            ? desc.OriginalFirstThunk
            : desc.FirstThunk;

        DWORD thunkRaw = rvaToOffset(sections, iltRva);

        while (true) {
            pPeFile->seekg(thunkRaw, std::ios_base::beg);

            if (is64Bit) {
                ULONGLONG thunk = 0;
                pPeFile->read(reinterpret_cast<char*>(&thunk), sizeof(thunk));
                if (!*pPeFile || thunk == 0) break;

                if (thunk & IMAGE_ORDINAL_FLAG64) {
                    entry.ordinals.push_back(
                        static_cast<WORD>(thunk & 0xFFFF));
                }
                else {
                    // Thunk →{ WORD Hint; CHAR Name[]; }
                    DWORD nameRva = static_cast<DWORD>(thunk & 0x7FFFFFFF);
                    DWORD nameOff = rvaToOffset(sections, nameRva);
                    if (nameOff) {
                        std::string fn = readStringFromFile(pPeFile,
                            nameOff + sizeof(WORD));
                        if (!fn.empty())
                            entry.functions.push_back(std::move(fn));
                    }
                }
                thunkRaw += sizeof(ULONGLONG);
            }
            else {
                DWORD thunk = 0;
                pPeFile->read(reinterpret_cast<char*>(&thunk), sizeof(thunk));
                if (!*pPeFile || thunk == 0) break;

                if (thunk & IMAGE_ORDINAL_FLAG32) {
                    entry.ordinals.push_back(
                        static_cast<WORD>(thunk & 0xFFFF));
                }
                else {
                    DWORD nameOff = rvaToOffset(sections, thunk);
                    if (nameOff) {
                        std::string fn = readStringFromFile(pPeFile,
                            nameOff + sizeof(WORD));
                        if (!fn.empty())
                            entry.functions.push_back(std::move(fn));
                    }
                }
                thunkRaw += sizeof(DWORD);
            }
        }

        result.push_back(std::move(entry));
        rawOffsetOfImportDescriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
}


ExportTableSt parseExportTable(
    std::ifstream* pPeFile,
    DWORD exportDirRva,
    const std::vector<IMAGE_SECTION_HEADER>& sections) 
{
    ExportTableSt exportTable;

    DWORD rawExpDir = rvaToOffset(sections, exportDirRva);
    if (rawExpDir == 0)
        return exportTable;

    IMAGE_EXPORT_DIRECTORY expDir{};
    pPeFile->seekg(rawExpDir, std::ios_base::beg);
    pPeFile->read(reinterpret_cast<char*>(&expDir), sizeof(expDir));

    exportTable.moduleName = readStringFromFile(pPeFile,
        rvaToOffset(sections, expDir.Name));
    exportTable.baseOrdinal = expDir.Base;
    exportTable.numberOfFunctions = expDir.NumberOfFunctions;
    exportTable.numberOfNames = expDir.NumberOfNames;

    if (expDir.NumberOfFunctions == 0)
        return exportTable;

    // Load all three parallel arrays
    std::vector<DWORD> funcRVAs(expDir.NumberOfFunctions);
    std::vector<DWORD> nameRVAs(expDir.NumberOfNames);
    std::vector<WORD>  nameOrdinals(expDir.NumberOfNames);

    pPeFile->seekg(rvaToOffset(sections, expDir.AddressOfFunctions),
        std::ios_base::beg);
    pPeFile->read(reinterpret_cast<char*>(funcRVAs.data()),
        expDir.NumberOfFunctions * sizeof(DWORD));

    pPeFile->seekg(rvaToOffset(sections, expDir.AddressOfNames),
        std::ios_base::beg);
    pPeFile->read(reinterpret_cast<char*>(nameRVAs.data()),
        expDir.NumberOfNames * sizeof(DWORD));

    pPeFile->seekg(rvaToOffset(sections, expDir.AddressOfNameOrdinals),
        std::ios_base::beg);
    pPeFile->read(reinterpret_cast<char*>(nameOrdinals.data()),
        expDir.NumberOfNames * sizeof(WORD));

    for (DWORD i = 0; i < expDir.NumberOfNames; ++i) {
        ExportFunSt fn{};
        fn.name = readStringFromFile(pPeFile,
            rvaToOffset(sections, nameRVAs[i]));
        fn.funcIndex = nameOrdinals[i];
        fn.realOrdinal = expDir.Base + nameOrdinals[i];
        fn.funcRva = funcRVAs[nameOrdinals[i]]; // index into EAT
        exportTable.exportFuns.push_back(fn);
    }

    return exportTable;
}


std::string decodeMachine(WORD machine) {
    switch (machine) {
    case 0x0000: return "Unknown";
    case 0x014C: return "x86 (i386)";
    case 0x0200: return "Intel Itanium (IA-64)";
    case 0x8664: return "x64 (AMD64)";
    case 0xAA64: return "ARM64 (AArch64)";
    case 0x01C0: return "ARM little-endian";
    case 0x01C4: return "ARM Thumb-2 (ARMNT)";
    case 0x5032: return "RISC-V 32-bit";
    case 0x5064: return "RISC-V 64-bit";
    case 0x0EBC: return "EFI Byte Code";
    default: {
        std::ostringstream o;
        o << "Unknown (0x" << std::uppercase << std::hex << machine << ")";
        return o.str();
    }
    }
}

std::string decodeSubsystem(WORD sub) {
    switch (sub) {
    case  1: return "Native (no subsystem)";
    case  2: return "Windows GUI";
    case  3: return "Windows Console (CUI)";
    case  5: return "OS/2 Console";
    case  7: return "POSIX Console";
    case  9: return "Windows CE GUI";
    case 10: return "EFI Application";
    case 11: return "EFI Boot Service Driver";
    case 12: return "EFI Runtime Driver";
    case 13: return "EFI ROM Image";
    case 14: return "XBOX";
    case 16: return "Windows Boot Application";
    default:
        return "Unknown (" + std::to_string(sub) + ")";
    }
}

std::string decodeTimestamp(DWORD ts) {
    // The linker stores seconds since 1970-01-01 00:00:00 UTC
    // NOTE: A timestamp of 0 or 0xFFFFFFFF usually means the linker
    //       stripped or randomised it (reproducible builds / LTCG).
    if (ts == 0)          return "0 (stripped / not set)";
    if (ts == 0xFFFFFFFF) return "0xFFFFFFFF (reproducible build / randomised)";

    time_t t = static_cast<time_t>(ts);
    struct tm tmInfo = {};
#ifdef _WIN32
    gmtime_s(&tmInfo, &t);
#else
    gmtime_r(&t, &tmInfo);
#endif
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tmInfo);
    return std::string(buf);
}

std::vector<std::string> decodeFileCharacteristics(WORD c) {
    std::vector<std::string> v;
    if (c & 0x0001) v.push_back("RELOCS_STRIPPED");
    if (c & 0x0002) v.push_back("EXECUTABLE_IMAGE");
    if (c & 0x0004) v.push_back("LINE_NUMS_STRIPPED");
    if (c & 0x0008) v.push_back("LOCAL_SYMS_STRIPPED");
    if (c & 0x0010) v.push_back("AGGRESSIVE_WS_TRIM");
    if (c & 0x0020) v.push_back("LARGE_ADDRESS_AWARE");
    if (c & 0x0080) v.push_back("BYTES_REVERSED_LO");
    if (c & 0x0100) v.push_back("32BIT_MACHINE");
    if (c & 0x0200) v.push_back("DEBUG_STRIPPED");
    if (c & 0x0400) v.push_back("REMOVABLE_RUN_FROM_SWAP");
    if (c & 0x0800) v.push_back("NET_RUN_FROM_SWAP");
    if (c & 0x1000) v.push_back("SYSTEM");
    if (c & 0x2000) v.push_back("DLL");
    if (c & 0x4000) v.push_back("UP_SYSTEM_ONLY");
    if (c & 0x8000) v.push_back("BYTES_REVERSED_HI");
    return v;
}

std::vector<std::string> decodeDllCharacteristics(WORD c) {
    std::vector<std::string> v;
    if (c & 0x0020) v.push_back("HIGH_ENTROPY_VA");
    if (c & 0x0040) v.push_back("DYNAMIC_BASE (ASLR)");
    if (c & 0x0080) v.push_back("FORCE_INTEGRITY");
    if (c & 0x0100) v.push_back("NX_COMPAT (DEP)");
    if (c & 0x0200) v.push_back("NO_ISOLATION");
    if (c & 0x0400) v.push_back("NO_SEH");
    if (c & 0x0800) v.push_back("NO_BIND");
    if (c & 0x1000) v.push_back("APPCONTAINER");
    if (c & 0x2000) v.push_back("WDM_DRIVER");
    if (c & 0x4000) v.push_back("GUARD_CF (CFG)");
    if (c & 0x8000) v.push_back("TERMINAL_SERVER_AWARE");
    return v;
}

std::vector<std::string> decodeSectionCharacteristics(DWORD c) {
    std::vector<std::string> v;
    if (c & 0x00000020) v.push_back("CNT_CODE");
    if (c & 0x00000040) v.push_back("CNT_INIT_DATA");
    if (c & 0x00000080) v.push_back("CNT_UNINIT_DATA");
    if (c & 0x00000200) v.push_back("LNK_INFO");
    if (c & 0x00000800) v.push_back("LNK_REMOVE");
    if (c & 0x00001000) v.push_back("LNK_COMDAT");
    if (c & 0x00008000) v.push_back("GPREL");
    if (c & 0x01000000) v.push_back("LNK_NRELOC_OVFL");
    if (c & 0x02000000) v.push_back("MEM_DISCARDABLE");
    if (c & 0x04000000) v.push_back("MEM_NOT_CACHED");
    if (c & 0x08000000) v.push_back("MEM_NOT_PAGED");
    if (c & 0x10000000) v.push_back("MEM_SHARED");
    if (c & 0x20000000) v.push_back("MEM_EXECUTE");
    if (c & 0x40000000) v.push_back("MEM_READ");
    if (c & 0x80000000) v.push_back("MEM_WRITE");
    return v;
}

const char* dataDirectoryName(int i) {
    static const char* names[] = {
        "Export Table",            // 0
        "Import Table",            // 1
        "Resource Table",          // 2
        "Exception Table",         // 3
        "Certificate Table",       // 4
        "Base Relocation Table",   // 5
        "Debug",                   // 6
        "Architecture",            // 7
        "Global Ptr",              // 8
        "TLS Table",               // 9
        "Load Config Table",       // 10
        "Bound Import",            // 11
        "Import Address Table",    // 12
        "Delay Import Descriptor", // 13
        "CLR Runtime Header",      // 14
        "Reserved"                 // 15
    };
    if (i >= 0 && i < 16) return names[i];
    return "Unknown";
}


double calculateSectionEntropy(std::ifstream* pPeFile,
    DWORD rawOffset,
    DWORD rawSize) {
    if (rawSize == 0) return -1.0;

    auto savedPos = pPeFile->tellg();
    pPeFile->seekg(rawOffset, std::ios_base::beg);

    std::vector<unsigned char> buf(rawSize);
    pPeFile->read(reinterpret_cast<char*>(buf.data()), rawSize);
    DWORD bytesRead = static_cast<DWORD>(pPeFile->gcount());

    pPeFile->seekg(savedPos);
    pPeFile->clear(); 

    if (bytesRead == 0) return -1.0;

    DWORD freq[256] = {};
    for (DWORD i = 0; i < bytesRead; ++i)
        freq[buf[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / bytesRead;
        entropy -= p * std::log2(p);
    }
    return entropy;
}


std::string sectionName(const IMAGE_SECTION_HEADER& sec) {
    return std::string(reinterpret_cast<const char*>(sec.Name),
        strnlen(reinterpret_cast<const char*>(sec.Name), 8));
}