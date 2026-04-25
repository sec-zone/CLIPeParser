#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>
#include <winnt.h>


typedef struct ImportsTableStruct {
    std::string          dllName;
    std::vector<std::string> functions;
    std::vector<DWORD>   ordinals;
} ImportsTableSt, * pImportsTable;

typedef struct ExportFunctionStruct {
    std::string name;
    DWORD       funcIndex;
    DWORD       realOrdinal;
    DWORD       funcRva;
} ExportFunSt, * pExportFun;

typedef struct ExportsTableStruct {
    std::string           moduleName;
    DWORD                 baseOrdinal;
    DWORD                 numberOfFunctions;
    DWORD                 numberOfNames;
    std::vector<ExportFunSt> exportFuns;
} ExportTableSt, * pExportTable;


bool parseDosHeader(std::ifstream* pPeFile, IMAGE_DOS_HEADER& dosHeader);

bool parseNtHeader(std::ifstream* pPeFile, DWORD ntOffset,
    IMAGE_FILE_HEADER& fileHeader);

bool parseOptionalHeader32(std::ifstream* pPeFile, DWORD ntOffset,
    IMAGE_OPTIONAL_HEADER32& optionalHeader32);

bool parseOptionalHeader64(std::ifstream* pPeFile, DWORD ntOffset,
    IMAGE_OPTIONAL_HEADER64& optionalHeader64);

bool parseSectionHeaders(std::ifstream* pPeFile, DWORD ntOffset,
    WORD numSections,
    std::vector<IMAGE_SECTION_HEADER>& sections);

std::vector<ImportsTableSt> parseImportTables(
    std::ifstream* pPeFile,
    const std::vector<IMAGE_SECTION_HEADER>& sections,
    DWORD rawOffsetOfImportDescriptor,
    bool is64Bit);

ExportTableSt parseExportTable(
    std::ifstream* pPeFile,
    DWORD exportDirRva,
    const std::vector<IMAGE_SECTION_HEADER>& sections);


IMAGE_OPTIONAL_HEADER64 convertOptionalHeader32To64(
    const IMAGE_OPTIONAL_HEADER32& h32);

DWORD rvaToOffset(const std::vector<IMAGE_SECTION_HEADER>& sections, DWORD rva);

std::string readStringFromFile(std::ifstream* pPeFile, DWORD offset);


// Returns a human-readable machine type str
std::string decodeMachine(WORD machine);

// Returns the subsystem name (e.g. "Windows Console (CUI)")
std::string decodeSubsystem(WORD subsystem);

// Converts the raw Unix timestamp stored in IMAGE_FILE_HEADER to a UTC string
std::string decodeTimestamp(DWORD timestamp);

// Decodes IMAGE_FILE_HEADER.Characteristics bit flags into individual names
std::vector<std::string> decodeFileCharacteristics(WORD chars);

// Decodes IMAGE_OPTIONAL_HEADER.DllCharacteristics bit flags 
std::vector<std::string> decodeDllCharacteristics(WORD chars);

// Decodes IMAGE_SECTION_HEADER.Characteristics bit flags 
std::vector<std::string> decodeSectionCharacteristics(DWORD chars);

// Returns a short name for each of the 16 data-directory slots
const char* dataDirectoryName(int index);


double calculateSectionEntropy(std::ifstream* pPeFile,
    DWORD rawOffset,
    DWORD rawSize);

// Returns a safe, null-terminated section name (up to 8 chars)
std::string sectionName(const IMAGE_SECTION_HEADER& sec);