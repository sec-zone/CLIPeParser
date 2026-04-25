#include <iostream>
#include <fstream>
#include <string>
#include "UI.h"
#include "Parser.h"


static void printFlagList(const std::vector<std::string>& flags) {
    if (flags.empty()) {
        std::cout << "  " GRY "|" RST "       " GRY "(none)" RST "\n";
        return;
    }
    for (const auto& f : flags)
        std::cout << "  " GRY "|" RST "       " CYN "- " RST << f << "\n";
}

int main(int argc, char** argv) {
    initConsole();
    printBanner();

    if (argc < 2) {
        std::cout << SYM_ERR "Usage: peParse.exe <filepath>\n";
        return -1;
    }

    std::cout << SYM_OK "Target: " WHT << argv[1] << RST "\n";

    std::ifstream peFile(argv[1], std::ios::binary);
    if (!peFile.is_open()) {
        std::cout << SYM_ERR "Cannot open file.\n";
        return -1;
    }

    bool is64Bit = true;


    IMAGE_DOS_HEADER dosHeader;
    if (!parseDosHeader(&peFile, dosHeader)) {
        std::cout << SYM_ERR "Not a valid PE file (missing MZ signature).\n";
        return -1;
    }

    printSectionTitle("DOS Header");
    printField("Magic", "0x" + std::string("5A4D") + "  (MZ)");
    printField("PE Header Offset", fmtHex(dosHeader.e_lfanew));

 
    IMAGE_FILE_HEADER fileHeader;
    if (!parseNtHeader(&peFile, dosHeader.e_lfanew, fileHeader)) {
        std::cout << SYM_ERR "NT signature not found — not a valid PE format.\n";
        return -1;
    }

    printSectionTitle("File Header");
    printField("Machine", decodeMachine(fileHeader.Machine));
    printField("Number of Sections",
        std::to_string(fileHeader.NumberOfSections));
    printField("Timestamp", decodeTimestamp(fileHeader.TimeDateStamp)
        + GRY "  (" + fmtHex(fileHeader.TimeDateStamp) + ")" RST);
    printField("Symbol Table Ptr", fmtHex(fileHeader.PointerToSymbolTable));
    printField("Number of Symbols", std::to_string(fileHeader.NumberOfSymbols));
    printField("Opt. Header Size", std::to_string(fileHeader.SizeOfOptionalHeader) + " bytes");
    printField("Characteristics", fmtHex(fileHeader.Characteristics, 4));
    printFlagList(decodeFileCharacteristics(fileHeader.Characteristics));

 
    IMAGE_OPTIONAL_HEADER64 optHdr;

    if (fileHeader.Machine == 0x14C) {
        is64Bit = false;
        IMAGE_OPTIONAL_HEADER32 optHdr32;
        parseOptionalHeader32(&peFile, dosHeader.e_lfanew, optHdr32);
        optHdr = convertOptionalHeader32To64(optHdr32);
    }
    else {
        parseOptionalHeader64(&peFile, dosHeader.e_lfanew, optHdr);
    }

    printSectionTitle("Optional Header");
    printField("Magic",
        is64Bit ? "0x020B  (PE32+ / 64-bit)"
        : "0x010B  (PE32  / 32-bit)");
    printField("Linker Version",
        std::to_string(optHdr.MajorLinkerVersion) + "."
        + std::to_string(optHdr.MinorLinkerVersion));
    printField("Entry Point", fmtHex(optHdr.AddressOfEntryPoint));
    printField("Image Base", fmtHex64(optHdr.ImageBase));
    printField("Base of Code", fmtHex(optHdr.BaseOfCode));
    printField("Section Alignment", fmtHex(optHdr.SectionAlignment));
    printField("File Alignment", fmtHex(optHdr.FileAlignment));
    printField("OS Version",
        std::to_string(optHdr.MajorOperatingSystemVersion) + "."
        + std::to_string(optHdr.MinorOperatingSystemVersion));
    printField("Image Version",
        std::to_string(optHdr.MajorImageVersion) + "."
        + std::to_string(optHdr.MinorImageVersion));
    printField("Subsystem", decodeSubsystem(optHdr.Subsystem));
    printField("Size of Image", std::to_string(optHdr.SizeOfImage) + " bytes");
    printField("Size of Headers", std::to_string(optHdr.SizeOfHeaders) + " bytes");
    printField("Size of Code", std::to_string(optHdr.SizeOfCode) + " bytes");
    printField("Checksum", fmtHex(optHdr.CheckSum));
    printField("Stack Reserve", fmtHex64(optHdr.SizeOfStackReserve));
    printField("Stack Commit", fmtHex64(optHdr.SizeOfStackCommit));
    printField("Heap Reserve", fmtHex64(optHdr.SizeOfHeapReserve));
    printField("Heap Commit", fmtHex64(optHdr.SizeOfHeapCommit));
    printField("DLL Characteristics",
        fmtHex(optHdr.DllCharacteristics, 4));
    printFlagList(decodeDllCharacteristics(optHdr.DllCharacteristics));

 
    printSectionTitle("Data Directories (non-zero)");
    bool anyDir = false;
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        const auto& dir = optHdr.DataDirectory[i];
        if (dir.VirtualAddress == 0 && dir.Size == 0) continue;
        anyDir = true;
        std::string info = fmtHex(dir.VirtualAddress)
            + "  size: " + std::to_string(dir.Size);
        printField(std::string("[") + std::to_string(i) + "] "
            + dataDirectoryName(i), info);
    }
    if (!anyDir)
        std::cout << "  " GRY "|" RST "  " GRY "(all empty)" RST "\n";


    std::vector<IMAGE_SECTION_HEADER> sections;
    parseSectionHeaders(&peFile, dosHeader.e_lfanew,
        fileHeader.NumberOfSections, sections);

    std::string sectionTitleStr = "Sections  ("
        + std::to_string(fileHeader.NumberOfSections) + ")";
    printSectionTitle(sectionTitleStr);

    // Table header
    std::cout << "  " GRY "|" RST "  "
        << BOLD
        << std::left << std::setw(12) << "Name"
        << std::left << std::setw(14) << "Virt. Addr"
        << std::left << std::setw(14) << "Raw Offset"
        << std::left << std::setw(12) << "Virt Size"
        << std::left << std::setw(12) << "Raw Size"
        << std::left << std::setw(28) << "Entropy"
        << "Characteristics"
        << RST "\n";

    std::cout << "  " GRY "|  "
        << std::string(10, '-') << "  "
        << std::string(12, '-') << "  "
        << std::string(12, '-') << "  "
        << std::string(10, '-') << "  "
        << std::string(10, '-') << "  "
        << std::string(10, '-') << "  "
        << std::string(30, '-')
        << RST "\n";

    for (const auto& sec : sections) {
        double entropy = calculateSectionEntropy(
            &peFile, sec.PointerToRawData, sec.SizeOfRawData);

        auto flags = decodeSectionCharacteristics(sec.Characteristics);
        std::string flagStr = joinFlags(flags, " | ");

        std::cout << "  " GRY "|" RST "  "
            << WHT << std::left << std::setw(12) << sectionName(sec) << RST
            << std::left << std::setw(14) << fmtHex(sec.VirtualAddress)
            << std::left << std::setw(14) << fmtHex(sec.PointerToRawData)
            << std::left << std::setw(12) << sec.Misc.VirtualSize
            << std::left << std::setw(12) << sec.SizeOfRawData;

        if (entropy < 0.0)
            std::cout << std::left << std::setw(28)
            << (std::string(GRY) + "N/A (no raw data)" + RST);
        else
            std::cout << colorEntropy(entropy);

        std::cout << "  " << flagStr << "\n";
    }


    DWORD importDirRva = optHdr.DataDirectory[1].VirtualAddress;

    if (importDirRva == 0) {
        printSectionTitle("Imports");
        std::cout << "  " GRY "|" RST "  " GRY "(no import directory)" RST "\n";
    }
    else {
        DWORD importRawOff = rvaToOffset(sections, importDirRva);
        auto imports = parseImportTables(&peFile, sections,
            importRawOff, is64Bit);

        std::string importTitle = "Imports  ("
            + std::to_string(imports.size()) + " DLLs)";
        printSectionTitle(importTitle);

        for (const auto& dll : imports) {
            printRule();
            std::cout << "  " GRY "|" RST "  "
                << MAG BOLD << dll.dllName << RST
                << GRY "  [" << dll.functions.size()
                << " named, " << dll.ordinals.size()
                << " by ordinal]" RST "\n";

            for (const auto& fn : dll.functions)
                std::cout << "  " GRY "|" RST "       "
                << GRN "- " RST << fn << "\n";

            for (const auto& ord : dll.ordinals)
                std::cout << "  " GRY "|" RST "       "
                << YEL "- " RST "#" << std::dec << ord
                << GRY "  (by ordinal)" RST "\n";
        }
    }

    DWORD exportDirRva = optHdr.DataDirectory[0].VirtualAddress;

    if (exportDirRva == 0) {
        printSectionTitle("Exports");
        std::cout << "  " GRY "|" RST "  " GRY "(no export directory)" RST "\n";
    }
    else {
        auto expTable = parseExportTable(&peFile, exportDirRva, sections);

        std::string exportTitle = "Exports  ("
            + std::to_string(expTable.numberOfFunctions)
            + " functions, " + std::to_string(expTable.numberOfNames)
            + " named)";
        printSectionTitle(exportTitle);

        printField("Module Name", expTable.moduleName);
        printField("Base Ordinal", std::to_string(expTable.baseOrdinal));
        printRule();

        std::cout << "  " GRY "|" RST "  "
            << BOLD
            << std::left << std::setw(50) << "Name"
            << std::left << std::setw(10) << "Index"
            << std::left << std::setw(10) << "Ordinal"
            << "RVA"
            << RST "\n";

        for (const auto& fn : expTable.exportFuns) {
            std::cout << "  " GRY "|" RST "  "
                << WHT << std::left << std::setw(50) << fn.name << RST
                << std::left << std::setw(10) << fn.funcIndex
                << std::left << std::setw(10) << fmtHex(fn.realOrdinal, 4)
                << fmtHex(fn.funcRva) << "\n";
        }
    }

    peFile.close();

    std::cout << "\n" SYM_OK "Done.\n\n";
    std::cout << GRY "  Press Enter to exit..." RST;
    std::cin.get();
    return 0;
}