#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <windows.h>


inline void initConsole() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode))
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    // Keep default code page — no UTF-8, no box-drawing chars needed
}


#define RST     "\033[0m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define RED     "\033[91m"
#define GRN     "\033[92m"
#define YEL     "\033[93m"
#define BLU     "\033[94m"
#define MAG     "\033[95m"
#define CYN     "\033[96m"
#define WHT     "\033[97m"
#define GRY     "\033[90m"


#define SYM_OK    GRN  "[+]" RST " "
#define SYM_ERR   RED  "[-]" RST " "
#define SYM_INFO  CYN  "[*]" RST " "
#define SYM_WARN  YEL  "[!]" RST " "

inline void printBanner() {
    std::cout
        << BOLD CYN
        "\n"
        "  ########  ########     ########     ###    ########   ######  ######## ########  \n"
        "  ##     ## ##          ##     ##   ## ##   ##     ## ##    ## ##       ##     ## \n"
        "  ##     ## ##          ##     ##  ##   ##  ##     ## ##       ##       ##     ## \n"
        "  ########  ######      ########  ##     ## ########   ######  ######   ########  \n"
        "  ##        ##          ##        ######### ##   ##         ## ##       ##   ##   \n"
        "  ##        ##          ##        ##     ## ##    ##  ##    ## ##       ##    ##  \n"
        "  ##        ########    ##        ##     ## ##     ##  ######  ######## ##     ## \n"
        RST GRY
        "  Portable Executable Parser  |  v1.0\n"
        RST "\n";
}


inline void printSectionTitle(const std::string& title) {
    std::cout << "\n" BOLD BLU "  +--- " RST BOLD << title << RST "\n";
}


inline void printField(const std::string& key, const std::string& value) {
    std::cout
        << "  |  "
        << YEL << std::left << std::setw(30) << key << RST
        << WHT << value << RST << "\n";
}


inline void printSubField(const std::string& label, const std::string& value) {
    std::cout
        << "  |       "
        << GRY << std::left << std::setw(26) << label << RST
        << value << "\n";
}


inline void printItem(const std::string& text, int depth = 1) {
    std::string pad(depth * 4 + 2, ' ');
    std::cout << pad << "- " << text << "\n";
}


inline void printRule() {
    std::cout << "  " GRY "|\n" RST;
}


inline std::string fmtHex(DWORD val, int width = 8) {
    std::ostringstream o;
    o << "0x" << std::uppercase << std::hex
        << std::setw(width) << std::setfill('0') << val;
    return o.str();
}


inline std::string fmtHex64(ULONGLONG val) {
    std::ostringstream o;
    o << "0x" << std::uppercase << std::hex
        << std::setw(16) << std::setfill('0') << val;
    return o.str();
}


//   > 7.2  → RED    (likely packed / encrypted)
//   > 6.5  → YELLOW (possibly compressed)
//   < 1.0  → GRAY   (sparse / zero-filled)
//   else   → GREEN  (normal)
inline std::string colorEntropy(double e) {
    std::ostringstream o;
    o << std::fixed << std::setprecision(3) << e;
    std::string s = o.str();
    if (e > 7.2) return std::string(RED  BOLD) + s + " [packed/encrypted?]" + RST;
    if (e > 6.5) return std::string(YEL) + s + " [possibly compressed]" + RST;
    if (e < 1.0) return std::string(GRY) + s + " [sparse/zeroed]" + RST;
    return         std::string(GRN) + s + RST;
}


inline std::string joinFlags(const std::vector<std::string>& flags,
    const std::string& sep = " | ") {
    if (flags.empty()) return GRY "(none)" RST;
    std::string result;
    for (size_t i = 0; i < flags.size(); ++i) {
        if (i) result += sep;
        result += flags[i];
    }
    return result;
}