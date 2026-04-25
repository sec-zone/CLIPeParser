# CLIPeParser

A command-line Portable Executable (PE) file parser written in C++.  
This is a personal **educational project** I built to learn and understand the internals of the PE file format — from DOS headers all the way down to import/export tables. If you find it useful or want to improve it, **pull requests are more than welcome** — I'd genuinely be happy to see others push updates and make this better.

---

## Features

- Parses both **PE32 (x86)** and **PE32+ (x64)** binaries
- **DOS Header** — magic signature, PE offset
- **File Header** — machine type, section count, timestamp (decoded to UTC), characteristics flags
- **Optional Header** — entry point, image base, stack/heap sizes, subsystem, DLL characteristics (ASLR, DEP, CFG, etc.)
- **Data Directories** — all 16 slots, non-zero entries displayed with RVA and size
- **Section Table** — virtual address, raw offset, sizes, decoded permission flags, and **Shannon entropy** per section (color-coded to hint at packed/encrypted content)
- **Import Table** — all DLLs with functions resolved both by name and by ordinal; correctly prefers ILT over IAT for bound images
- **Export Table** — module name, base ordinal, full function list with index, ordinal, and RVA
- **Colored CLI output** — ANSI colors via `ENABLE_VIRTUAL_TERMINAL_PROCESSING`, fully ASCII-safe for Windows CMD

---

## How to Compile (Visual Studio 2022)

**Requirements:**
- Visual Studio 2022 (any edition)
- Windows SDK (included with VS by default)
- C++17 or later

**Steps:**

1. Clone the repository:
   ```
   git clone https://github.com/sec-zone/CLIPeParser.git
   ```

2. Open Visual Studio 2022 and create a new project:
   - `Create a new project` → `Console App (C++)` → Next
   - Give it a name and choose a location → Create

3. Add the source files to the project:
   - In Solution Explorer, right-click `Source Files` → `Add` → `Existing Item`
   - Select `Main.cpp`, `Parser.cpp`
   - Right-click `Header Files` → `Add` → `Existing Item`
   - Select `Parser.h`, `UI.h`

4. Set the C++ standard to C++17:
   - Right-click the project → `Properties`
   - `Configuration Properties` → `C/C++` → `Language`
   - Set `C++ Language Standard` to `ISO C++17 (/std:c++17)`
   - Click `Apply` → `OK`

5. Build:
   - Press `Ctrl+Shift+B` or go to `Build` → `Build Solution`
   - The output binary will be in `x64\Debug\` or `x64\Release\` depending on your selected configuration

**Usage:**
```
peParse.exe <path-to-pe-file>
```

Example:
```
peParse.exe C:\Windows\System32\notepad.exe
```

---

## Project Structure

```
pe-parser/
|-- Main.cpp       - Entry point, output logic
|-- Parser.h       - Data structures and function declarations
|-- Parser.cpp     - All parsing and decode logic
|-- UI.h           - ANSI color macros and display helper functions
```

---

## Contributing

This project started as a way for me to learn how the PE format works at a low level.  
If you want to add something — more data directories, TLS table parsing, resource section parsing, relocation tables, anything — feel free to fork and open a pull request. I will be happy to review and merge improvements.

---

## References

- [Microsoft PE Format Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- *An In-Depth Look into the Win32 Portable Executable File Format* — Matt Pietrek (MSDN Magazine)
- [Corkami PE Internals](https://github.com/corkami/docs/blob/master/PE/PE.md)

---

## License

This project is released under the **MIT License** — do whatever you want with it.
