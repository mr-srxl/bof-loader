

***

# BOF Loader

A lightweight, standalone executable for testing and running Beacon Object Files (BOFs) locally. Perfect for developing and debugging BOFs without needing to deploy a full C2 infrastructure.

## Compilation

Compile the loader using Microsoft Visual C++ (MSVC) Developer Command Prompt:

```cmd
cl.exe /O2 bof_loader.cpp /Fe:bof_loader.exe
```

## Usage

```cmd
.\bof_loader.exe <bof_file.o> <entry_point> [arguments...]
```

### Argument Formats

BOFs require arguments to be packed in specific formats. This loader automatically handles the packing for you based on the prefixes below:

*   `i:1234` — Packs as a 4-byte Integer.
*   `s:Hello` — Packs as a null-terminated String.
*   `w:Hello` — Packs as a Wide String (UTF-16).
*   `f:C:\path\file.exe` — **File handler.** Reads the file from disk and packs its raw bytes into the buffer. Essential for BOFs that upload payloads (like `psexec`).
*   `1234` — Auto-inferred as an Integer (if numeric).
*   `Hello` — Auto-inferred as a String.
*   `"Hello World"` — Auto-inferred as a String with spaces (use double quotes).

## Examples

**1. Run a simple BOF with no arguments:**
```cmd
.\bof_loader.exe .\whoami.o go
```

**2. Run a BOF with auto-inferred arguments (IP and Port):**
```cmd
.\bof_loader.exe .\portscan.o go 192.168.1.10 445
```

**3. Run a BOF with explicit string arguments:**
```cmd
.\bof_loader.exe .\registry.o go s:HKLM\SOFTWARE\Microsoft\Windows
```

**4. Run a BOF that requires a file payload (e.g., PsExec lateral movement):**
*(Notice how `f:` is used to pass the executable bytes, while `svc.exe` is passed as a normal string for the filename)*
```cmd
.\bof_loader.exe .\psexec.o go 127.0.0.1 f:.\beacon.exe svc.exe ADMIN$ C:\Windows WindowsUpdateSvc "Windows Update"
```
