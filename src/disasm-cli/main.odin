package cli

import "core:fmt"
import "core:os"

import "disasm:disasm"
import "disasm:arg"
import "disasm:format"

HELP_TEMPLATE ::
`x86-disasm: An x86 disassembler.

Usage:
    %s <file> [options...]

Options:
-help
    Print a help message
-verbose
    Print verbose messages
-flavor:<flavor>
    Specify the assembly output flavor. Options:
    * intel (default) - Print x86 disasm's intel-style assembly.
    * att - Print AT&T style assembly, like in gas.
    * nasm - Print assembly that tries to match ndisasm output as much as possible.
-format:<format>
    Specify the format of the input file. Options:
    * auto (default) - Auto-detect a format (the default).
    * elf  - ELF file (Linux relocatable files, shared objects, executables)
    * pe   - PE file (Windows executables and shared objects)
    * coff - COFF file (Windows relocatable files)
    * raw  - Binary file containing assembly.
-cpu:<bits>
    Specify the CPU Mode. Options:
    * auto (default) - Auto-detect using the file format (default).
    * 16   - A 16-bit CPU mode.
    * 32   - A 32-bit CPU mode.
    * 64   - A 64-bit CPU mode.
-section:<name>
    Disassemble a specific section. If this option is not specified, then
    .text (the default code section) is disassembled.
-function:<name>
    Disassemble a specific function. If this option is not specified, then
    the the entire section is disassembled. This option can not be used
    together with -section option.
`

File_Format :: enum {
    Auto,
    ELF,
    PE,
    COFF,
    Raw,
}

Disasm_Scope :: enum {
    File,
    Section,
    Symbol,
}

verbose_print := false

main :: proc() {
    mb_input_path := Maybe(string) {}
    args, options := arg.parse(os.args[1:])
    if len(args) == 0 {
        fmt.eprintfln(HELP_TEMPLATE, os.args[0])
        os.exit(2)
    }
    if "help" in options {
        fmt.printfln(HELP_TEMPLATE, os.args[0])
        os.exit(0)
    }
    if "verbose" in options {
        verbose_print = true
    }
    input_file_format := cast(File_Format) File_Format(.Auto)
    if "format" in options {
        format_opt := options["format"]
        if format_str, ok := format_opt.(string); ok {
            switch format_str {
            case "auto":
            case "elf":  input_file_format = .ELF
            case "pe":   input_file_format = .PE
            case "coff": input_file_format = .COFF
            case "raw":  input_file_format = .Raw
            case:
                fmt.eprintfln("Unknown file format: %s", format_str)
            }
        } else {
            fmt.eprintfln("Error: Unexpected key=value pair for -format option. Use -format:<format> syntax")
            os.exit(2)
        }
    }
    cpu_machine := format.Machine.Unknown
    if "cpu" in options {
        cpu_opt := options["cpu"]
        if cpu_str, ok := cpu_opt.(string); ok {
            switch cpu_str {
            case "auto":
            case "16": cpu_machine = .X86_16
            case "32": cpu_machine = .X86_32
            case "64": cpu_machine = .X86_64
            }
        } else {
            fmt.eprintfln("Error: Unexpected key=value pair for -cpu option. Use -cpu:<bits> syntax")
            os.exit(2)
        }
    }
    mb_section := Maybe(string) {}
    if "section" in options {
        section_opt := options["section"]
        if section_str, ok := section_opt.(string); ok {
            mb_section = section_str
        } else {
            fmt.eprintfln("Error: Unexpected key=value pair for -section option. Use -section:<name> syntax")
            os.exit(2)
        }
    }
    mb_function := Maybe(string) {}
    if "function" in options {
        function_opt := options["function"]
        if function_str, ok := function_opt.(string); ok {
            mb_function = function_str
        } else {
            fmt.eprintfln("Error: Unexpected key=value pair for -function option. Use -function:<name> syntax")
            os.exit(2)
        }
    }
    // Reading the input file.
    input_path := args[0]
    if verbose_print {
        fmt.printfln("Trying to open the file '%s'", input_path)
    }
    file_bytes, file_bytes_ok := os.read_entire_file(input_path, allocator = context.allocator)
    if !file_bytes_ok {
        if os.is_dir(input_path) {
            fmt.eprintfln("Error: cannot disassemble directory: '%s'", input_path)
            os.exit(1)
        } else {
            fmt.eprintfln("Error: File does not exist: '%s'", input_path)
            os.exit(1)
        }    
    }
    // Detecting the file type.
    if input_file_format == .Auto {
        if verbose_print {
            fmt.printfln("Detecting file type for '%s'", input_path)
        }
        switch {
        case format.is_pe(file_bytes):   input_file_format = .PE
        case format.is_coff(file_bytes): input_file_format = .COFF
        case: input_file_format = .Raw
        }
        if verbose_print {
            fmt.printfln("Detected file type: '%v'", input_file_format)
        }
    }
    if input_file_format == .ELF {
        fmt.eprintfln("ELF files are not supported yet.")
        os.exit(1)
    }
    // Parse the input file format.
    file: format.File
    switch input_file_format {
        case .Raw:
        case .COFF:
            ok: bool
            file, ok = format.coff_parse(file_bytes)
            if !ok {
                fmt.eprintfln("Error: Bad COFF file: '%s'", input_path)
                os.exit(1)
            }
            cpu_machine = file.machine
        case .PE:
            ok: bool
            file, ok = format.pe_parse(file_bytes)
            if !ok {
                fmt.eprintfln("Error: Bad PE file: '%s'", input_path)
                os.exit(1)
            }
            cpu_machine = file.machine
        case .ELF:  unreachable()
        case .Auto: unreachable()
    }
    // Detecting the CPU type.
    if cpu_machine == .Unknown {
        if verbose_print {
            fmt.printfln("Detecting CPU mode from file type %v", input_file_format)
        }
        if input_file_format == .Raw {
            fmt.eprintfln("Error: CPU Mode detection doesn't work for files of type 'raw'. Please specify the CPU mode explicitly using -cpu option")
            os.exit(1)
        }
        if verbose_print {
            fmt.printfln("Detected CPU mode: %v", cpu_machine)
        }
    }
    // Figuring out the what to disassemble.
    scope := cast(Disasm_Scope) Disasm_Scope.File
    section, section_ok := mb_section.?
    function, function_ok := mb_function.?
    if section_ok && input_file_format == .Raw {
        fmt.eprintfln("Error: Cannot use -section option with -format:raw")
        os.exit(2)
    }
    if !section_ok && input_file_format != .Raw {
        section = ".text"
        scope = .Section
    }
    if function_ok {
        if input_file_format == .Raw {
            fmt.eprintfln("Error: Cannot use -function option with -format:raw")
            os.exit(2)
        }
        if section_ok {
            fmt.eprintfln("Error: Cannot use -function option together with -section")
            os.exit(2)
        }
        scope = .Symbol
    }
    disasm_bytes: []u8 = ---
    disasm_vaddr: u64
    switch scope {
    case .File:
        disasm_bytes = file_bytes
    case .Section:
        for file_section in file.sections {
            if file_section.name == section {
                disasm_bytes = file_section.bytes
                disasm_vaddr = file_section.vaddr
            }
        }
    case .Symbol:
        for file_symbol in file.symbol {
            if file_symbol.name == function {
                disasm_bytes = file_symbol.bytes
                disasm_vaddr = file_symbol.vaddr
            }
        }
    }
    if verbose_print {
        fmt.printfln("Disassembly start: %08x (%d bytes)", disasm_vaddr, len(disasm_bytes))
    }
    print_flavor := disasm.Syntax_Variant.Intel
    if "flavor" in options {
        if str, ok := options["flavor"].(string); ok {
            switch str {
            case "intel": print_flavor = .Intel
            case "att": print_flavor = .ATT
            case "nasm": print_flavor = .Nasm
            }
        } else {
            fmt.eprintfln("The -flavor option expects a string")
            os.exit(2)
        }
    }
    bytes := disasm_bytes
    vaddr := disasm_vaddr
    stdout := os.stream_from_handle(os.stdout)
    for inst in disasm.disasm_one(bytes) {
        fmt.printf("%012x | ", vaddr)
        for i in 0 ..<8 {
            if i < inst.size {
                fmt.printf("%02x", bytes[u64(i)])
            } else {
                fmt.printf("  ")
            }
        }
        fmt.printf(" | ")
        err := disasm.print_one(stdout, vaddr, inst, print_flavor)
        if err != nil {
            os.exit(1)
        }
        fmt.println()
        bytes = bytes[inst.size:]
        vaddr += u64(inst.size)
    }
}
