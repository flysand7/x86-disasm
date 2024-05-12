package cli

import "core:fmt"
import "core:os"
import "pe"

HELP_TEMPLATE ::
`x86-disasm: An x86 disassembler.
Usage:
  %s <file> [options...]
Options:
  -help
      Print a help message
  -verbose
      Print verbose messages
  -format:<format>
      Specify the format of the input file. Options:
        auto - Auto-detect a format (the default).
        elf  - ELF file (Linux relocatable files, shared objects, executables)
        pe   - PE file (Windows executables and shared objects)
        coff - COFF file (Windows relocatable files)
        raw  - Binary file containing assembly.
  -cpu:<bits>
      Specify the CPU Mode. Options:
        auto - Auto-detect using the file format (default).
        16   - A 16-bit CPU mode.
        32   - A 32-bit CPU mode.
        64   - A 64-bit CPU mode.
`

File_Format :: enum {
    Auto,
    ELF,
    PE,
    COFF,
    Raw,
}

CPU_Mode :: enum {
    Auto,
    M16,
    M32,
    M64,
}

verbose_print := false

main :: proc() {
    mb_input_path := Maybe(string) {}
    args, options := parse_args(os.args[1:])
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
    cpu_mode := cast(CPU_Mode) CPU_Mode.Auto
    if "cpu" in options {
        cpu_opt := options["cpu"]
        if cpu_str, ok := cpu_opt.(string); ok {
            switch cpu_str {
            case "auto":
            case "16": cpu_mode = .M16
            case "32": cpu_mode = .M32
            case "64": cpu_mode = .M64
            }
        } else {
            fmt.eprintfln("Error: Unexpected key=value pair for CPU option. Use -cpu:<bits> syntax")
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
        case pe.is_pe(file_bytes):   input_file_format = .PE
        case pe.is_coff(file_bytes): input_file_format = .COFF
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
    // Detecting the CPU type.
    if cpu_mode == .Auto {
        if verbose_print {
            fmt.printfln("Detecting CPU mode from file type %v", input_file_format)
        }
        if input_file_format == .Raw {
            fmt.eprintfln("Error: CPU Mode detection doesn't work for files of type 'raw'. Please specify the CPU mode explicitly using -cpu option")
            os.exit(1)
        }
        switch input_file_format {
            case .COFF: cpu_mode = cpu_mode_from_bitness(pe.coff_machine_bitness(file_bytes))
            case .PE:   cpu_mode = cpu_mode_from_bitness(pe.pe_machine_bitness(file_bytes))
            case .ELF:  unreachable()
            case .Raw:  unreachable()
            case .Auto: unreachable()
        }
        if verbose_print {
            fmt.printfln("Detected CPU mode: %v", cpu_mode)
        }
    }
}

cpu_mode_from_bitness :: proc(bits: int) -> CPU_Mode {
    switch bits {
        case 16: return .M16
        case 32: return .M32
        case 64: return .M64
        case: unreachable()
    }
}
