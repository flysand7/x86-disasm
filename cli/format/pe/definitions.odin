package pe

PE_SIGNATURE_OFFSET :: 0x3c
PE_SIGNATURE :: u32le(0x0000_4550) // "PE\x00\x00"
PE_SIGNATURE_STRING :: "PE\x00\x00"

Optional_Header_Magic :: enum u16le {
	PE32      = 0x010b,
	PE32_PLUS = 0x020b,
}

Optional_Header_Base :: struct #packed {
	magic:                          Optional_Header_Magic,
	major_linker_version:           u8,
	minor_linker_version:           u8,
	size_of_code:                   u32le,
	size_of_initialized_data:       u32le,
	size_of_uninitialized_data:     u32le,
	address_of_entry_point:         u32le,
	base_of_code:                   u32le,
}

File_Header :: struct #packed {
	machine:                 File_Machine,
	number_of_sections:      u16le,
	time_date_stamp:         u32le,
	pointer_to_symbol_table: u32le,
	number_of_symbols:       u32le,
	size_of_optional_header: u16le,
	characteristics:         bit_set[File_Characteristic; u16le],
}

Data_Directory :: struct #packed {
	virtual_address: u32le,
	size:            u32le,
}

Optional_Header32 :: struct #packed {
	using base: Optional_Header_Base,
	base_of_data:                   u32le,
	image_base:                     u32le,
	section_alignment:              u32le,
	file_alignment:                 u32le,
	major_operating_system_version: u16le,
	minor_operating_system_version: u16le,
	major_image_version:            u16le,
	minor_image_version:            u16le,
	major_subsystem_version:        u16le,
	minor_subsystem_version:        u16le,
	win32_version_value:            u32le,
	size_of_image:                  u32le,
	size_of_headers:                u32le,
	check_sum:                      u32le,
	subsystem:                      Subsystem,
	dll_characteristics:            bit_set[DLL_Characteristic; u16le],
	size_of_stack_reserve:          u32le,
	size_of_stack_commit:           u32le,
	size_of_heap_reserve:           u32le,
	size_of_heap_commit:            u32le,
	loader_flags:                   u32le,
	number_of_rva_and_sizes:        u32le,
	data_directory:                 [16]Data_Directory,
}

Optional_Header64 :: struct #packed {
	using base: Optional_Header_Base,
	image_base:                     u64le,
	section_alignment:              u32le,
	file_alignment:                 u32le,
	major_operating_system_version: u16le,
	minor_operating_system_version: u16le,
	major_image_version:            u16le,
	minor_image_version:            u16le,
	major_subsystem_version:        u16le,
	minor_subsystem_version:        u16le,
	win32_version_value:            u32le,
	size_of_image:                  u32le,
	size_of_headers:                u32le,
	check_sum:                      u32le,
	subsystem:                      Subsystem,
	dll_characteristics:            bit_set[DLL_Characteristic; u16le],
	size_of_stack_reserve:          u64le,
	size_of_stack_commit:           u64le,
	size_of_heap_reserve:           u64le,
	size_of_heap_commit:            u64le,
	loader_flags:                   u32le,
	number_of_rva_and_sizes:        u32le,
	data_directory:                 [16]Data_Directory,
}

// .debug section
Debug_Directory_Entry :: struct #packed {
	characteristics:     u32le,
	time_date_stamp:     u32le,
	major_version:       u16le,
	minor_version:       u16le,
	type:                Debug_Type,
	size_of_data:        u32le,
	address_of_raw_data: u32le,
	pointer_to_raw_data: u32le,
}


File_Machine :: enum u16le {
	UNKNOWN     = 0x0,
	AM33        = 0x1d3,
	AMD64       = 0x8664,
	ARM         = 0x1c0,
	ARMNT       = 0x1c4,
	ARM64       = 0xaa64,
	EBC         = 0xebc,
	I386        = 0x14c,
	IA64        = 0x200,
	LOONGARCH32 = 0x6232,
	LOONGARCH64 = 0x6264,
	M32R        = 0x9041,
	MIPS16      = 0x266,
	MIPSFPU     = 0x366,
	MIPSFPU16   = 0x466,
	POWERPC     = 0x1f0,
	POWERPCFP   = 0x1f1,
	R4000       = 0x166,
	SH3         = 0x1a2,
	SH3DSP      = 0x1a3,
	SH4         = 0x1a6,
	SH5         = 0x1a8,
	THUMB       = 0x1c2,
	WCEMIPSV2   = 0x169,
}

Directory_Entry :: enum u8 {
	EXPORT         = 0,
	IMPORT         = 1,
	RESOURCE       = 2,
	EXCEPTION      = 3,
	SECURITY       = 4,
	BASERELOC      = 5,
	DEBUG          = 6,
	ARCHITECTURE   = 7, // reserved
	GLOBALPTR      = 8,
	TLS            = 9,
	LOAD_CONFIG    = 10,
	BOUND_IMPORT   = 11,
	IAT            = 12,
	DELAY_IMPORT   = 13,
	COM_DESCRIPTOR = 14, // DLR Runtime headers
	_RESERVED      = 15,
}
#assert(len(Directory_Entry) == 16)

File_Characteristic :: enum u16le {
	RELOCS_STRIPPED         = 0,
	EXECUTABLE_IMAGE        = 1,
	LINE_NUMS_STRIPPED      = 2,
	LOCAL_SYMS_STRIPPED     = 3,
	AGGRESIVE_WS_TRIM       = 4,
	LARGE_ADDRESS_AWARE     = 5,

	BYTES_REVERSED_LO       = 7,
	MACHINE_32BIT           = 8, // IMAGE_FILE_32BIT_MACHINE  originally
	DEBUG_STRIPPED          = 9,
	REMOVABLE_RUN_FROM_SWAP = 10,
	NET_RUN_FROM_SWAP       = 11,
	SYSTEM                  = 12,
	DLL                     = 13,
	UP_SYSTEM_ONLY          = 14,
	BYTES_REVERSED_HI       = 15,
}

Subsystem :: enum u16le {
	UNKNOWN                  = 0,
	NATIVE                   = 1,
	WINDOWS_GUI              = 2,
	WINDOWS_CUI              = 3,
	OS2_CUI                  = 5,
	POSIX_CUI                = 7,
	NATIVE_WINDOWS           = 8,
	WINDOWS_CE_GUI           = 9,
	EFI_APPLICATION          = 10,
	EFI_BOOT_SERVICE_DRIVER  = 11,
	EFI_RUNTIME_DRIVER       = 12,
	EFI_ROM                  = 13,
	XBOX                     = 14,
	WINDOWS_BOOT_APPLICATION = 16,
}

DLL_Characteristic :: enum u16le {
	HIGH_ENTROPY_VA       = 5,
	DYNAMIC_BASE          = 6,
	FORCE_INTEGRITY       = 7,
	NX_COMPAT             = 8,
	NO_ISOLATION          = 9,
	NO_SEH                = 10,
	NO_BIND               = 11,
	APPCONTAINER          = 12,
	WDM_DRIVER            = 13,
	GUARD_CF              = 14,
	TERMINAL_SERVER_AWARE = 15,
}

Debug_Type :: enum u32le {
	UNKNOWN               = 0,  // An unknown value that is ignored by all tools.
	COFF                  = 1,  // The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
	CODEVIEW              = 2,  // The Visual C++ debug information.
	FPO                   = 3,  // The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
	MISC                  = 4,  // The location of DBG file.
	EXCEPTION             = 5,  // A copy of .pdata section.
	FIXUP                 = 6,  // Reserved.
	OMAP_TO_SRC           = 7,  // The mapping from an RVA in image to an RVA in source image.
	OMAP_FROM_SRC         = 8,  // The mapping from an RVA in source image to an RVA in image.
	BORLAND               = 9,  // Reserved for Borland.
	RESERVED10            = 10, // Reserved.
	CLSID                 = 11, // Reserved.
	REPRO                 = 16, // PE determinism or reproducibility.
	EX_DLLCHARACTERISTICS = 20, // Extended DLL characteristics bits.
}

Section_Header32 :: struct #packed {
	name:                    [8]u8,
	virtual_size:            u32le,
	virtual_address:         u32le,
	size_of_raw_data:        u32le,
	pointer_to_raw_data:     u32le,
	pointer_to_relocations:  u32le,
	pointer_to_line_numbers: u32le,
	number_of_relocations:   u16le,
	number_of_line_numbers:  u16le,
	characteristics:         Image_Scn_Characteristics,
}

Reloc :: struct #packed {
	virtual_address:    u32le,
	symbol_table_index: u32le,
	type:               Rel,
}

Image_Scn_Characteristics :: enum u32le {
	TYPE_NO_PAD            = 0x00000008, // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files. = 0x00000010, // Reserved for future use.
	CNT_CODE               = 0x00000020, // The section contains executable code.
	CNT_INITIALIZED_DATA   = 0x00000040, // The section contains initialized data.
	CNT_UNINITIALIZED_DATA = 0x00000080, // The section contains uninitialized data.
	LNK_OTHER              = 0x00000100, // Reserved for future use.
	LNK_INFO               = 0x00000200, // The section contains comments or other information. The .drectve section has this type. This is valid for object files only. = 0x00000400, // Reserved for future use.
	LNK_REMOVE             = 0x00000800, // The section will not become part of the image. This is valid only for object files.
	LNK_COMDAT             = 0x00001000, // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
	GPREL                  = 0x00008000, // The section contains data referenced through the global pointer (GP).
	MEM_PURGEABLE          = 0x00020000, // Reserved for future use.
	MEM_16BIT              = 0x00020000, // Reserved for future use.
	MEM_LOCKED             = 0x00040000, // Reserved for future use.
	MEM_PRELOAD            = 0x00080000, // Reserved for future use.
	ALIGN_1BYTES           = 0x00100000, // Align data on a 1-byte boundary. Valid only for object files.
	ALIGN_2BYTES           = 0x00200000, // Align data on a 2-byte boundary. Valid only for object files.
	ALIGN_4BYTES           = 0x00300000, // Align data on a 4-byte boundary. Valid only for object files.
	ALIGN_8BYTES           = 0x00400000, // Align data on an 8-byte boundary. Valid only for object files.
	ALIGN_16BYTES          = 0x00500000, // Align data on a 16-byte boundary. Valid only for object files.
	ALIGN_32BYTES          = 0x00600000, // Align data on a 32-byte boundary. Valid only for object files.
	ALIGN_64BYTES          = 0x00700000, // Align data on a 64-byte boundary. Valid only for object files.
	ALIGN_128BYTES         = 0x00800000, // Align data on a 128-byte boundary. Valid only for object files.
	ALIGN_256BYTES         = 0x00900000, // Align data on a 256-byte boundary. Valid only for object files.
	ALIGN_512BYTES         = 0x00A00000, // Align data on a 512-byte boundary. Valid only for object files.
	ALIGN_1024BYTES        = 0x00B00000, // Align data on a 1024-byte boundary. Valid only for object files.
	ALIGN_2048BYTES        = 0x00C00000, // Align data on a 2048-byte boundary. Valid only for object files.
	ALIGN_4096BYTES        = 0x00D00000, // Align data on a 4096-byte boundary. Valid only for object files.
	ALIGN_8192BYTES        = 0x00E00000, // Align data on an 8192-byte boundary. Valid only for object files.
	LNK_NRELOC_OVFL        = 0x01000000, // The section contains extended relocations.
	MEM_DISCARDABLE        = 0x02000000, // The section can be discarded as needed.
	MEM_NOT_CACHED         = 0x04000000, // The section cannot be cached.
	MEM_NOT_PAGED          = 0x08000000, // The section is not pageable.
	MEM_SHARED             = 0x10000000, // The section can be shared in memory.
	MEM_EXECUTE            = 0x20000000, // The section can be executed as code.
	MEM_READ               = 0x40000000, // The section can be read.
	MEM_WRITE              = 0x80000000, // The section can be written to.
}


Rel :: enum u16le {
	I386_ABSOLUTE         = 0x0000,
	I386_DIR16            = 0x0001,
	I386_REL16            = 0x0002,
	I386_DIR32            = 0x0006,
	I386_DIR32NB          = 0x0007,
	I386_SEG12            = 0x0009,
	I386_SECTION          = 0x000A,
	I386_SECREL           = 0x000B,
	I386_TOKEN            = 0x000C,
	I386_SECREL7          = 0x000D,
	I386_REL32            = 0x0014,

	AMD64_ABSOLUTE        = 0x0000,
	AMD64_ADDR64          = 0x0001,
	AMD64_ADDR32          = 0x0002,
	AMD64_ADDR32NB        = 0x0003,
	AMD64_REL32           = 0x0004,
	AMD64_REL32_1         = 0x0005,
	AMD64_REL32_2         = 0x0006,
	AMD64_REL32_3         = 0x0007,
	AMD64_REL32_4         = 0x0008,
	AMD64_REL32_5         = 0x0009,
	AMD64_SECTION         = 0x000A,
	AMD64_SECREL          = 0x000B,
	AMD64_SECREL7         = 0x000C,
	AMD64_TOKEN           = 0x000D,
	AMD64_SREL32          = 0x000E,
	AMD64_PAIR            = 0x000F,
	AMD64_SSPAN32         = 0x0010,

	ARM_ABSOLUTE          = 0x0000,
	ARM_ADDR32            = 0x0001,
	ARM_ADDR32NB          = 0x0002,
	ARM_BRANCH24          = 0x0003,
	ARM_BRANCH11          = 0x0004,
	ARM_SECTION           = 0x000E,
	ARM_SECREL            = 0x000F,
	ARM_MOV32             = 0x0010,

	THUMB_MOV32           = 0x0011,
	THUMB_BRANCH20        = 0x0012,
	THUMB_BRANCH24        = 0x0014,
	THUMB_BLX23           = 0x0015,

	ARM_PAIR              = 0x0016,

	ARM64_ABSOLUTE        = 0x0000,
	ARM64_ADDR32          = 0x0001,
	ARM64_ADDR32NB        = 0x0002,
	ARM64_BRANCH26        = 0x0003,
	ARM64_PAGEBASE_REL21  = 0x0004,
	ARM64_REL21           = 0x0005,
	ARM64_PAGEOFFSET_12A  = 0x0006,
	ARM64_PAGEOFFSET_12L  = 0x0007,
	ARM64_SECREL          = 0x0008,
	ARM64_SECREL_LOW12A   = 0x0009,
	ARM64_SECREL_HIGH12A  = 0x000A,
	ARM64_SECREL_LOW12L   = 0x000B,
	ARM64_TOKEN           = 0x000C,
	ARM64_SECTION         = 0x000D,
	ARM64_ADDR64          = 0x000E,
	ARM64_BRANCH19        = 0x000F,
	ARM64_BRANCH14        = 0x0010,
	ARM64_REL32           = 0x0011,
}

PE_CODE_VIEW_SIGNATURE_RSDS :: u32le(0x5344_5352)

COFF_SYMBOL_SIZE :: 18

COFF_Symbol :: struct #packed {
	using _: struct #raw_union {
		name:              [8]u8,
		name_ref: struct {
			zeroes: u32le,
			offset: u32le,
		}
	},
	value:                 u32le,
	section_number:        i16le,
	type:                  Image_Sym_Type,
	storage_class:         Image_Sym_Class,
	number_of_aux_symbols: u8,
}

// COFF_Symbol_Aux_Format5 describes the expected form of an aux symbol
// attached to a section definition symbol. The PE format defines a
// number of different aux symbol formats: format 1 for function
// definitions, format 2 for .be and .ef symbols, and so on. Format 5
// holds extra info associated with a section definition, including
// number of relocations + line numbers, as well as COMDAT info. See
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-5-section-definitions
// for more on what's going on here.
COFF_Symbol_Aux_Format5 :: struct #packed {
	size:             u32le,
	num_relocs:       u16le,
	num_line_numbers: u16le,
	checksum:         u32le,
	sec_num:          u16le,
	selection:        Image_Comdat_Select,
	_:                [3]u8, // padding
}

Image_Comdat_Select :: enum u8 {
	NODUPLICATES = 1,
	ANY          = 2,
	SAME_SIZE    = 3,
	EXACT_MATCH  = 4,
	ASSOCIATIVE  = 5,
	LARGEST      = 6,
}

// The symbol record is not yet assigned a section. A value of zero indicates
// that a reference to an external symbol is defined elsewhere. A value of
// non-zero is a common symbol with a size that is specified by the value.
IMAGE_SYM_UNDEFINED              :: 0
// The symbol has an absolute (non-relocatable) value and is not an address.
IMAGE_SYM_ABSOLUTE               :: -1
// The symbol provides general type or debugging information but does not
// correspond to a section. Microsoft tools use this setting along
// with .file records (storage class FILE).
IMAGE_SYM_DEBUG                  :: -2

Image_Sym_Type :: enum u16le {
	NULL   = 0,
	VOID   = 1,
	CHAR   = 2,
	SHORT  = 3,
	INT    = 4,
	LONG   = 5,
	FLOAT  = 6,
	DOUBLE = 7,
	STRUCT = 8,
	UNION  = 9,
	ENUM   = 10,
	MOE    = 11,
	BYTE   = 12,
	WORD   = 13,
	UINT   = 14,
	DWORD  = 15,
	PCODE  = 32768,

	DTYPE_NULL     = 0,
	DTYPE_POINTER  = 0x10,
	DTYPE_FUNCTION = 0x20,
	DTYPE_ARRAY    = 0x30,
}

Image_Sym_Class :: enum u8 {
	NULL             = 0,
	AUTOMATIC        = 1,
	EXTERNAL         = 2,
	STATIC           = 3,
	REGISTER         = 4,
	EXTERNAL_DEF     = 5,
	LABEL            = 6,
	UNDEFINED_LABEL  = 7,
	MEMBER_OF_STRUCT = 8,
	ARGUMENT         = 9,
	STRUCT_TAG       = 10,
	MEMBER_OF_UNION  = 11,
	UNION_TAG        = 12,
	TYPE_DEFINITION  = 13,
	UNDEFINED_STATIC = 14,
	ENUM_TAG         = 15,
	MEMBER_OF_ENUM   = 16,
	REGISTER_PARAM   = 17,
	BIT_FIELD        = 18,
	FAR_EXTERNAL     = 68, // Not in PECOFF v8 spec
	BLOCK            = 100,
	FUNCTION         = 101,
	END_OF_STRUCT    = 102,
	FILE             = 103,
	SECTION          = 104,
	WEAK_EXTERNAL    = 105,
	CLR_TOKEN        = 107,

	END_OF_FUNCTION  = 255,
}
