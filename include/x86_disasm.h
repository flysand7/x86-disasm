/*
    C api for x86-disasm (untested).
*/
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
    #define x86_extern extern "C"
#else
    #define x86_extern extern
#endif

/*
    The generic sizing of various operands or memory.
    The value X86_Size_Default is used internally and
    should not appear in the output.
*/
enum X86_Size {
    X86_Size_Default  = 0,
    X86_Size_Size_8   = 1,
    X86_Size_Size_16  = 2,
    X86_Size_Size_32  = 3,
    X86_Size_Size_64  = 4,
    X86_Size_Size_128 = 5,
    X86_Size_Size_256 = 6,
    X86_Size_Size_512 = 7,
};

/*
    Register set of x86.
    Specifies a distinct line of registers for which an index is used.

    Reg - general-purpose registers: AX, CX, DX, BX, SP, BP, SI, DI,
        as well as their 8, 32 or 64-bit versions.
    Mmx - an MMX register: MM0 .. MM7
    Xmm - an XMM or YMM register: XMM0..XMM15, YMM0..YMM15
    Sreg - a segment register: ES, CS, SS, DS, FS, GS
    Dreg - a debug register DR0 .. DR7 (4 through 7 don't exist but they can be encoded)
    Creg - a control register CD0 .. CR7 (same as debug registers for 4 through 7)
    Bndreg - a bound register (BND0 .. BND7)
    St - an x87 FPU stack "register".
    Extras - IP and FLAGS.
*/
enum X86_Reg_Set {
    X86_Reg_Set_Reg    = 0,
    X86_Reg_Set_Mmx    = 1,
    X86_Reg_Set_Xmm    = 2,
    X86_Reg_Set_Sreg   = 3,
    X86_Reg_Set_Dreg   = 4,
    X86_Reg_Set_Creg   = 5,
    X86_Reg_Set_Bndreg = 6,
    X86_Reg_Set_St     = 7,
    X86_Reg_Set_Extras = 8,
};

/*
    The mode the CPU is expected to run in when executing the code.

    X86_CPU_16 - 16-bit code disassembly.
    X86_CPU_32 - 32-bit code disassembly.
    X86_CPU_64 - 64-bit code disassembly.
*/
enum X86_CPU_Mode {
    X86_CPU_16,
    X86_CPU_32,
    X86_CPU_64,
};

/*
    An immediate operand.
*/
struct X86_Imm typedef X86_Imm;
struct X86_Imm {
    int64_t value;
};

/*
    A register operand.

    kind - one of the values from X86_Reg_Set enum.
    size - one of the values from X86_Size enum.
    idx - the index into the register table for that register.
*/
struct X86_Reg typedef X86_Reg;
struct X86_Reg {
    uint8_t kind;
    uint8_t size;
    uint8_t idx;
};

/*
    A memory operand.

    size - one of the values from the X86_Size enum. Specifies the load size.
    base - the base register.
    index - the index register.
    scale - the scale that's applied to the index.
    disp - sign-extended displacement.

    The memory operand specifies the memory in the form of
        size [base + index*scale + disp]
*/
struct X86_Mem typedef X86_Mem;
struct X86_Mem {
    uint8_t size;
    X86_Reg base;
    X86_Reg index;
    int32_t disp;
    int32_t scale;
};

/*
    Short memory displacement. Relative to the address of the next
    instruction.
*/
struct X86_Mem_Short typedef X86_Mem_Short;
struct X86_Mem_Short {
    int8_t disp;
};

/*
    Near memory operand.

    size - specifies the size of the data referenced by the operand.
    offs - specifies the offset from the segment.
*/
struct X86_Mem_Near typedef X86_Mem_Near;
struct X86_Mem_Near {
    uint8_t size;
    int32_t offs;
};

/*
    Far memory operand.

    size - specifies the size of the data referenced by the operand.
    seg - specifies the 16-bit segment for the memory.
    offs - specifies the offset from segment base.
*/
struct X86_Mem_Far typedef X86_Mem_Far;
struct X86_Mem_Far {
    uint8_t size;
    uint16_t seg;
    int32_t offs;
};

/*
    Instruction operand kinds.
*/
enum X86_Operand_Kind {
    X86_Operand_None,
    X86_Operand_Reg,
    X86_Operand_Mem,
    X86_Operand_Mem_Short,
    X86_Operand_Mem_Near,
    X86_Operand_Mem_Far,
    X86_Operand_Imm,
};

/*
    Operand union.
    
    kind - one of the values from the X86_Operand_Kind enum.
*/
struct X86_Operand typedef X86_Operand;
struct X86_Operand {
    union {
        X86_Reg       op_reg;
        X86_Mem       op_mem;
        X86_Mem_Short op_mem_short;
        X86_Mem_Near  op_mem_near;
        X86_Mem_Far   op_mem_far;
        X86_Imm       op_imm;
    };
    intptr_t kind;
};

// Instruction has REP prefix.
#define X86_Flag_Rep   1<<0

// Instruction has REPZ prefix.
#define X86_Flag_Repz  1<<1

// Instruction has REPNZ prefix.
#define X86_Flag_Repnz 1<<2

// Instruction has LOCK prefix.
#define X86_Flag_Lock  1<<3

// Instruction has BND prefix.
#define X86_Flag_Bnd   1<<4

/*
    String type for mnemonics.
*/
struct X86_String typedef X86_String;
struct X86_String {
    char *data;
    size_t len;
};

/*
    Type representing an instruction.

    mnemonic - the name of instruction.
    length - the length of instruction encoding, in bytes.
    seg - the segment override for the instruction (affects Mem operand)
    op - array of up to 4 operands.
    op_count - number of operands in the instruction.
    flags - instruction flags. See X86_Flag_*.
*/
struct X86_Inst typedef X86_Inst;
struct X86_Inst {
    X86_String mnemonic;
    intptr_t length;
    X86_Reg  seg;
    X86_Operand op[4];
    intptr_t op_count;
    uint8_t flags;
};

/*
    Errors returned by the pre-decoding phase.

    None - no error.
    Trunc - an instruction could not be decoded because go beyond the bounds
        of the supplied buffer.
    No_Encoding - after scanning the prefixes and the opcode no encoding was
        found that identifies the general shape of the instruction.
    Invalid - an instruction was decoded successfully but contained invalid
        fields. For example for VEX.M-MMMM field can only have a few valid
        values.
*/
enum X86_Disasm_Error {
    None        = 0,
    Trunc       = 1,
    No_Encoding = 2,
    Invalid     = 3,
};

/*
    The instruction decoding API is split into two parts for the sake of
    multithreadability. Pre-decoding phase finds the basic shape of an instruction
    and returns a handle (encoding) representing it. The decoding phase then
    takes the buffer containing that instruction and the encoding and transforms
    it into an instruction struct with all the operands decoded.

    This function is meant to be called in the loop with adjusted values of
    buf_len and len for each instruction that was pre-decoded. Do not call decode
    if pre-decoding returned an error.

    In case pre-decoding return an error recovery is possible: The out_size
    parameter will still contain the length of instruction upto which the output
    was parsed. It is possible to output these bytes as 'db 0xHH' (like ndisasm)
    and call this function on the next iteration adjusting the length. But note
    that the rest of the output may not be correct.

    cpu_mode - The mode in which to decode.
    buf_len - the length of the buffer containing insturctions.
    buf - the pointer to the buffer containing instructions.
    out_encoding - encoding handle.
    out_size - the size of pre-decoded instruction.

    Returns an error, if pre-decoding phase failed to decode an instruction.

    Thread-safety: safe, but beware that the offset to the next instruction
    is unknown.
*/
x86_extern X86_Disasm_Error x86_disasm_pre_decode(
    X86_CPU_Mode cpu_mode,
    size_t buf_len,
    uint8_t *buf,
    uint64_t *out_encoding,
    uint64_t *out_size
);

/*
    Decode an instruction of given length.

    cpu_mode - the CPU mode instruction is supposed to be decoded at.
    buf_len - length of the instruction, in bytes.
    buf - pointer to the buffer containing instruciton buffer.
    encoding - the encoding handle returned by x86_disasm_pre_decode.
    out_instruction - the instruction output.

    Thread-safety: safe.
*/
x86_extern bool x86_disasm_decode(
    X86_CPU_Mode cpu_mode,
    size_t buf_len,
    uint8_t *buf,
    uint64_t encoding,
    X86_Inst *out_instruction
);


/*
    The printing API
    x86-disasm library has some built-in functions for printing instructions
    into text streams. These functions are not thread-safe.
*/

/*
    Buffered output for instruction printing. You can create one of these bad
    boys and have the instruction printing into your string builder or other
    thing to speed up the output to stdout.

    ctx - user data for instruction 
    procedure - The procedure that is called upon flushing the stream/overflowing
        the internal buffer.
    _buf, _buf_idx - internal data for statekeeping for the buffered output.
        Don't touch these ones.
    
    The parameters to the procedure:
        ctx - the context of the stream (same as X86_Stream's)
        buf_len - the length of the character buffer (non-zero).
        buf - the character buffer.
*/
struct X86_Stream typedef X86_Stream;
struct X86_Stream {
	void (*procedure)(void *ctx, size_t buf_len, char *buf);
	void *ctx;
    char _buf[1024];
    intptr_t _buf_idx;
};

/*
    Flush the data from the internal buffers of the stream to the user procedure.
    Make sure to call this function after the printing to the stream has been
    finished.
    
    Thread-safety: not thread safe.
*/
x86_extern void x86_stream_flush(X86_Stream *s);

/*
    Write a string to the buffered stream.

    str_len - the length of the string.
    str - the string to print to the stream.
    
    Thread-safety: not thread safe.
*/
x86_extern void x86_stream_write_str(X86_Stream *s, size_t str_len, char *str);

/*
    Write an integer to the buffered stream, in decimal format.

    number - the number to print.
    force_sign - force the plus sign in case the number is positive.
    
    Thread-safety: not thread safe.
*/
x86_extern void x86_stream_write_int(X86_Stream *s, int64_t number, int32_t force_sign);

/*
    Write an integer to the buffered stream, in hexadecimal format.

    number - the number to print.
    pad - pad the output to N characters with zeroes.
    
    Thread-safety: not thread safe.
*/
x86_extern void x86_stream_write_hex(X86_Stream *s, int64_t number, intptr_t pad);

/*
    Write an instruction in Intel-flavored assembly into the output buffer.

    inst - pointer to instruction to print.
    colors - whether to print ansi codes for colored output.
    
    Thread-safety: not thread safe.
*/
x86_extern void x86_stream_write_inst_intel(X86_Stream *s, X86_Inst *inst, int32_t colors);

/*
    Write an instruction in AT&T-flavored assembly into the output buffer.

    inst - pointer to instruction to print.
    colors - whether to print ansi codes for colored output.
    
    Thread-safety: not thread safe.
*/
x86_extern void x86_stream_write_inst_att(X86_Stream *s, X86_Inst *inst, int32_t colors);
