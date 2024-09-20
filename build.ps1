
odin build tools/tablegen -out:table-gen.exe -debug
./table-gen ./tables/16bit.txt disasm/table_gen.odin
odin build cli -out:x86-disasm.exe -debug -define:X86_USE_STUB=false
