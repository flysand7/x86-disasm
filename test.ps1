
# Build test files
mkdir -p tmp/bin -erroraction 'silentlycontinue'
nasm test/asm/mov16.asm -o tmp/bin/mov16

# Build the assembler
./build

# Run the test files
./x86-disasm ./tmp/bin/mov16 -cpu:16


