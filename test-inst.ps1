
mkdir -p tmp/bin -erroraction 'silentlycontinue'
nasm test/asm/inst.asm -o tmp/bin/inst
./build
./x86-disasm ./tmp/bin/inst -cpu:16


