
ODIN_FLAGS := "-o:none -debug -out:test.bin"

prepare-disasm FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out

build-cli: generate
    odin build . -o:none -debug

build-cli-release: generate
    odin build . -o:aggressive

time-cli: generate build-cli
    time ./x86-disasm x86-disasm > /dev/null

test-local: (prepare-disasm "./tests/local.asm") generate build-cli
    ./x86-disasm -format:raw64 ./temp/temp.out -print-all

test-self: generate build-cli
    ./x86-disasm ./x86-disasm -print-all

generate:
    odin run disasm/table
    odin check disasm/generated_table -no-entry-point

