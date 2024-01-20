
prepare-disasm FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out

build-cli: generate
    odin build src -out:x86-disasm -o:none -debug

build-cli-release: generate
    odin build src -out:x86-disasm -o:aggressive -disable-assert

build-lib: generate
    odin build src -out:x86-disasm -o:none -debug -out -build-mode:object

build-lib-release: generate
    odin build src -out:x86-disasm -o:aggressive -disable-assert -build-mode:object

time-cli-objudmp: generate build-cli-release
    hyperfine -w 16 "./x86-disasm ./x86-disasm -no-color" "objdump -M intel -d -j .text ./x86-disasm" --output pipe

time-cli-ndisasm: generate build-cli-release
    tests/1million.py
    hyperfine -w 16 "./x86-disasm tests/is-even.bin -no-color -format:raw64" "ndisasm -b64 tests/is-even.bin" --output pipe

test-local: (prepare-disasm "./tests/local.asm") generate build-cli
    ./x86-disasm -format:raw64 ./temp/temp.out -print-all

test-self: generate build-cli
    ./x86-disasm ./x86-disasm -print-all

generate:
    odin run src/disasm/table -out:table-generator
    odin check src/disasm/generated_table -no-entry-point
    rm ./table-generator

