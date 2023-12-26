
test TEST FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out
    odin test src -test-name:test_{{TEST}} -- temp/temp.out

dump FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out
    odin test src -test-name:test_dump -- temp/temp.out

