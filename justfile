
test TEST FILENAME:
    mkdir -p temp/
    nasm {{FILENAME}} -o temp/temp.out
    odin test src -test-name:test_{{TEST}} -- temp/temp.out

