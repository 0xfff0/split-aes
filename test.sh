#!/bin/bash

prog=./a.out

if [[ ! -f "${prog}" ]]; then
    echo "Did you build ${prog}?"
    exit 1
fi

function test_case() {
    [[ "$#" == "2" ]] || exit 1

    kib=$1
    threads=$2

    echo "Test ${threads}-thread operations (input ${kib} Kib)"
    dd if=/dev/random of=./test_file.bin bs=1024 count=${kib} &> /dev/null
    ${prog} -i ./test_file.bin -o ./test_file.enc -p password123 -j ${threads} enc
    ${prog} -i ./test_file.enc -o ./test_file.dec -p password123 -j ${threads} dec
    diff ./test_file.dec ./test_file.bin &> /dev/null || echo "FAILED"
    rm test_file.*
}

test_case 2 1
test_case 2 4
test_case 1048576 1
test_case 1048576 8
