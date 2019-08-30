# Assignment_02 - Shell_Reverse_TCP shellcode

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.
https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-1456

## Assignment details

Create a Shell_Reverse_TCP shellcode
- Reverse connects to configured IP and Port
- Executes /bin/sh on successful connection

IP and Port should be easily configurable

### Instructions
- Run ./compile_reverse_shell.sh shell_reverse_tcp [ip] [port]
- Example: ./compile_reverse_shell.sh shell_reverse_tcp 127.1.1.1 1337
