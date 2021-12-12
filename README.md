# Advanced Buffer overflow 
buffer overflow on the read function that reads from the file to a buffer that is fixed size to 8000 bytes somthing like that ,  NX is enabled , so the stack is not executable 

<b> exploit </b> : first to bypass the NX we need to call the API <b> Virtualprotect </b> to change the protection on the stack to executable then place our shellcode (to find the address of <b>System </b> in mscvrt.dll) after the return from VirtualProtect
more explications on the script . 


