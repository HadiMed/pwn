# Advanded Buffer overlow 
buffer overflow on the read function that reads from the file to a buffer that is fixed size to 8000 bytes somthing like that , it s uses the NX flag , so the stack is not executable 

<b> exploit </b> : first to bypass the NX we need to call the API <b> Virtualprotect </b> to change the protection on the stack to executable then place our shellcode after the return from VirtualProtect
more explications on the script . 


