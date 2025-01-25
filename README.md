

![screenshot](https://raw.githubusercontent.com/tlsbollei/HookDetector/refs/heads/main/dec/rabbit.gif)

&nbsp;




[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![first-timers-only Friendly](https://img.shields.io/badge/first--timers--only-friendly-blue.svg)](http://www.firsttimersonly.com/)

## Introduction

This program checks if functions in ntdll.dll are hooked or modified. It looks at the first few bytes of each function to see if they match the expected code. If the bytes are different, it indicates the function may be hooked. The program uses memory reading techniques (Portable Executable file structure manipulation, image below) to inspect the functions and report their status. It helps detect tampering or alterations in system functions. 

![screenshot](https://raw.githubusercontent.com/tlsbollei/HookDetector/refs/heads/main/dec/PE-Structure.png)

### In this program, we are going to be specifically playing with the Export Directory located within the NT Headers of a PE (Portable Executable file), more specifically in the DataDirectory field of the IMAGE_OPTIONAL_HEADER.


## Introduction to Syscalls 

* ```Syscalls (System Calls)``` are the mechanism by which programs interact with the operating system kernel to perform tasks that require higher privileges or direct access to system resources.
* When a program needs to perform an operation like reading a file, allocating memory, or creating a process, it issues a syscall to request that the kernel perform the action on its behalf.
* This is necessary because user-mode applications do not have direct access to kernel-level resources for security and stability reasons.
* In Windows, ```syscalls``` are exposed through functions like ```NtCreateFile```, ```NtQuerySystemInformation```, ```ZwReadFile```, etc., which are implemented in the ```ntdll.dll``` library.
* These functions serve as an abstraction layer between ```user-mode``` applications and the underlying operating system kernel, allowing programs to request services in a controlled, secure manner. 

## Introduction to Hooks

* Syscall hooks refer to a method of modifying the normal behavior of system calls, usually by intercepting them and redirecting their execution to custom code. This modification is often used to monitor, modify, or even bypass the intended behavior of syscalls.
* In the context of malicious software or debugging tools, syscall hooks can be used to hide activity (e.g., hiding processes or files) or alter the function of critical system calls to avoid detection or modify system behavior.

# Workflow and Walkthrough
Below shows the stub for for ```NtReadVirtualMemory``` on a system with no EDR present, meaning the syscall``` NtReadVirtualMemory``` is not hooked:

![screenshot](https://raw.githubusercontent.com/tlsbollei/HookDetector/refs/heads/main/dec/stub11.png)


We can see the NtReadVirtualMemory syscall stub starts with instructions:

```yaml
00007ffc`d6dcc780 4c8bd1          mov     r10,rcx
00007ffc`d6dcc783 b83f000000      mov     eax,3Fh
...
```

... which roughly translates to the following opcodes :

```4c 8b d1 b8```

Below shows an example of how ```NtReadVirtualMemory``` syscall stub looks like when it's hooked by an EDR:
![screenshot](https://raw.githubusercontent.com/tlsbollei/HookDetector/refs/heads/main/dec/stub22.png)

We can see that the hooked NtReadVirtualMemory syscall stub starts with different instructions :

```yaml
jmp 0000000047980084
```

... which roughly translates to the following opcodes :

```e9 0f 64 f8 c7```



All x64 Windows SYSCALLs must follow this general calling convention : 

```yaml
MOV R10, RCX
MOV EAX, <SYSCALL_NUMBER>h
SYSCALL
RETN
```

...as a result of this standard pattern, hook detection becomes trivial.

## Workflow

Based on these discoveries, we can map out and brainstorm :

* Hooks are typically implemented by replacing the first few bytes of a function’s code with a JMP or CALL instruction. This redirection changes the flow of execution, causing the program to jump to another address where custom behavior (e.g., logging or blocking actions) is executed instead of the original function.
* The program detects syscall hooks by examining the first few bytes of the functions in ntdll.dll, particularly those starting with Nt or Zw (common prefixes for syscalls).
* Prologue inspection is used to check if the first bytes of these functions match a known unhooked pattern (e.g., 0x4c 0x8b 0xd1 0xb8), which is characteristic of unmodified syscalls.
* The program uses ReadProcessMemory to retrieve the first few bytes of each syscall function and then compares them to a predefined pattern.
* If the bytes don't match, it indicates that the function might be hooked. The program specifically looks for JMP or CALL opcodes (0xE9 or 0xFF), which are commonly used to redirect the execution flow in a hook.

That`s it! Nothing more, nothing less.
For those who understand concepts better visually - below is a graph of our plan 

![screenshot](https://raw.githubusercontent.com/tlsbollei/HookDetector/refs/heads/main/dec/hookedunhooked.png)

# Key Features
* Dynamic Function Scanning: Loads ```ntdll.dll``` into memory using LoadLibraryA and retrieves the process handle with ```GetCurrentProcess()``` to access its functions.

* PE Header Parsing: Extracts the DOS Header and NT Headers to locate the Export Directory, where the addresses and names of exported functions are stored.

* Export Directory Iteration: Uses ```AddressOfFunctions```, ```AddressOfNames```, and ```AddressOfNameOrdinals``` to loop through all exported functions in ```ntdll.dll```.

* Syscall Detection: The ```isSyscall``` function checks if a function starts with ```Nt``` or ```Zw```, signaling it's a ```syscall``` and requiring special hook checks.

* Memory Integrity Check: ```ReadProcessMemory``` reads function memory and compares the first bytes against expected patterns, detecting hooks or modifications.

* Hook Detection: Identifies functions with ```JMP``` or ```CALL``` instructions (common hooks) and reports their status, distinguishing between unhooked and modified functions.


## You may also like...

- [NTDLL.dll Unhooker](https://github.com/tlsbollei/NTDLL-Unhook) - A program written in C that unhooks the .txt section of the NTDLL.dll loaded in memory with the .text section of a clean copy on the disk, effectively removing any EDR-placed security hooks
- [SHA-256 Crack](https://github.com/tlsbollei/sha256crack) - SHA256 cracking tool written in C++ utilizing 2 attack modes - a Dictionary attack and a Brute Force attack with a customizable charset and max length



> GitHub [tlsbollei](https://github.com/tlsbollei) &nbsp;&middot;&nbsp;
> Instagram [0fa102](https://www.instagram.com/0fa102/)
> Discord [0fa](https://discord.com/channels/@me)
> Telegram [boleii655](https://t.me/boleii655)

 <img src="https://raw.githubusercontent.com/tlsbollei/HookDetector/refs/heads/main/dec/me.png" alt="screenshot" width="200"/> 
 Y3J1c2hhbmRkZXN0cm95Cg==
