---
title: Nightmare Series - Stack Smashing (Part 1)
categories:
  - Blog
tags:
  - Reversing
  - Exploits
published: false
---
In this series I plan to run through the Nightmare set of binary challenges kindly created at https://github.com/guyinatuxedo/nightmare for my own fun and

File: 04-bof_variable/csaw18_boi

File Analysis:
Basic analysis of the file confirms it is an 64 bit ELF file and importantly in this cases shows us that it is not stripped meaning symbols are available and makes debugging and reversing easier for us.
![](/assets/images/stacksmashing01_nightmare_04_csaw_boi/file_check.png)
Symbols can be confirmed via 'readelf -s boi' which outputs the symbol list and corresponding offsets.

Running the file presents us a basic prompt for input which on testing returns the current date time as output.
![](/assets/images/stacksmashing01_nightmare_04_csaw_boi/prompt.png)

Basic RE:
Utilising PEDA (link), which provides an enhanced set of tools within GDB for debugging, we can start to inspect the binary. The 'checksec' command give us a quick overview of the binary protections enabled:
![](/assets/images/stacksmashing01_nightmare_04_csaw_boi/checksec.png)

Given we have symbols, we can take a look at the main functions simply by dumping the disassembly in GDB:
![](/assets/images/stacksmashing01_nightmare_04_csaw_boi/main_dump.png)

It's can be observed that the following is occurring:
 - Basic function prologue
 - Stack variable setup
 - Syscall to 'puts'
 - Syscall to 'read'
 - Resultant jump locations both land at 'run_cmd' function with different inputs
 - Epilogue and exit

From the events within the main function we see that the user is prompted for input, the input is read into a stack variable (rbp-0x30) and then compared to a value (rbp-0x1c = 0xcaf4baee) via the 'cmp' instruction. A conditional branch is taken to reach one of two calls to 'run_cmd', each with differing function parameters. Dumping the string parameters address values we can see that each one is a different string, one containing the location for 'date' and the other 'bash'. The confirms the behaviour observed when running the binary as test inputs display the current date to the user before exiting.

This is further confirmed when dumping the contents of the 'run_cmd' function:
![](/assets/images/stacksmashing01_nightmare_04_csaw_boi/run_cmd_dump.png)
The value passed as a function parameter is then passed to the system syscall and executed. So our goal is to now ensure that the conditional branch takes the route of run_cmd('/bin/bash') and we have a shell!

In order to achieve this, we can overflow the saved stack value and overwrite the saved value. The read function reads in a total of 0x18 bytes from the user input onto the stack variable located at rbp-0x30 which is an int (2 bytes)

Inspecting the location of the target value (rbp-0x1c) we can see that this is within the 0x18 bytes which we currently have write control over onto the stack (0x30-0x1c=0x14) which means we have the ability to overwrite 4 remaining bytes of the target stack variable containing '0xdeadbeef'

![](/assets/images/stacksmashing01_nightmare_04_csaw_boi/exploit_basic.png)

Exploit:

In this example, for the exploit to succeed we have to send the appropriate amount of data (0x14 bytes) followed by our overwrite payload value of '0xcaf3baee' and we should ensure the binary takes the conditional branch to start '/bin/bash'. We can utilise the interactive function of pwntools to connect and confirm the shell.

![](/assets/images/stacksmashing01_nightmare_04_csaw_boi/exploit.png)
