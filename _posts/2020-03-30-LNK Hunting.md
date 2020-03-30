---
title: "LNK Hunting" 

categories:
  - Blog
  
tags:
  - Malware
  - Research
  
published: false
---

LNK Shortcut files present an interesting attack vector for intial access during malware campaings. The description and icon of the 
LNK files can be modified to trick users alongside the intial phishing context, allowing LNK files to serve as first stage droppers
or fully self serving payloads.






```rule lnk_simple_poc{
strings:
//LNK Format
  $lnk = {4C 00 00 00 01 14 02 00}

//OPTIONS
  $cmd1 = "bitsadmin" ascii wide 
  $cmd2 = "ertutil" ascii wide 
  $cmd3 = "wscript" ascii wide
  $cmd4 = "cscript" ascii wide
  $cmd5 = "powershell" ascii wide
  $cmd6 = "http" ascii wide
condition:
  ($lnk at 0) and any of $cmd*
}```

Deploying this using VT Hunt and Retro hunt allows us to find previous samples and alert on new incoming samples (provided you have goof fortune to have an enterprise license)
Quick run in retro hunt shows around 10000 matches for 90 days worth of data, however today an interesting sample flagged in live hunt email notifications.

Based around the current health pandemic which attackers are clearly attempting to leverage for lure material:
Filename: '20200308-sitrep-48-covid19.pdf.lnk'
MD5 aa67b7141327c0fad9881597c76282c0
SHA-1 2ea6ee7b3bbcfb06da23627f76df93c69061af59
SHA-256 d67ab3d7e09ee705111ee707c528c18a1caab04ab77a5f2b2b58ba58be7f3060
SSDEEP 24576:CQjIcFyV0dxCboFKK6irgwX7tkErksUJnUXo7B5jj86X:CQRAoXBXJxmJn3n3X
File type Windows shortcut
Magic MS Windows shortcut
File size 1.11 MB (1160121 bytes) 


