---
title: "LNK Hunting"

categories:
  - Blog

tags:
  - Malware
  - Research

published: false
---

LNK Shortcut files present an interesting attack vector for initial access during malware campaigns. The description and icon of the
LNK files can be modified to trick users alongside the initial phishing context, allowing LNK files to serve as first stage droppers
or fully self serving payloads.

```
rule lnk_simple_poc{
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
}
```

Deploying this using VT Hunt and Retro hunt allows us to find previous samples and alert on new incoming samples (provided you have goof fortune to have an enterprise license)
Quick run in retro hunt shows around 10000 matches for 90 days worth of data, however today an interesting sample flagged in live hunt email notifications.

Based around the current health pandemic which attackers are clearly attempting to leverage for lure material:

Filename: **'20200308-sitrep-48-covid19.pdf.lnk'**
 - MD5 aa67b7141327c0fad9881597c76282c0
 - SHA-1 2ea6ee7b3bbcfb06da23627f76df93c69061af59
 - SHA-256 d67ab3d7e09ee705111ee707c528c18a1caab04ab77a5f2b2b58ba58be7f3060
 - SSDEEP 24576:CQjIcFyV0dxCboFKK6irgwX7tkErksUJnUXo7B5jj86X:CQRAoXBXJxmJn3n3X
 - File type Windows shortcut
 - Magic MS Windows shortcut
 - File size 1.11 MB (1160121 bytes)

The LNK binary structure is (fairly) straight forward (link here) and so the easiest point to start with is examining the strings within the shell shortcut.
[](../assets/images/2020-03-30-LNK_Hunting/strings.png)

The following can be observed:
 - cmd.exe execution
 - Copies the file '20200308-sitrep-48-covid-19-.pdf.lnk' to a .tmp file in the %tmp% directory
 - Copies certutil.exe from system32 folder the the %tmp% directory and renames as msoia.exe (Office Telemetry Agent)
 - Uses findstr.exe to loacted and extract an appended base64 string contained within the LNK file starting with the string 'TVNDRgAAAA' into a .tmp file
 - Decodes the extracted text using -decoded flag for disguised certutil.exe
 - Utilised the expand.exe binary to expand the contents of the newly decoded file (hints that this is a archive file, likely CAB)
 - Run a javascript file named '9sOXN6Ltf0afe7.js' using wscript (file likley extracted from the archive previously expanded)

[[]][]
