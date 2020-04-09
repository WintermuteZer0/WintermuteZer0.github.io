---
title: "Vulnerability Research for the Blue Teamer"

categories:
  - Blog

tags:
  - DFIR
  - Research

published: false
---

Recently I have had fun poking around looking for privilege file abuse using symbolic links, hard links and junctions to try and gain elevated file write, delete or copy primitives. Still a fun area of exploration (especially given the numerous CVE's appearing in the past year) however I was curious around looking at these types of techniques on a larger scale.

From a research perspective the flow follows something along the lines of the following:
 - Setup clean test Windows build
 - Install SysInternals, RPCView and a few other tools
 - Install/setup any other target applications of choice
 - Run everything and look for the following in procmon (as a starting point):
   - Details do not contain "impersonating"
   - Integrity levels are not low or medium
   - CreateFile or DeleteFile operations
   - Result is FILE NOT FOUND
   - Poking around at various associated RPC interfaces and COM objects on the system
   - and so on and so forth (in depth blog post by itself)

I was recently intrigued by the idea of applying the search across larger scale enterprise datasets. From the perspective of a blue teamer, usually this is in the course of investigating an ongoing incident or mid response and to uncover an attacker utilising techniques within the environment.

What if we take the same privilege escalation principles and attempt to unveil hidden opportunities in the environment before the attacker can?

Detection of the cause is always better than detection of the symptom.

Normally, the detection process follows the lines of attempting to identify the symptom of something suspicious, i.e
 - Service binaries being overwritten by detection of hash comparison (expected to actual)
 - Service binary changes by detection of the update of the post change suspicious behaviour
 - Suspicious post action indicators such as a SYSTEM level processes and shells etc.







Examples:

Privilege Escalation

Service Unquoted Binary Path
 - Windows Security Event 7045

Elevated execution from usr writable location  
 - Services
 - Scheduled Tasks

Driver Injection
 - Symon EventCode 6 where driver location is User Writeable (highly unlikely but still)

DLL Injection
 - Symon EventCode 7 where Module location is User Writeable

Privilege File Creation
 - Sysmon EventCode 11 where
