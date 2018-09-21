pyRAT - version 1.0

--> pyRAT SETUP 


1. To connect to the RPC service you need to download the msfrpc module from
https://github.com/SpiderLabs/msfrpc/
2. Download and install ClamAV with the command:
root@kali: apt-get install clamav
3. Download and install pyClamd from https://xael.org/pages/pyclamd-en.html
and run the following commands in terminal:
• python setup.py install
• sudo apt install clamav-daemon
• sudo service clamav-daemon start
4. Issue this command inside msfconsole:
msf > load msgrpc Pass=abc123
If all goes well, the following response will be shown in the console, which tells
the IP address, username, and password that will be used for the connection to
the msgrpc server:
* MSGRPC Service: 127.0.0.1:55552How to install and run pyRAT
38
* MSGRPC Username: msf
* MSGRPC Password: abc123
* Successfully loaded plugin: msgrpc
5. Run pyRAT.py and enjoy hacking!


IMPORTANT NOTICE: The user has to be aware that the payload will only work if the target machine is vulnerable to the chosen exploit(when starting the App). Sometimes the payload will work only with the use of multi/handler and not with the use of that chosen exploit(e.g. exploit/windows/smb/ms17_010_psexec). This happens because the target might not be vulnerable to the exploit that was used. 
So, the user has to know prior to the use of pyRAT, the vulnerability that he is going to exploit in the target machine. If he is not sure, the use of multi/handler might be a solution.
