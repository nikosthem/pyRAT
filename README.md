# pyRAT - An Antivirus Evasion Tool!

**pyRAT** is an desktop tool, written in Python, which automates the **generation of Metasploit payload executables** that have the ability to invade systems without getting detected by most antivirus solutions. **pyRAT** meets all the requirements of usability and makes use of the **Metasploit Framework** along with its features. The exploitation process has the intention of gaining access to the vulnerable system by creating a **meterpreter session** between the user and the target system. **pyRAT** currently targets only Windows machines.


## Getting Started

Download pyRAT by cloning the Git repository:

	git clone https://github.com/nikosthem/pyRAT.git


## Installation

1. In order to make the application interact with the Metasploit Framework you have to connect to the RPC service. Download the msfrpc module from
https://github.com/SpiderLabs/msfrpc/ and run in terminal(inside python-msfrpc directory):
* python setup.py install

2. Download and install ClamAV with the command:
root@kali: apt-get install clamav

3. Download and install pyClamd from https://xael.org/pages/pyclamd-en.html
and run the following commands in terminal:
* python setup.py install
* sudo apt install clamav-daemon
* sudo service clamav-daemon start

4. Issue this command inside msfconsole:
**msf > load msgrpc Pass=abc123**

If all goes well, the following response will be shown in the console, which tells
the IP address, username, and password that will be used for the connection to
the msgrpc server:
* MSGRPC Service: 127.0.0.1:55552
* MSGRPC Username: msf
* MSGRPC Password: abc123
* Successfully loaded plugin: msgrpc

5. Run pyRAT.py and enjoy hacking!


## Important Notice 

The user has to be aware that the payload will only work if the target machine is vulnerable to the chosen exploit(when starting the App). Sometimes the payload will work only with the use of multi/handler and not with the use of that chosen exploit(e.g. exploit/windows/smb/ms17_010_psexec). This happens because the target might not be vulnerable to the exploit that was used. 
So, the user has to know prior to the use of pyRAT, the vulnerability that he is going to exploit in the target machine. If he is not sure, the use of multi/handler might be a solution.

## Disclaimer

**pyRAT** is developed, strictly, for **educational purposes** and its ultimate goal is to be a helpful tool during the process of a penetration test. Any other malicious or illegal usage of this tool is not recommended and it does not represent the purpose of thsi research. Overall, this work can provide a great learning opportunity in the area of ethical hacking using penetration testing.


## Prerequisites

 - Python 2.7
 - Metasploit Framework
 - Kali Linux (or any other Linux distro with Metasploit Framework installed)
 - msfrpc module
 - ClamAV and pyClamd


## Built With

* Python 2.7


## Versioning

pyRAT - Version 1.0.0


## Authors

* **Nikos Themelis** - [nikosthem](https://github.com/nikosthem)
