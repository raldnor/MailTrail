import platform
import email
import sys
import argparse
import re
import socket
import ast
import os
import dns.resolver
from ipwhois import IPWhois
from pprint import pprint
from email.parser import HeaderParser


PROGVERSION = 'v0.6.1'

class bcolors:
    HEADER = '\033[92m\033[1m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

windows = False
if platform.system() == 'Windows':
    windows = True

def checkExit():
    if windows == True:
        input('\r\nPress Enter to exit...')

class MailTrailParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        checkExit()
        sys.exit(2)

def printHeader():
	if windows == False:
		print(f'{bcolors.HEADER}')
	print('\r\n\
  /\\/\\   __ _(_) /__   \\_ __ __ _(_) | \r\n /    \\ / _` | | | / /\\/ \'__/ _` | | | \r\n/ /\\/\\ \\ (_| | | |/ /  | | | (_| | | | \r\n\\/    \\/\\__,_|_|_|\\/   |_|  \\__,_|_|_| \r\n%s - Peter Berends for Team SOS\r\n' % PROGVERSION)
	if windows == False:
		print(f'{bcolors.ENDC}')
		
printHeader()				
		
parser = MailTrailParser()
parser.add_argument("mailfile", help = "Analyse a mail file")
parser.add_argument("-o", "--output", help = "Write output to file")
args = parser.parse_args()


def removeLineBreaks(val):
    try:
        val = val.replace("\r","")
        val = val.replace("\n"," ")
        return val.rstrip()
    except:
        return ''

report = ''		
def buildReport(msg, val=''):
	global report
	report += msg + removeLineBreaks(val) + '\n'

def printOk(msg, val=''):	
	buildReport(msg, val)
	if windows == False:
		print(f'{bcolors.OKBLUE}'+msg+f'{bcolors.ENDC}'+removeLineBreaks(val))
	else:
		print(msg + removeLineBreaks(val))

def printProcess(msg, val=''):
	buildReport(msg, val)
	if windows == False:
		print(f'{bcolors.OKGREEN}'+msg+f'{bcolors.ENDC}'+removeLineBreaks(val))
	else:
		print(msg + removeLineBreaks(val))

def printError(msg, val=''):
	buildReport(msg, val)
	if windows == False:
		print(f'{bcolors.FAIL}'+msg+f'{bcolors.ENDC}'+removeLineBreaks(val))
	else:
		print(msg + removeLineBreaks(val))

def printWarning(msg, val=''):
	buildReport(msg, val)
	if windows == False:
		print(f'{bcolors.WARNING}'+msg+f'{bcolors.ENDC}'+removeLineBreaks(val))
	else:
		print(msg + removeLineBreaks(val))
    
def getIP(hostname): 
    global senderip
    try:
        printOk("Looking up IP for hostname: ", hostname) 
        ip = socket.gethostbyname(hostname) 
        printProcess("+ IP: ", ip) 
        senderip = ip
    except: 
        printError("- Unable to lookup IP") 
        
def parseWhois(data):
    if 'network' in data.keys():
        printProcess('+ ASN description: ', data['asn_description'])
        printProcess('+ Name: ', data['network']['name'])
        printProcess('+ Country: ', data['network']['country'])
        printProcess('+ IP block: ', data['network']['cidr'])
    else:
        printError('- Could not find network section in WHOIS data')
    if 'objects' and 'entities' in data.keys():
        #for i in data['entities']:
        for i in data['objects']:
            printProcess('+ Handle: ', i)
            try:
                if 'contact' in data['objects'][i].keys():
                    contactinfo = data['objects'][i]['contact'] or {}
                
                    addresses_from_contactinfo = contactinfo.get('address') or {}
                    for address in addresses_from_contactinfo:
                        printProcess('+ \tAddress ',removeLineBreaks(address['value']))
                    
                    emails_from_contactinfo = contactinfo.get('email') or {}
                    for email in emails_from_contactinfo:
                        printProcess('+ \t' + email['type'] + ' ', email['value'])
                
                    phone_from_contactinfo = contactinfo.get('phone') or {}
                    for phone in phone_from_contactinfo:
                        printProcess('+ \t' + phone['type'] + ' ', phone['value'])
            except:
                a=1        
            if 'events' in data['objects'][i].keys():
                eventinfo = data['objects'][i] or {}
                events = eventinfo.get('events') or {}
                for event in events:
                    printProcess('+ \t' + event['action'] + ' ', event['timestamp'])
    else:
        printError('- Could not find objects/entities in WHOIS data')

def renderMailTrail(message):
    headerdict = dict()
    sourceserver = ''
    i = 0
    
    for key, value in message.items():
        if key.lower() == 'received':
            headerdict[i] = removeLineBreaks(value)
            i += 1
    
    headercount = i
    printOk('\r\nHops taken to deliver the message: ', str(headercount))
    
    while i > 0:
        curheader = headerdict[i-1]
        tempvars = curheader.split(';')
        statusmsg = ''
        if i < 10:
            statusmsg = '------- [' + str(i) + '] -------'
        else :
            statusmsg = '------- [' + str(i) + '] ------'
        if (i == headercount):
            try: 
                splitvar = tempvars[0].lower()
                splitvar = splitvar.split('from ')
                splitvar = splitvar[1].split(' ', 1)
                sourceserver = splitvar[0]
            except:
                sourceserver = ''
            statusmsg = 'START' + ' - [' + str(i) + '] ------->'
        elif (i == 1):
            statusmsg += '|'
        else:
            statusmsg += '>'
        printOk(statusmsg)
        printProcess('+ ' + tempvars[1] + ' ', tempvars[0])
        i -= 1
    printOk('------------------- END')
    return sourceserver
    
def whoisLookup(domain):
    try:
        try:
            ip = socket.gethostbyname(domain)
        except:
            printWarning('- Could not find the IP address for ' + domain)
        object = IPWhois(ip)
        res = object.lookup_rdap(depth=1) 
        return res
    except:
        printWarning('- Could not lookup WHOIS information for ' + domain)
        return 0

  
"""
    PROGRAM FLOW STARTS HERE
"""

# 1. OPEN MAIL FILE
try:
    with open(args.mailfile) as file:
        filename, fileext = os.path.splitext(args.mailfile)
        if fileext == '.msg':
            import outlookmsgfile
            eml = outlookmsgfile.load(file)
            message = email.message_from_string(str(eml))
        else:
            message = email.message_from_file(file)
        mailfrom = message['From']
        mailto = message['To']
        returnpath = message['Return-Path'] or 'not set'
        replyto = message['Reply-To'] or 'not set'
        xmailer = message['X-Mailer'] or 'not set'
        xoriginatingip = message['X-Originating-IP'] or 'not set'
        printOk('Mail recipient: ', mailto)
        printOk('Mail sender: ', mailfrom)
        printOk('Return-Path (usually the same as sender): ', returnpath)
        printOk('Reply-to (usually the same as sender): ', replyto)
        printOk('Mail client: ', xmailer)
        domain = re.search("@[\w.]+", mailfrom)
        domain = domain.group()
        domain = domain[1:]
except:
    printError("\r\nERROR! - Could not parse the file specified\r\n")
    #raise
    checkExit()
    sys.exit(2)
# 2. LOOKUP SENDER MAIL ADDRESS (might be spoofed)
if (len(domain) > 2):
    printOk('\r\nSender domain as specified: ', domain)
    res = whoisLookup(domain)
    if (res != 0):
        parseWhois(res)

# 3. LOOKUP MX RECORDS FOR EMAIL ADDRESS DOMAIN
printOk('\r\nLooking up MX records for domain:')
i = 0
try:
    for lookup in dns.resolver.resolve(domain, 'MX'):
        printProcess('+ mailserver: ', lookup.to_text())
        i += 1
    if i == 0:
        printWarning('No MX records found')
except:
    printError('Could not lookup MX information')

# 4. ANALYSE RECEIVED HEADERS TO PRINT MAIL TRAIL
try:
    sourceserver = renderMailTrail(message)
except:
    printError('\r\nCould not interpret mail trail')
    checkExit()
    sys.exit(2)    

# 5. TRY TO LOOKUP ORIGINATING MAIL SERVER
if (sourceserver != ''):
    printProcess('\r\n+ Origin server/mail client: ', sourceserver)
    printOk('Trying to get WHOIS info for originating mail server/mail client ', sourceserver)
    res = whoisLookup(sourceserver)
    if (res != 0):
        parseWhois(res)
    else:
        printOk('No server information found, originating mail server or client station might be internal')
        
# 6. ORIGINATING IP IS SPECIFIED
if xoriginatingip != 'not set':
    ip = xoriginatingip.translate({ord(i): None for i in '[]'})
    printOk('\r\nX-Originating IP is set (often the ip-address of the sender/client): ', ip)
    printOk('Whois on X-Originating IP:')
    res = whoisLookup(ip)
    if (res != 0):
        parseWhois(res)
    else:
        printOk('No server information found.')
		
# 7. POSSIBLE INTERESTING HEADERS:
printOk('\r\nPossible interesting headers:')
headers = {'X-Spam-Level', 'X-Spam-Score', 'X-Spam-Status', 'X-Spam-Report', 'dkim', 'dmarc', 'Authentication-Results', 'Received-SPF', 'List-Unsubscribe', 'X-Virus-Scanned', 'X-Antivirus-Status'}
headercount = 0
for header in headers:
	result = message[header] or 'not set'
	if result != 'not set':
		headercount += 1
		printOk('+ ' + header + ': ', result)
if headercount == 0:
	printOk('No additional interesting headers found')
	
# WRITE OUTPUT TO FILE
if args.output:
    print('Writing output to: %s' % args.output)
    try:
    	with open(args.output, 'w') as outputfile:
    		outputfile.write(report)
    except:
    	printError('ERROR! Could not write to: ', args.output)
        	
checkExit()
