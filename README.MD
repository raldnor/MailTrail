# MailTrail

A simple script to check mail messages. Does some basic lookups.

A portable Windows release can be downloaded here: https://github.com/raldnor/MailTrail/releases

## Installation:
Create a virtual environment in the same directory where MailTrail is located:
```
$ python3 -venv p3env
```
Active the environment:
```
$ source ./p3env/bin/activate
```
Install requirements (Python packages):
```
$ pip install < requirements.txt
```

## Usage:
MailTrail expects mail messages in text-format (like .eml or .msg).

```
(p3env)$ python3 ./mailtrail.py 
 
  /\/\   __ _(_) /__   \_ __ __ _(_) | 
 /    \ / _` | | | / /\/ '__/ _` | | | 
/ /\/\ \ (_| | | |/ /  | | | (_| | | | 
\/    \/\__,_|_|_|\/   |_|  \__,_|_|_| 
v0.6 - Peter Berends for Team SOS 
    
usage: mailtrail.py [-h] [-o OUTPUT] mailfile
```

When using the -o flag output is also written to a text-file. 

## How to interpret the results
MailTrail was written as a simple little tool to do some lookups on mail messages. For example to spot indicators of phishing. Due to the nature of the mail protocol where many servers and clients use their own header formats the usability is limited, but it might aid in initial analysis.

The tool does the following steps:

### 1. Open the file with local analysis
When the file is opened it checks for the sender and recipient names. Indicators of spam or phishing might be a different return-path or reply-to field compared the the senders email address. 
The mail-client is usually spoofed, but displayed anyway. Sometimes script-kiddies use pre-baked scripts with a l33t mail-client name (e.g. Ph1sh3rM4n v3.0).
The sender domain is the domainname of the email address of the sender. This is used in the next step.

### 2. WHOIS lookup on the domain name of the senders email address
This is mostly for reference and this data is related to the email address, not to the path the email has travelled. You should correlate this info with data collected further on.

### 3. Looking up MX records
A company usually has its mail servers specified in their DNS records. These mail servers handle mail for the domain involved. When the mail trail (as shown in the next step) does not correlate it might be an indication for spam or phishing.

### 4. Mail Trail
Next follows a listing of servers that processed the mail while on its way to the recipient. The top record is where the email starts, so the last record is the server used by the recipient (your company?).
You should take a good look at the timestamps in front of the records, a long time between servers might indicate an overloaded server (and spammers and phishers usually know how to stress their mail servers).

### 5. Origin server
The first server that appears in the mail trail is the server that accepted the email from the sender. A lookup is made to get WHOIS information about this server. Often the first mail server is internally situated in a network. In such a case a failed lookup might be good news. A lookup involving some shady WHOIS information might be an indicator for a cheaply hosted or compromised server somewhere on the internet.
Make sure to correlate this information with the MX records from before.

### 6. X-Originating IP
Sometimes the mail client reports the IP address from which the mail is sent. When this information appears in the headers of the email message another WHOIS lookup is made to try to get information about the senders origin country (does it match the mail address lookup info?).

### 7. Additional interesting headers
Lastly a check is done for existence of some commonly-used headers. Notice that some of these headers can easily be inserted by a malicious person to fool a reader, like the X-Antivirus headers that give the impression that the mail attachments are safe to open. The following headers are checked:
- 'X-Spam-Level' - Indicates the probability of being spam by the number of asterisks (*) used
- 'X-Spam-Score' - Indicates the probability of being spam by numbers
- 'X-Spam-Status' - Which spam tests are used and what result was reported
- 'X-Spam-Report' - Human-readable report of found spam indicators
- 'Authentication-Results' - Might give information about SPF/DKIM checks. This reports whether the sender IP was allowed to send mail from this account (SPF) and whether the message was signed (DKIM)
- 'Received-SPF' - Tells whether the test to check if the original mail server was an authorised sender was succesful (pass)
- 'CMM-Authentication-Results' - Same as Received-SPF, but used by Microsoft (Hotmail)
- 'dkim' - Result of DKIM-test where individual email messages can be verified with a digital signature
- 'dmarc' - Result of DMARC test, a standard where authentication and signing are combined (SPF and DKIM)
- 'List-Unsubscribe' - Mailing lists often include this header with an address to unsubscribe (don't be fooled, this might be an indication the message is read)
- 'X-Virus-Scanned' - Might give the name of a virus scanner used, but often fake to give more 'authenticity' 
- 'X-Antivirus-Status' - Result of the virus scan (whether faked or not)

### Other useful stuff
WHOIS lookups often contain abuse information, like a phone number or email address. This might be used to report abuse of the server involved or to notify the company of a spoofed sender. 

## Ideas / TODO
Perhaps sometime, if I have time left, during a moon eclipse, when I'm fired from my job, when Netflix stops streaming, when Amazon stops sending toys to my house address...
I might add the following:
- SPF / DKIM checks
- Spam score indicators (I HATE THE LACK OF STANDARDIZATION HERE WITH A PASSION)
- Test HTML content for indicators (URLs, JS, weird links in images, URL shorteners etc.)
- Extract binaries and grep strings (same indicators as above)
- and so on...

## Questions?
Contact me: raldnor [atttt] elizium [dottttt] nu

### Credits
This app makes use of outlookmsgfile.py library to convert msg files to eml by Joshua Tauberer: https://github.com/JoshData/convert-outlook-msg-file.
