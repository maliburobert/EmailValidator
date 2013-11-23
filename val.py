import sys, urllib2, re, smtplib, socket, dns.resolver
from dns.exception import DNSException

WSP = r'[ \t]'                                       # see 2.2.2. Structured Header Field Bodies
CRLF = r'(?:\r\n)'                                   # see 2.2.3. Long Header Fields
NO_WS_CTL = r'\x01-\x08\x0b\x0c\x0f-\x1f\x7f'        # see 3.2.1. Primitive Tokens
QUOTED_PAIR = r'(?:\\.)'                             # see 3.2.2. Quoted characters
FWS = r'(?:(?:' + WSP + r'*' + CRLF + r')?' + \
            WSP + r'+)'                                    # see 3.2.3. Folding white space and comments
CTEXT = r'[' + NO_WS_CTL + \
                r'\x21-\x27\x2a-\x5b\x5d-\x7e]'              # see 3.2.3
CCONTENT = r'(?:' + CTEXT + r'|' + \
                     QUOTED_PAIR + r')'                        # see 3.2.3 (NB: The RFC includes COMMENT here
                                                                                                         # as well, but that would be circular.)
COMMENT = r'\((?:' + FWS + r'?' + CCONTENT + \
                    r')*' + FWS + r'?\)'                       # see 3.2.3
CFWS = r'(?:' + FWS + r'?' + COMMENT + ')*(?:' + \
             FWS + '?' + COMMENT + '|' + FWS + ')'         # see 3.2.3
ATEXT = r'[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]'           # see 3.2.4. Atom
ATOM = CFWS + r'?' + ATEXT + r'+' + CFWS + r'?'      # see 3.2.4
DOT_ATOM_TEXT = ATEXT + r'+(?:\.' + ATEXT + r'+)*'   # see 3.2.4
DOT_ATOM = CFWS + r'?' + DOT_ATOM_TEXT + CFWS + r'?' # see 3.2.4
QTEXT = r'[' + NO_WS_CTL + \
                r'\x21\x23-\x5b\x5d-\x7e]'                   # see 3.2.5. Quoted strings
QCONTENT = r'(?:' + QTEXT + r'|' + \
                     QUOTED_PAIR + r')'                        # see 3.2.5
QUOTED_STRING = CFWS + r'?' + r'"(?:' + FWS + \
                                r'?' + QCONTENT + r')*' + FWS + \
                                r'?' + r'"' + CFWS + r'?'
LOCAL_PART = r'(?:' + DOT_ATOM + r'|' + \
                         QUOTED_STRING + r')'                    # see 3.4.1. Addr-spec specification
DTEXT = r'[' + NO_WS_CTL + r'\x21-\x5a\x5e-\x7e]'    # see 3.4.1
DCONTENT = r'(?:' + DTEXT + r'|' + \
                     QUOTED_PAIR + r')'                        # see 3.4.1
DOMAIN_LITERAL = CFWS + r'?' + r'\[' + \
                                 r'(?:' + FWS + r'?' + DCONTENT + \
                                 r')*' + FWS + r'?\]' + CFWS + r'?'  # see 3.4.1
DOMAIN = r'(?:' + DOT_ATOM + r'|' + \
                 DOMAIN_LITERAL + r')'                       # see 3.4.1
ADDR_SPEC = LOCAL_PART + r'@' + DOMAIN               # see 3.4.1

# A valid address will match exactly the 3.4.1 addr-spec.
VALID_ADDRESS_REGEXP = '^' + ADDR_SPEC + '$'

#SETUP KEYWORDS
spamtraps = ['fakemx.net','grey-area.mailhostingserver.com','ctmail.com','nullmx.domainmanager.com']
keywords = ['unknown','does not exist','no such user','unrouteable','doesnt','no mailbox','invalid address','invalid recipient','ddress rejected']
unknowns = ['transaction failed - psmtp','relay access','block','bounce verification']

def validate_email(email):
    try:
        assert re.match(VALID_ADDRESS_REGEXP, email) is not None
        hostname = email[email.find('@')+1:]
        try:
            mx_hosts = dns.resolver.query(hostname, 'MX')
        except Exception:
            try:
                smtp = smtplib.SMTP(timeout=15) 
                smtp.connect(hostname)
                return ['UNKNOWN no mx servers but valid email domain']
            except Exception:
                return ['BAD no mx servers']
        i = 0
        for mx in mx_hosts:
            mxresult = [str(mx_hosts[i].exchange)]
            for spamtrap in spamtraps:
                if re.search(spamtrap,str(mx).lower()): 
                    reresult = ['BAD SPAMTRAP!']
                    return reresult + mxresult
            try:
                smtp = smtplib.SMTP(timeout=15)
                smtp.connect(str(mx_hosts[i].exchange))
                i += 1
                status, _ = smtp.helo()
                #REMEMBER: We must try all the mail servers listed
                if i == len(mx_hosts) and status != 250: return ['UNKNOWN MX Exhausted',str(mx_hosts[i-1].exchange),status,_] #status + '|' + _ + '|MX Exhausted'
                #if re.search('Pleased to be wasting your time',_()): 
                #    reresult = ['UNKNOWN verification block']
                #    break
                heloresult = [status, _] 
                if status != 250: continue
                smtp.mail('')
                status, _ = smtp.rcpt(email)
                if status != 250 and status != 550:
                    reresult = ['UNKNOWN Based upon error code']
                if status == 550:
                    for keyword in keywords:
                        if re.search(keyword,_.lower()): reresult = ['BAD']
                    for unknown in unknowns:
                        if re.search(unknown,_.lower()): reresult = ['UNKNOWN verification block']
                if status == 250:
                    if '(sink)' in _: reresult = ['BAD']
                rcptresult = [status, _] 
                smtp.quit()
                break
            except smtplib.SMTPServerDisconnected: #Server not permits verify user
                return ['UNKNOWN SMTPServerDisconnected', str(mx_hosts[i-1].exchange)]
            except Exception:
                return ['UNKNOWN possible timeout', str(mx_hosts[i-1].exchange)]
    except socket.error, v:
        errorcode=v[0]
        return ['UNKNOWN socket error:' + str(errorcode)]
    except (AssertionError):
        if AssertionError:
            return ['BAD regex fail']
    if 'reresult' not in locals(): reresult = ['OK']
    if 'rcptresult' not in locals(): rcptresult = ['NA']
    if 'mxresult' not in locals(): rcptresult = ['NA']
    return reresult + mxresult + heloresult + rcptresult

