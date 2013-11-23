import dns.resolver #requires dnspython
import Queue, threading, urllib2, re, sys, socket, os, csv, datetime, subprocess, tarfile
sys.path.append(os.getcwd())
from val import *

queue = Queue.Queue()
out_queue = Queue.Queue()
myfilename = sys.argv[1].split('.')[0] + '_Verified.csv'
myfile = open(myfilename, 'wb')
wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
wr.writerow(['date_time','email','status','mx','helo','helo greet','rcpt','rcpt greet'])

class ThreadUrl(threading.Thread):
    """Threaded Url Grab"""

    def __init__(self, queue, out_queue):
        threading.Thread.__init__(self)
        self.queue = queue
        self.out_queue = out_queue

    def run(self):
        while True:
            #grabs host from queue
            email = self.queue.get()
            is_valid = validate_email(email)
            is_valid.insert(0, email)
            is_valid.insert(0, datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
            wr.writerow(is_valid) 
            #print is_valid
            self.queue.task_done()


if len(sys.argv) == 3:
    ip = urllib2.urlopen('http://ifconfig.me/ip')
    ip = ip.read()
    ip = ip.rstrip()
    s = urllib2.urlopen('http://addgadgets.com/ip_blacklist/index.php?ipaddr=' + ip)
    s = s.read()
    t = re.search(r'\d?\d?\/72', s)
    t = t.group()
    blacklistcount = t[:t.find('/')]
    print "Blacklists: " + blacklistcount
    #raw_input("Press any key to continue...")
    

def main():
    count = 0
    p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE)
    result, err = p.communicate()
    if p.returncode != 0:
        raise IOError(err)
    
    FileIN = open(sys.argv[1])
    if len(sys.argv) < 2:
        print "need email list parameter"
        sys.exit('Usage: %s emails.txt' % sys.argv[0])
        
    #spawn a pool of threads, and pass them queue instance    
    for i in range(200):
        t = ThreadUrl(queue, out_queue)
        t.setDaemon(True)
        t.start()
        
    #populate queue with data
    for email in FileIN:
        count += 1
        if count % 500 == 0: print '%d of %d', %(count,total)
        email = email.strip()
        queue.put(email)
            
    #wait on the queue until everything has been processed
    queue.join()
    out_queue.join()
main()
myfile.close()

tar = tarfile.open(sys.argv[1][:1] + '.tgz', 'w:gz')
tar.add(myfilename)
tar.close()
#subprocess.call(['tar','-pczf',sys.argv[1][:1] + '.tgz' sys.argv[1].split('.')[0] + '_Verified.csv'])
subprocess.call(['mv','-f',sys.argv[1][:1] + '.tgz','/var/www/html'])
subprocess.call(['rm','-f',sys.argv[1].split('.')[0] + '_Verified.csv'])

print 'Finished %s as %s' %(sys.argv[1], sys.argv[1][:1] + '.tgz')