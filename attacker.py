import pexpect
import time

print("Starting SSH attacker simulation... waiting 10s for browser")
time.sleep(10)
child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@localhost -p 2222')
child.expect('assword:')
child.sendline('admin123')
child.expect('root@ubuntu:~#')
print("Authenticated!")

time.sleep(1)
child.sendline('ls -la')
child.expect('root@ubuntu:~#')
print("Executed ls -la")

time.sleep(1)
child.sendline('whoami')
child.expect('root@ubuntu:~#')
print("Executed whoami")

time.sleep(1)
child.sendline('pwd')
child.expect('root@ubuntu:~#')
print("Executed pwd")

child.sendline('exit')
print("Done!")
