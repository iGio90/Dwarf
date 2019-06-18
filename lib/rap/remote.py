#!/usr/bin/python
#
# Python implementation of the radare remote protocol
#

##===================================================0
## server api
##===================================================0

from socket import *
from struct import *

RAP_OPEN = 1
RAP_READ = 2
RAP_WRITE = 3
RAP_SEEK = 4
RAP_CLOSE = 5
RAP_SYSTEM = 6
RAP_CMD = 7
RAP_REPLY = 0x80


# TODO: Add udp
# TODO: allow to init funptrs with a tuple
class RapServer:
    def __init__(self):
        self.offset = 0
        self.size = 0
        self.fd = None
        self.handle_eof = None
        self.handle_system = None
        self.handle_cmd = None
        self.handle_seek = None
        self.handle_read = None
        self.handle_write = None
        self.handle_open = None
        self.handle_close = None

        self.running = False

    # copypasta from client
    def system(self, cmd):
        buf = pack(">Bi", RAP_SYSTEM, len(str(cmd)))
        self.fd.send(buf)
        self.fd.send(cmd)
        # read response
        buf = self.fd.recv(5)
        (c, l) = unpack(">Bi", buf)
        if c != RAP_SYSTEM | RAP_REPLY:
            print("rmt-system: Invalid response packet")
            return ""
        if l > 0:
            buf = self.fd.recv(l)
        else:
            buf = ""
        return buf

    def _handle_packet(self, c, key):
        self.fd = c
        if key == RAP_OPEN:
            buf = c.recv(2)
            (flags, length) = unpack(">BB", buf)
            file = c.recv(length)
            if self.handle_open is not None:
                fd = self.handle_open(file, flags)
            else:
                fd = 3434
            buf = pack(">Bi", key | RAP_REPLY, fd)
            c.send(buf)
        elif key == RAP_READ:
            buf = c.recv(4)
            (length,) = unpack(">I", buf)
            if self.handle_read is not None:
                ret = self.handle_read(length)
                lon = len(ret)
            else:
                ret = ""
                lon = 0
            print("PACKING REPLY")
            buf = pack(">Bi", key | RAP_REPLY, lon)
            print("SENDING RAP READ")
            c.send(buf)
            c.send(ret)
        elif key == RAP_WRITE:
            buf = c.recv(4)
            (length,) = unpack(">I", buf)
            buf = c.recv(length)
            # TODO: get buffer and length
            if self.handle_write is not None:
                length = self.handle_write(buf)
            buf = pack(">Bi", key | RAP_REPLY, length)
            c.send(buf)
        elif key == RAP_SEEK:
            buf = c.recv(9)
            (type, off) = unpack(">BQ", buf)
            seek = 0
            if self.handle_seek is not None:
                seek = self.handle_seek(off, type)
            else:
                if type == 0:  # SET
                    seek = off
                elif type == 1:  # CUR
                    seek = seek + off
                elif type == 2:  # END
                    seek = self.size
            self.offset = seek
            buf = pack(">BQ", key | RAP_REPLY, seek)
            c.send(buf)
        elif key == RAP_CLOSE:
            if self.handle_close is not None:
                length = self.handle_close(self.fd)
        elif key == RAP_CMD:
            buf = c.recv(4)
            (length,) = unpack(">i", buf)
            ret = c.recv(length)
            if self.handle_cmd is not None:
                reply = self.handle_cmd(ret)
            else:
                reply = ""
            buf = pack(">Bi", key | RAP_REPLY, len(str(reply)))
            c.send(buf + reply)
        elif key == RAP_SYSTEM:
            buf = c.recv(4)
            (length,) = unpack(">i", buf)
            ret = c.recv(length)
            if self.handle_system is not None:
                reply = self.handle_system(ret)
            else:
                reply = ""
            buf = pack(">Bi", key | RAP_REPLY, len(str(reply)))
            c.send(buf + reply)
        else:
            print("Unknown command %x" % key)
            c.close()

    def _handle_client(self, c):
        while True:
            try:
                buf = c.recv(1)
                if buf == "" and self.handle_eof is not None:
                    self.handle_eof(c)
                    break
                if len(buf) == 0:
                    print("Connection closed\n")
                    break
                self._handle_packet(c, ord(buf))
            except KeyboardInterrupt:
                break

    def listen_tcp(self, port):
        s = socket()
        s.bind(("0.0.0.0", port))
        s.listen(999)
        print("Listening at port %d" % port)
        self.running = True
        while self.running:
            (c, (addr, port)) = s.accept()
            print("New client %s:%d" % (addr, port))
            self._handle_client(c)

    def stop(self):
        self.running = False


##===================================================0
## client api
##===================================================0

class RapClient:
    def __init__(self, host, port):
        self.connect_tcp(host, port)

        self.fd = None

    def connect_tcp(self, host, port):
        fd = socket()
        fd.connect((host, port))
        self.fd = fd

    def disconnect(self):
        self.fd.close()
        self.fd = None

    def open(self, file, flags):
        b = pack(">BBB", RAP_OPEN, flags, len(file))
        self.fd.send(b)
        self.fd.send(file)
        # response
        buf = self.fd.recv(5)
        (c, l) = unpack(">Bi", buf)
        if c != (RAP_REPLY | RAP_OPEN):
            print("rmt-open: Invalid response packet 0x%02x" % c)
        return l

    def read(self, count):
        b = pack(">Bi", RAP_READ, count)  # len(buf))
        self.fd.send(b)
        # response
        buf = self.fd.recv(5)
        (c, l) = unpack(">Bi", buf)
        buf = self.fd.recv(l)
        return buf

    # TODO: not tested
    def write(self, buf):
        # self.fd.send(buf)
        b = pack(">Bi", RAP_WRITE, len(buf))
        self.fd.send(b + buf)
        # response
        buf = self.fd.recv(5)
        (c, l) = unpack(">Bi", buf)
        if c != (RAP_REPLY | RAP_WRITE):
            print("rmt-write: Invalid response packet 0x%02x" % c)

    def lseek(self, type, addr):
        # WTF BBQ?
        buf = pack(">BBQ", RAP_SEEK, type, addr)
        self.fd.send(buf)
        # read response
        buf = self.fd.recv(5)  # XXX READ 5!?!?!? shouldnt be 9 ?!?!? WTF
        (c, l) = unpack(">Bi", buf)
        # print("Lseek : %d"%l)
        return l

    def close(self, fd):
        buf = pack(">Bi", RAP_CLOSE, fd)
        self.fd.send(buf)
        # read response
        buf = self.fd.recv(5)
        (c, l) = unpack(">Bi", buf)
        if c != RAP_REPLY | RAP_CLOSE:
            print("rmt-close: Invalid response packet")

    def cmd(self, cmd):
        buf = pack(">Bi", RAP_CMD, len(str(cmd)))
        self.fd.send(buf + cmd)
        # read response
        buf = self.fd.recv(5)
        (c, l) = unpack(">Bi", buf)
        if c != RAP_CMD | RAP_REPLY:
            print(c)
            print("rmt-cmd: Invalid response packet")
            return ""
        buf = ""
        if l > 0:
            read = 0
            while read < l:
                rbuf = self.fd.recv(l - read)
                read += len(rbuf)
                buf += rbuf
        return buf

    def system(self, cmd):
        buf = pack(">Bi", RAP_SYSTEM, len(str(cmd)))
        self.fd.send(buf)
        self.fd.send(cmd)
        # read response
        buf = self.fd.recv(5)
        (c, l) = unpack(">Bi", buf)
        if c != RAP_SYSTEM | RAP_REPLY:
            print("rmt-system: Invalid response packet")
            return ""
        if l > 0:
            buf = self.fd.recv(l)
        return buf
