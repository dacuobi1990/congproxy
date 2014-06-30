from OpenSSL import SSL
import socket
import time

class NetLibError(Exception): pass
class NetLibDisconnect(Exception): pass
class NetLibTimeout(Exception): pass

class filelike(object):
    BLOCKSIZE = 1024 * 32
    def __init__(self, o):
        self.o = o
        self._log = None

    def set_descriptor(self, o):
        self.o = o

    def __getattr__(self, attr):
        return getattr(self.o, attr)

    def start_log(self):
        """
            Starts or resets the log.

            This will store all bytes read or written.
        """
        self._log = []

    def stop_log(self):
        """
            Stops the log.
        """
        self._log = None

    def is_logging(self):
        return self._log is not None

    def get_log(self):
        """
            Returns the log as a string.
        """
        if not self.is_logging():
            raise ValueError("Not logging!")
        return "".join(self._log)

    def add_log(self, v):
        if self.is_logging():
            self._log.append(v)

class Writer(filelike):
    def flush(self):
        try:
            if hasattr(self.o, "flush"):
                self.o.flush()
        except socket.error, v:
            raise NetLibDisconnect(str(v))

    def write(self, v):
        if v:
            try:
                if hasattr(self.o, "sendall"):
                    self.add_log(v)
                    return self.o.sendall(v)
                else:
                    r = self.o.write(v)
                    self.add_log(v[:r])
                    return r
            except (SSL.Error, socket.error), v:
                raise NetLibDisconnect(str(v))


class Reader(filelike):
    def read(self, length):
        """
            If length is -1, we read until connection closes.
        """
        result = ''
        start = time.time()
        while length == -1 or length > 0:
            if length == -1 or length > self.BLOCKSIZE:
                rlen = self.BLOCKSIZE
            else:
                rlen = length
            try:
                data = self.o.read(rlen)
            except SSL.ZeroReturnError:
                break
            except SSL.WantReadError:
                if (time.time() - start) < self.o.gettimeout():
                    time.sleep(0.1)
                    continue
                else:
                    raise NetLibTimeout
            except socket.timeout:
                #raise NetLibTimeout
                raise socket.timeout
            except socket.error:
                raise NetLibDisconnect
            except SSL.SysCallError, v:
                raise NetLibDisconnect
            if not data:
                break
            result += data
            if length != -1:
                length -= len(data)
        self.add_log(result)
        return result

    def readline(self, size = None):
        result = ''
        bytes_read = 0
        while True:
            if size is not None and bytes_read >= size:
                break
            try:
                ch = self.read(1)
            except NetLibDisconnect:
                break
            bytes_read += 1
            if not ch:
                break
            else:
                result += ch
                if ch == '\n':
                    break
        return result