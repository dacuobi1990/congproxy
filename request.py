import string, urlparse

class HttpError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg

    def __str__(self):
        return "HttpError(%s, %s)"%(self.code, self.msg)

def get_line(fp):
	line=fp.readline()
	if line=='\r\n' or line == '\n':
		line=fp.readline()
	return line

def parse_line(line):
    try:
        method, url, protocol = string.split(line)
    except ValueError:
    	return None
    return method ,url,protocol


def parse_url(url):
    """
        Returns a (scheme, host, port, path) tuple, or None on error.
    """
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
   # print    scheme, netloc, path, params, query, fragment
    if not scheme:
        return None
    if ':' in netloc:
        host, port = string.rsplit(netloc, ':', maxsplit=1)
        try:
            port = int(port)
        except ValueError:
            return None
    else:
        host = netloc
        if scheme == "https":
            port = 443
        else:
            port = 80
    path = urlparse.urlunparse(('', '', path, params, query, fragment))
    
    if not path.startswith("/"):
    	path = "/" + path
    return scheme, host, port, path  

def parse_http_protocol(s):
    """
        Parse an HTTP protocol declaration. Returns a (major, minor) tuple, or
        None.
    """
    if not s.startswith("HTTP/"):
        return None
    _, version = s.split('/', 1)
    if "." not in version:
        return None
    major, minor = version.split('.', 1)
    try:
        major = int(major)
        minor = int(minor)
    except ValueError:
        return None
    return major, minor


def read_headers(fp):
    """
        Read a set of headers from a file pointer. Stop once a blank line is
        reached. Return a ODictCaseless object, or None if headers are invalid.
    """
    length=0
    ret = []
    header={}
    name = ''
    while 1:
        line = fp.readline()
        length+=len(line)
        if not line or line == '\r\n' or line == '\n':
            break

        if line[0] in ' \t':
            if not ret:
                return None
            # continued header
            ret[-1][1] = ret[-1][1] + '\r\n ' + line.strip()
        else:
            i = line.find(':')
            # We're being liberal in what we accept, here.
            if i > 0:
                name = line[:i]
                value = line[i+1:].strip()
                ret.append([name.lower(), value.lower()])
            else:
                return None

    for i in ret:
        if not header.has_key(i[0]):
            header[i[0]]=[]

        header[i[0]].append(i[1])



        

        #for i in ret:
            #header[i[0]]=i[1]
    return header,length


def get_header_tokens(headers, key):
    """
        Retrieve all tokens for a header key. A number of different headers
        follow a pattern where each header line can containe comma-separated
        tokens, and headers can be set multiple times.
    """
    toks = []
    toks=headers[key][0].split(',')
    return toks

def has_chunked_encoding(headers):
    if not headers.has_key('transfer-encoding'):
        return False
    #print get_header_tokens(headers,'transfer-encoding')
    return "chunked" in [i.lower() . strip() for i in get_header_tokens(headers, "transfer-encoding")]


def read_chunked(code, fp, limit):
    """
        Read a chunked HTTP body.

        May raise HttpError.
    """
    content = ""
    total = 0
    while 1:
        line = fp.readline(128)
        if line == "":
            raise HttpError(code, "Connection closed prematurely")
        if line != '\r\n' and line != '\n':
            try:
                length = int(line, 16)
            except ValueError:
                # FIXME: Not strictly correct - this could be from the server, in which
                # case we should send a 502.
                raise HttpError(code, "Invalid chunked encoding length: %s"%line)
            if not length:
                break
            total += length
            if limit is not None and total > limit:
                msg = "HTTP Body too large."\
                      " Limit is %s, chunked content length was at least %s"%(limit, total)
                raise HttpError(code, msg)
            content += fp.read(length)
            line = fp.readline(5)
            if line != '\r\n':
                raise HttpError(code, "Malformed chunked body")
    while 1:
        line = fp.readline()
        if line == "":
            raise HttpError(code, "Connection closed prematurely")
        if line == '\r\n' or line == '\n':
            break
    return content

def read_http_body(code, rfile, headers,all,limit):
    """
        Read an HTTP body:

            code: The HTTP error code to be used when raising HttpError
            rfile: A file descriptor to read from
            headers: An ODictCaseless object
           # all: Should we read all data?
            limit: Size limit.
    """
    if has_chunked_encoding(headers):
        content = read_chunked(code, rfile, limit)
    elif "content-length" in headers:
        try:
            l = int(headers["content-length"][0].strip())
        except ValueError:
            # FIXME: Not strictly correct - this could be from the server, in which
            # case we should send a 502.
            raise HttpError(code, "Invalid content-length header: %s"%headers["content-length"][0])
        if limit is not None and l > limit:
            raise HttpError(code, "HTTP Body too large. Limit is %s, content-length was %s"%(limit, l))
        content = rfile.read(l)
    elif all:
        content = rfile.read(limit if limit else -1)
    else:
        content = ""
    return content,len(content)


def read_http_body_request(rfile, wfile, headers, httpversion, limit):
    """
        Read the HTTP body from a client request.
    """
    if "expect" in headers:
        # FIXME: Should be forwarded upstream
        if "100-continue" in headers['expect'] and httpversion >= (1, 1):
            wfile.write('HTTP/1.1 100 Continue\r\n')
            wfile.write('\r\n')
            del headers['expect']
    return read_http_body(400, rfile, headers, False, limit)


def read_http_body_response(rfile, headers, limit):
    """
        Read the HTTP body from a server response.

    """
    if headers.has_key('connection'):
        all = "close" in get_header_tokens(headers, "connection")
    else:
        all=False
    return read_http_body(500, rfile, headers, all, limit)

def read_response(rfile, method, body_size_limit):
    """
        Return an (httpversion, code, msg, headers, content) tuple.
    """
    line = rfile.readline()
    print line
    if line == "\r\n" or line == "\n": # Possible leftover from previous message
        line = rfile.readline()
    if not line:
        raise HttpError(502, "Blank server response.")
    parts = line.strip().split(" ", 2)
    if len(parts) == 2: # handle missing message gracefully
        parts.append("")
    if not len(parts) == 3:
        raise HttpError(502, "Invalid server response: %s"%repr(line))
    proto, code, msg = parts
    httpversion = parse_http_protocol(proto)
    if httpversion is None:
        raise HttpError(502, "Invalid HTTP version in line: %s"%repr(proto))
    try:
        code = int(code)
    except ValueError:
        raise HttpError(502, "Invalid server response: %s"%repr(line))
    header,header_len = read_headers(rfile)
    if header is None:
        raise HttpError(502, "Invalid headers.")
    if code >= 100 and code <= 199:
        return read_response(rfile, method, body_size_limit)
    if method == "HEAD" or code == 204 or code == 304:
        content = ""
        content_len = 0
    else:
        content,content_len = read_http_body_response(rfile, header, body_size_limit)
    return line,httpversion, code, msg,header,header_len, content,content_len


def request_connection_close(httpversion, headers):
    if "connection" in headers:
        toks = get_header_tokens(headers, "connection")
        if "close" in toks:
            return True
        elif "keep-alive" in toks:
            return False
    if "proxy-connection" in headers:
        toks = get_header_tokens(headers, "proxy-connection")
        if "close" in toks:
            return True
        elif 'keep-alive' in toks:
            return False
    if httpversion == (1, 1):
        return False
    return True



def response_connection_close(httpversion, headers):
    """
        Checks the response to see if the client connection should be closed.
    """
    if request_connection_close(httpversion, headers):
        return True
    elif (not has_chunked_encoding(headers)) and "content-length" in headers:
        return False
    return True