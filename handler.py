import filelike
import request
import threading
import certutils
from OpenSSL import SSL
import os
import traceback
import ssl
import socket
import time
import urltree
import Cookie
import signal
import sys
class client(object):
	def __init__(self,addr,num):
		self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.sock.settimeout(5)
		self.rfile=filelike.Reader(self.sock.makefile('rb','-1'))
		self.wfile=filelike.Writer(self.sock.makefile('wb','-1'))
		#self.wfile=self.sock.makefile('wb','-1')
		self.num=num
		self.addr=addr
		
	def connect(self):
		try:
			self.sock.connect(self.addr)
			return True
		except socket.error,v:
			print v
			return False

	def convert_to_ssl(self):
		self.sock=ssl.wrap_socket(self.sock,cert_reqs=ssl.CERT_NONE)
		self.rfile=filelike.Reader(self.sock.makefile('rb','-1'))
		self.wfile=filelike.Writer(self.sock.makefile('wb','-1'))
		self.sock.settimeout(5)


	def shutdown(self):
		try:
			self.sock.shutdown(socket.SHUT_RDWR)
		except:
			pass
		self.sock.close()





class basehandler(object):
	def __init__(self,clisock,cli_address,lock,num,thread_table,url_table):
		self.clisock=clisock
		self.clisock.settimeout(5)
		self.rfile=filelike.Reader(self.clisock.makefile('rb','-1'))
		self.wfile=filelike.Writer(self.clisock.makefile('wb','-1'))
		#self.wfile=self.clisock.makefile('wb','-1')
		self.num=num
		self.lock=lock
		self.sersock=None
		self.is_ssl=False
		self.keepalive=True
		self.sni=None
		self.info=[]
		self.info.append(self.num)
		self.thread_table = thread_table
		self.url_table = url_table

	def deal_header(self,header,c_len):
		referer = None
		if header.has_key('transfer-encoding'):
			
			del header['transfer-encoding']
			header['content-length']=[str(c_len)]
		if header.has_key('proxy-connection'):
			h_c=header['proxy-connection'][0]
			del header['proxy-connection']
			header['connection']=[h_c]
		if header.has_key('if-modified-since'):
			#print '~~~~~~~~~~~~~~'
			del header['if-modified-since']

		if header.has_key('if-none-match'):
			#print '~~~~~~~~~~~~~~'
			del header['if-none-match']

		if header.has_key('last-modified'):
			del header['last-modified']

		if header.has_key('referer'):
			referer = header['referer'][0]

		if header.has_key('set-cookie'):
			print 'set-cookie:',header['set-cookie']
			#ckie = Cookie.SimpleCookie()
			#ckstr=''
			#for i in header['set-cookie']:
				#ckstr=ckstr+i+'\r\n'
			#ckie.load(ckstr)
			#print 'ckie',ckie.output()

		if header.has_key('cache-control'):
			header['cache-control'] = ['no-cache']

		if not header.has_key('cache-control'):
			header['cache-control'] = ['no-cache']

		if header.has_key('expires'):
			del header['expires']

		if header.has_key('cookie'):
			print 'cookie:',header['cookie']


		head_content=''
		for key in header:
			if key =='set-cookie':
				ckie = Cookie.SimpleCookie()
				ckstr=''
				for i in header[key]:
					ckstr=ckstr+i+'\r\n'
				ckie.load(ckstr)
				s=ckie.output()
				s=s+'\r\n'
				head_content+=s

			else:
				for ele in header[key]:
					s=key.strip()+':'+ele.strip()+'\r\n'
					head_content+=s

		head_content+='\r\n'
		return head_content,referer


	def find_cert(self, host, port):
		sans = []
                try:
                    cert = certutils.get_remote((host, port))
                except :
                	print traceback.print_exc()
                	return
                if not cert:
                	return None
                sans = cert.altnames
                host = cert.cn.decode("utf8").encode("idna")
                ret = certutils.dummy_cert( 'certdir','ca/mitmproxy-ca.pem',host, sans)
                
                return ret
	


	def convert_to_ssl(self,cert,cakeypath):
		if not os.path.exists(cakeypath):
			print self.num, 'no cakeypath'
			return 

		try:
			self.clisock=ssl.wrap_socket(self.clisock,keyfile=cakeypath,certfile=cert,server_side=True,ssl_version=ssl.PROTOCOL_SSLv23)
		except:
			print self.num
			print traceback.print_exc()
			return 

		self.rfile=filelike.Reader(self.clisock.makefile('rb','-1'))
		#self.wfile.set_descripor(self.clisock)
		self.wfile=filelike.Writer(self.clisock.makefile('wb','-1'))
		self.clisock.settimeout(5)
		self.is_ssl=True






	def read_request(self):
		line=request.get_line(self.rfile)
		#print self.num,'!!'+line+'!!'
		if not line:
			print self.num,'no line '
			return None
		header,head_len=request.read_headers(self.rfile)
		#print self.num,'!!',header,'!!'
		if not header:
			print self.num,'no header'
			return None
		method,url,protocol=request.parse_line(line)
		#print method,url,protocol
		scheme =None
		host=None
		port =None
		path=None
		http_version=request.parse_http_protocol(protocol)
		#print scheme,host,port, path,http_version

#content,content_len=request.read_http_body_request(self.rfile,self.wfile, header, http_version, limit)
		
		if method=='CONNECT' :
			#change to ssl

			try:
				host,port=url.split(':') #host port
			except ValueError:
				return None
			port=int(port)
			scheme='https' # https
			
			with self.lock:
				print '*'*40
				print self.num
				print line
				head_content,referer=self.deal_header(header,None)
				print head_content
				print '*'*40

			re= 'HTTP/1.1 200 Connection established\r\n' +'\r\n'
			with self.lock:
				print '--------------------'
				print self.num
				print re,
				print '--------------------'

			self.clisock.sendall(re)
			print self.num,'write back'

			certpath=self.find_cert(host,port)
			if not certpath:
				print self.num
				print 'failed to generate certpath'
				return None

			self.convert_to_ssl(certpath,'ca/mitmproxy-ca.pem')
			if self.is_ssl == False:
				print self.num,'failed to convert to ssl'
				return None
			print 'done'

			line=request.get_line(self.rfile)

			if not line:
				return None
			header,header_len=request.read_headers(self.rfile)
			if not header:
				return None

			method,url,protocol=request.parse_line(line)
			try:
				content,content_len=request.read_http_body_request(self.rfile,self.wfile, header, http_version, None)
			except request.HttpError,v:
				print str(v)
				print self.num,'content read failed'
				return None

			request_len=len(line)+head_len+content_len
			head_content,referer=self.deal_header(header,content_len)
			request_content=line+head_content+content
			return request_content,request_len,scheme,host,port,method,url,referer




		else:
			if self.is_ssl==True:
				with self.lock:
					print 'what ? no connect but ssl is true?'
					print self.num
					print url

				try:
					content,content_len=request.read_http_body_request(self.rfile,self.wfile, header, http_version, None)
				except request.HttpError,v:
					print str(v)
					print self.num,'content read failed'
					return None

				request_len=len(line)+head_len+content_len
				head_content,referer=self.deal_header(header,content_len)
				request_content=line+head_content+content
				with self.lock:
					print '!!!!',self.num,scheme,host,port,method,url,referer
				return request_content,request_len,scheme,host,port,method,url,referer

			else:
				try:
					scheme, host, port, path=request.parse_url(url)
					content,content_len=request.read_http_body_request(self.rfile,self.wfile, header, http_version, None)
				except request.HttpError,v:
					print str(v)
					print self.num,'content read failed'
					return None

				#new_line =method +' '+path+' '+ protocol+'\r\n'
				#new_line = line
				p = line.find('HTTP')
				proto = line[p:]
				new_line = method+' '+path+' '+proto
				request_len=len(line)+head_len+content_len
				head_content,referer=self.deal_header(header,content_len)
				request_content=new_line+head_content+content


				return request_content,request_len,scheme,host,port,method,url,referer


	def handle_request(self):
		#self.info.append(self.num)
		try:
			re=self.read_request()
		except socket.timeout:
			print 'time out'
			self.keepalive = False
			return
		if not re:
			with self.lock:
				print self.num,'read request failed'
			self.keepalive=False
			return
		request_content,request_len,scheme,host,port,method,req_url,referer=re


		if self.sersock==None and host:
			src_addr=self.clisock.getpeername()
			k=(src_addr[0],str(src_addr[1]),host,str(port))
			self.info.append(k)
			dst_addr=(host,port)
			self.sersock=client(dst_addr,self.num)
			ifseccess=self.sersock.connect()
			if ifseccess==False:
				print self.num,'connect failed'
				self.keepalive=False
				return

		if self.sersock == None and not host:
			print 'no sersock and no dst host??'
			self.keepalive = False
			return

		if scheme == 'https' and  host:
			try:
				self.sersock.convert_to_ssl()
			except:
				print self.num
				print 'sersock convert to ssl failed'
				print traceback.print_exc()
				self.keepalive= False
				return

		urlhost = self.sersock.addr[0]
		if scheme == 'https':
			req_url = urlhost+req_url



		with self.lock:
			print '*'*40
			print 'thread num is %d' % self.num
			print 'the request length is %d'%request_len
			print request_content,
			print 'the referer is',referer
			print '*'*40
			if referer:
				#self.url_table[req_url]  = referer
				urltree.insert(req_url,referer)
				print 'has_referer'

			else :
				#self.url_table[req_url] = 'empty'
				print 'not_has_referer'
				urltree.insert(req_url,'empty')
				print 'has_referer'

			print urltree.re_len()




		
		try:
			self.sersock.sock.sendall(request_content)
		except :
			print 'write failed'
			print traceback.print_exc()
			self.keepalive=False
			return

		#r=self.sersock.rfile.readline()

		#r=self.sersock.sock.recv(4096)
		#print self.num
		#print r
                
		try:
			r=request.read_response(self.sersock.rfile,method,None)
		except:
			print self.num,'read_response failed'
			print traceback.print_exc()
			self.keepalive=False
			return 

		line,httpversion, code, msg,header,header_len, content,content_len=r
		response_len=len(line)+header_len+content_len
		head_content,referer=self.deal_header(header,content_len)
		response_content=line+head_content+content
		self.info.append((req_url,request_len,response_len))
		with self.lock:
			print '*'*40
			print 'thread num is %d' % self.num
			print 'the response length is %d'% response_len
			print line+head_content
			print '*'*40
		
		
		try:
			self.clisock.sendall(response_content)
		except:
			print self.sum,'response back failed'
			print traceback.print_exc()
			self.keepalive=False
			return 

		print 'put '
		
		#print self.num,len(self.info)
		if request.request_connection_close(httpversion,header) ==True:
			self.keepalive=False
			return


		if request.response_connection_close(httpversion, header) == True:
			self.keepalive=False
			return 
		


	def shutdown(self):
		try:
			self.clisock.shutdown(socket.SHUT_RDWR)
		except :
			pass
		self.clisock.close()



	def handle(self):
		while self.keepalive == True:
			self.handle_request()
		self.shutdown()
		if self.sersock:
			self.sersock.shutdown()
		with self.lock:
			f=open('result.txt','a')

			for i in self.info:
				i= str(i)
				f.write(i+'\n')

			#f.write(str(self.info)+'\n')
			f.write('-'*20+'\n')
			f.close()

			self.thread_table[0]-=1
			print self.thread_table[0]
			time.sleep(0.1)
			if self.thread_table[0] ==0:
				f=open('url.txt','a')
				urltree.write_file(f)
				f.write(time.ctime()+'\n')
				f.write('-'*20+'\n')
				f.close()

				f=open('tree.txt','a')
				urltree.build_tree(f)
				f.write('-----------'+time.ctime()+'---------'+'\n')
				f.close()

				f=open('result.txt','a')
				f.write('-----------'+time.ctime()+'---------'+'\n')
				f.write('\n\n\n')
				f.close()

				print 'done'
				num = sys.argv[1]
				print num
				os.kill(int(num),signal.SIGUSR1)
				
				pass
				# send signal

				












	



		


