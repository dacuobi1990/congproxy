import handler
import socket
import threading
class tcpserver(object):
	request_queue_size=20
	def __init__(self,server_address):
		self.server_address=server_address
		self.socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.bind(self.server_address)
		self.socket.listen(self.request_queue_size)

	def server_forever(self):
		lock=threading.Lock()
		serial=0
		thread_table=[0]
		while 1:
			try:
				clisock,cli_address=self.socket.accept()
			except socket.error:
				print 'sock failed'
				continue

			serial=serial+1
			thread_table[0]+=1
			url_table = {}
			t=threading.Thread(target=self.request_thread,args=(clisock,cli_address,lock,serial,thread_table,url_table))
			#t.setDaemon(True)
			t.start()


	def request_thread(self,clisock,cli_address,lock,num,thread_table,url_table):
		#try:
		h=handler.basehandler(clisock,cli_address,lock,num,thread_table,url_table)
		h.handle()
		#except ( filelike.NetLibError,filelike.NetLibDisconnect,filelike.NetLibTimeout),e:
			#print e,'request_thread',
			#return 
		#finally:
			#clisock.shutdown(socket.SHUT_WR)
			#clisock.close()

	def shut_down(self):
		self.socket.shutdown(socket.SHUT_RDWR)
		self.socket.close()



if __name__ == '__main__':
	host='127.0.0.1'
	port =8888
	ser=tcpserver((host,port))
	try:
		ser.server_forever()
	except KeyboardInterrupt:
		print 'main'
		print threading.enumerate()
		ser.shut_down()
		#return

			
				




