from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
import time
import os
import signal


profile = webdriver.FirefoxProfile()
profile.set_preference('network.proxy.type',1)
profile.set_preference('network.proxy.http','127.0.0.1')
profile.set_preference('network.proxy.http_port',8888)
profile.set_preference('network.proxy.ssl','127.0.0.1')
profile.set_preference('network.proxy.ssl_port',8888)
profile.native_events_enabled = True
dd= webdriver.Firefox(profile)
#dd.maximize_window()


f=open("dst_url.txt","r")

def sig_deal(signum,frame):
	global f
	global dd
	url = f.readline().strip()
	if not url:
		os.kill(0,signal.SIGINT)
		os._exit(0)
	dd.get(url)

signal.signal(signal.SIGUSR1,sig_deal)

num = os.getpid()
print num

pid = os.fork()
if pid ==0:
	#os.popen("python server.py")
	print "father",num
	os.system("python server.py %s"%str(num))
	print "server over"

else:
	time.sleep(1)
	url = f.readline().strip()
	dd.get(url)
	while 1:
		pass





