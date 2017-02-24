import sys
import socket
import threading

def server_loop(local_host, local_port, remote_host, remote_port, recieve_first):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		server.bind((local_host, local_port))

	except:
		print "[!] Failed to llisten on %s:%d" % (local_host, local_port)
		print "[!] Check for other listening sockets or correct permissions"
		sys.exit(0)

	print "[*] Listening on %s:%d" % (local_host, local_port)

	server.listen(5)

	while True:
		client_socket, addr = server.accept()

		# print out some info
		print "[==>] Recieved incoming connection from %s:%d" % (addr[0], addr[1])
		# new thread to talk to RHOST 
		proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, recieve_first))

		proxy_thread.start()


def main():
	# none of that fancy CMD handling, quick 'n dirty'
	if len(sys.argv[1:]) != 5:
		print "Usage: ./TCP-Proxy.py [localhost] [localport] [remotehost] [remoteport] [recievefirst]"
		print ", Example: ./TCP-Proxy 127.0.0.1 9000 10.12.132.1 9000 True"
		sys.exit(0)

	# local params 
	local_host = sys.argv[1]
	local_port = sys.argv[2]

	# remote params
	remote_host = sys.argv[3]
	remote_port = sys.argv[4]

	recieve_first = sys.argv[5]

	if "True" in recieve_first:
		recieve_first = True
	else:
		recieve_first = False

	server_loop(local_host, local_port, remote_host, remote_port, recieve_first)

main()
