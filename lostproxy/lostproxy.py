import threading
import argparse
import base64
import select
import socket
import os

# Initialize libraries
parser = argparse.ArgumentParser(description = "A multi functional proxy for HTTP, Socks4/4a and Socks5/5h all in one port.")

parser.add_argument("-l", "--listener", help = "Listening address, example: 0.0.0.0:8080")
parser.add_argument("-u", "--user", help = "(OPTIONAL) Username for auth, example: Jack")
parser.add_argument("-p", "--password", help = "(OPTIONAL) Password for auth, example: Password123")
parser.add_argument("-a", "--allow_localhost", help="(OPTIONAL) Allows localhost and other internal IP ranges.", action="store_true")

args = parser.parse_args()

# Static variables
PACKET_BUFFER = 65537
BAD_HEADERS = [
	b"proxy-authenticate",
	b"proxy-authorization",
	b"proxy-connection"
]


def relay_connection(client_socket, server_socket):
	socket_list = [client_socket, server_socket]
	should_close_socket = False
	try:
		while not should_close_socket:
			read_sockets, write_sockets, error_sockets = select.select(socket_list, [], socket_list, 5000)
			if error_sockets or not read_sockets:
				break
			for current_socket in read_sockets:
				opposite_socet = socket_list[1] if current_socket == socket_list[0] else socket_list[0]

				data = current_socket.recv(PACKET_BUFFER)
				if not data or data == b"":
					should_close_socket = True
					break
				opposite_socet.sendall(data)
	except:
		pass

def is_ip_local(ip_address):
	# Split IP in parts
	parts = ip_address.split('.')
	
	# Check if IP is valid
	if len(parts) != 4 or not all(part.isdigit() for part in parts):
		return False

	parts = [int(part) for part in parts]
	
	# Check for local IP
	if ((parts[0] == 0) or
		(parts[0] == 10) or
		(parts[0] == 172 and 16 <= parts[1] <= 31) or
		(parts[0] == 192 and parts[1] == 168) or
		(parts[0] == 127)):
		return True

	return False

class HTTPConnection():
	def __init__(self, server_config, init_packet, client_socket):
		# Parse the initial packet

		split_packet = init_packet.split(b"\r\n\r\n")

		self.data = split_packet[1]

		packet_lines = split_packet[0].split(b"\r\n")
		first_line_of_packet = packet_lines[0].split(b" ")

		self.method = first_line_of_packet[0]
		self.url = first_line_of_packet[1]
		self.http_version = first_line_of_packet[2]

		# Parse headers
		self.headers = {}

		was_host_found = False

		for header in packet_lines[1:]:
			split_header = header.split(b": ")

			# Get HOST
			if split_header[0].lower() == b"host":
				self.host_address = split_header[1]
				was_host_found = True

			self.headers[split_header[0]] = split_header[1]

		if not was_host_found:
			# Can't connect because the host header wasn't found, close the socket
			client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
			client_socket.close()
			return

		# Handle authentication
		if server_config.should_authenticate:
			for header in self.headers:
				if header.lower() == b"proxy-authorization":
					# Only support BASIC authentication
					if not self.headers[header].startswith(b"Basic "):
						client_socket.send(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
						client_socket.close()
						return

					# Decode the authentication token and compare it to username and password
					authentication_token = self.headers[header].split(b" ")[1]

					self.username, self.password = base64.b64decode(authentication_token).decode("utf-8").split(":")

					if (self.username, self.password) != server_config.authentication_parameters:
						client_socket.send(b"HTTP/1.1 401 Unauthorized\r\n\r\n")
						client_socket.close()
						return

		if self.method == b"CONNECT":
			# Handle HTTPS/TCPIP requests

			host_address_split = self.host_address.split(b":")

			self.host_address = host_address_split[0].decode("utf-8")
			self.requested_port = int(host_address_split[1])

			# Resolve domain
			self.ip_address = socket.gethostbyname(self.host_address)
			self.ip_bytes = socket.inet_aton(self.ip_address)

			# Do not allow localhost connections unless specified
			if not server_config.allow_localhost and is_ip_local(self.ip_address):
				client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
				client_socket.close()
				return

			# Create socket to server
			try:
				server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				server_socket.connect((self.ip_address, self.requested_port))
			except:
				# Connection failed
				client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
				client_socket.close()
				return

			# Send a successful response
			client_socket.send(b"HTTP/1.1 200 Connection established\r\nConnection: keep-alive\r\n\r\n")

			# Relay the connection
			relay_connection(client_socket, server_socket)
		else:
			# Handle HTTP requests

			# Get the protocol, if there isn't any, default to HTTP
			url_position = self.url.find(b"://")
			if (url_position == -1):
				url_no_protocol = self.url
			else:
				url_no_protocol = self.url[(url_position+3):]
			
			# Find the port
			position_of_port = url_no_protocol.find(b":")

			if position_of_port != -1:
				self.requested_port = int((url_no_protocol[(position_of_port+1):]).split(b'/')[0])
			else:
				self.requested_port = 80

			# Get location of url
			self.url_location = b"/" + url_no_protocol.split(b"/", 1)[1]

			# Filter headers
			self.filtered_headers = self.headers.copy()

			for bad_header in BAD_HEADERS:
				for header in self.headers:
					if header.lower() == bad_header:
						del self.filtered_headers[header]

			# Resolve domain
			self.ip_address = socket.gethostbyname(self.host_address)
			self.ip_bytes = socket.inet_aton(self.ip_address)

			# Do not allow localhost connections unless specified
			if not server_config.allow_localhost and is_ip_local(self.ip_address):
				client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
				client_socket.close()
				return

			# Create socket to server
			try:
				server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				server_socket.connect((self.host_address, self.requested_port))
			except:
				# Connection failed
				client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
				client_socket.close()
				return

			# Send method, url location and version
			server_socket.send(b" ".join([self.method, self.url_location, self.http_version]) + b"\r\n")

			# Send filtered headers
			for header in self.filtered_headers:
				server_socket.send(header + b": " + self.filtered_headers[header] + b"\r\n")

			# Send data
			server_socket.send(b"\r\n" + self.data)

			# Relay the connection
			relay_connection(client_socket, server_socket)


class Socks4Connection():
	def __init__(self, server_config, init_packet, client_socket):
		# Parse the initial packet

		self.version = init_packet[0]
		self.command = init_packet[1]
		self.requested_port = init_packet[2] * 256 + init_packet[3]
		self.requested_port_bytes = init_packet[2:4]
		self.user_id = init_packet[8:].split(b'\x00', 1)[0].decode("utf-8")
		self.ip_bytes = init_packet[4:8]
		self.ip_address = socket.inet_ntoa(self.ip_bytes)

		# Client is sending a socks4a packet, resolve the IP and continue
		if self.ip_address.startswith("0.0.0.") and not self.ip_address.endswith(".0"):
			# The domain is right at the end of the packet, just parse the last string
			self.domain_name = init_packet.split(b"\x00")[-2].decode('utf-8')

			# Resolve domain
			self.ip_address = socket.gethostbyname(self.domain_name)
			self.ip_bytes = socket.inet_aton(self.ip_address)

		# Handle authentication
		if server_config.should_authenticate and self.user_id.split("***") != list(server_config.authentication_parameters):
			client_socket.send(b"\x00\x5D")
			client_socket.close()
			return

		# Handle local IP blocking
		if not server_config.allow_localhost and is_ip_local(self.ip_address):
			client_socket.send(b"\x00\x5B")
			client_socket.close()
			return

		# Create socket to server
		try:
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.connect((self.ip_address, self.requested_port))
		except:
			# Connection failed
			client_socket.send(b"\x00\x5B")
			client_socket.close()
			return

		# Send success response and start relaying the connection
		client_socket.send(b"\x00\x5A" + self.requested_port_bytes + self.ip_bytes)

		relay_connection(client_socket, server_socket)

class Socks5Connection():
	def __init__(self, server_config, init_packet, client_socket):
		# Parse the initial packet

		self.version = init_packet[0]
		self.number_of_authentication_methods = init_packet[1]
		self.authentication_methods = init_packet[2:2+self.number_of_authentication_methods]

		# Handle authentication
		if server_config.should_authenticate:
			# If client doesn't support authentication through user and password, reject the connection
			if 0x02 not in self.authentication_methods:
				client_socket.sendall(b'\x05\xff')
				client_socket.close()
				return

			# Continue with authentication
			client_socket.sendall(b'\x05\x02')

			self.authentication_packet = client_socket.recv(PACKET_BUFFER)

			# If authentication version isn't 1, close the socket
			if self.authentication_packet[0] != 0x01:
				client_socket.close()
				return

			username_length = self.authentication_packet[1]
			password_length = self.authentication_packet[2+username_length]

			self.username = self.authentication_packet[2:2+username_length].decode("utf-8")
			self.password = self.authentication_packet[3+username_length:3+username_length+password_length].decode("utf-8")

			if (self.username, self.password) != server_config.authentication_parameters:
				# Authentication failed
				client_socket.sendall(b'\x01\x01')  # 0x01 version of the subnegotiation, 0x01 authentication failure
				client_socket.close()
				return

			# Authentication successful
			client_socket.sendall(b'\x01\x00')
		else:
			# No authentication
			client_socket.sendall(b'\x05\x00')

		# Recieve address
		self.address_packet = client_socket.recv(PACKET_BUFFER)

		# self.address_packet[0] is version, ignore it for now
		self.command = self.address_packet[1]

		if self.address_packet[2] != 0x00:
			# Reserved byte changed, not a standard socks5 stream, close connection
			client_socket.close()
			return

		self.address_type = self.address_packet[3]

		if self.address_type == 1:
			# Address is IPV4, convert it to a normal IP
			self.ip_bytes = self.address_packet[4:8]
			self.ip_address = socket.inet_ntoa(self.ip_bytes)
			self.requested_port_bytes = self.address_packet[-2:]
			self.requested_port = self.address_packet[-2] * 256 + self.address_packet[-1]
		elif self.address_type == 3:
			# Address is a domain name, get it
			domain_size = self.address_packet[4]
			self.domain_name = self.address_packet[5:5+domain_size]

			# And finally, resolve it
			self.ip_address = socket.gethostbyname(self.domain_name)
			self.ip_bytes = socket.inet_aton(self.ip_address)
			self.requested_port_bytes = self.address_packet[-2:]	
			self.requested_port = self.address_packet[-2] * 256 + self.address_packet[-1]
		else:
			# Address type is not support (IPV6, etc), close connection
			client_socket.close()
			return

		# Do not allow localhost connections unless specified
		if not server_config.allow_localhost and is_ip_local(self.ip_address):
			client_socket.close()
			return

		# Create socket to server
		try:
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.connect((self.ip_address, self.requested_port))
		except:
			# Connection failed
			client_socket.close()
			return

		# Send success response and start relaying the connection
		client_socket.send(b"\x05\x00\x00\x01" + self.ip_bytes + self.requested_port_bytes)

		relay_connection(client_socket, server_socket)

class MultiProxyServer:
	http_methods_bytes = [
		b"GET",
		b"HEAD",
		b"POST",
		b"PUT",
		b"DELETE",
		b"CONNECT",
		b"OPTIONS",
		b"TRACE",
		b"PATCH"
	]

	def __init__(self, allow_localhost, authentication_parameters=None):
		self.allow_localhost = allow_localhost
		self.should_authenticate = authentication_parameters != (None, None)
		self.authentication_parameters = authentication_parameters

	def connection_thread(self, conn, addr):
		try:
			# Get the first packet and analyze what type of proxy it is

			firstPacket = conn.recv(PACKET_BUFFER)

			if firstPacket.split(b" ",1)[0] in self.http_methods_bytes:
				# Handle HTTP

				HTTPConnection(self, firstPacket, conn)
			elif firstPacket[0] == 0x04:
				# Handle Socks4/4a

				Socks4Connection(self, firstPacket, conn)
			elif firstPacket[0] == 0x05:
				# Handle Socks5/5h

				Socks5Connection(self, firstPacket, conn)
			else:
				# We don't know the protocol used, raise an exception
				raise Exception("No known protocol used.")
		except:
			# Suppress errors
			pass

	def start(self, host, port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((host, port))
		sock.listen()

		print("[SYSTEM] Started listening on "+host+":"+str(port))

		# Listen forever
		while True:
			conn, addr = sock.accept()
			threading.Thread(target=self.connection_thread, args=(conn, addr)).start()

def controlc_handler():
	while True:
		try:
			# Create input, if user CTRL-C's this will error out
			input("")
		except:
			print("[SYSTEM] Exiting...")
			os._exit(0)

def run():
	if args.listener == None:
		parser.print_help()
		os._exit(1)

	# Parse host and port
	try:
		host, port = args.listener.split(":")
		port = int(port)
	except:
		parser.print_help()
		os._exit(1)

	# If either username or password have not been supplied, warn the user
	if (args.user == None) != (args.password == None):
		print("[WARNING] Invalid pair of authentication parameters supplied. Server will start without authentication.")
		args.user = None
		args.password = None

	# Warn the user about Socks4 authentication
	if args.user != None and args.password != None:
		print("[WARNING] Socks4/4a doesn't support USER:PASS authentication, the username and password will be split by \"***\", so for example you would connect as socks4://username***password@IP:PORT.")

	# Start the CTRL+C handler
	threading.Thread(target=controlc_handler).start()

	# Start the server
	MultiProxyServer(args.allow_localhost, authentication_parameters=(args.user, args.password)).start(host, port)

if __name__ == '__main__':
	run()