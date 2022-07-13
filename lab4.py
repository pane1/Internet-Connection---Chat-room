#!/usr/bin/env python
import argparse
import socket
import sys
import struct
import random
import threading
import time

CMD_SIZE = 1 # 1 byte
USER_SIZE = 64
RX_IFACE_ADDRESS = "0.0.0.0"

# Server code
class Server:
    HOSTNAME = "127.0.0.1"
    PORT = 50000
    BUFFER_SIZE = 1024
    MAX_BACKLOG = 5
    ENCODER = "utf-8"

    SOCKET_ADDR = (HOSTNAME, PORT)

    def __init__(self):
    	self.roomlist = {}
    	self.create_listen_socket()
    	self.process_connections_forever()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
            self.socket.bind(Server.SOCKET_ADDR)
            self.socket.listen(Server.MAX_BACKLOG)
            print("(Chat Room Directory Server) Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                threading.Thread(target=self.connection_handler, args=(self.socket.accept(), )).start()
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, addr_port = client
        print("-"*72)
        print("Connection with {}".format(addr_port))
        print(client)
        
        while True:
            try:
                recv_bytes = connection.recv(Server.BUFFER_SIZE)
                if len(recv_bytes) == 0:
                    print("Closing client connection...")
                    connection.close()
                    break
                recv_str = recv_bytes.decode(Server.ENCODER)
                recv = recv_str.split()
                if recv[0] == "getdir":
                    print("Received: getdir command.")
                    pkt = ""
                    for room in self.roomlist.values():
                    	roominfo = room.get_vars()
                    	pkt += f"Name:{roominfo[0]} IP:{roominfo[1]} Port:{roominfo[2]}\n"
                    if pkt == "":
                        pkt = "No rooms currently available."
                    pkt = pkt.encode(Server.ENCODER)
                    connection.sendall(pkt)
                    	
                elif recv[0] == "makeroom":
                    print("Received: makeroom command.")
                    pkt = ""
                    for room in self.roomlist.values():
                    	roominfo = room.get_vars()
                    	if(roominfo[0] != recv[1] and roominfo[1] == recv[2] and roominfo[2] == int(recv[3])):
                    	    pkt = "IP and Port already exists."
                    
                    if pkt == "":
                    	pkt = "Successfully created a chatroom."
                    	self.roomlist[recv[1]] = Room(recv[1], recv[2], recv[3])
                    
                    pkt = pkt.encode(Server.ENCODER)
                    connection.sendall(pkt)
                    
                elif recv[0] == "deleteroom":
                    print("Received: deleteroom command.")
                    self.roomlist.pop(recv[1])
            
            except KeyboardInterrupt:
                print()
                print("ERROR: Closing client connection due to error...")
                connection.close()
                break

class Room:

    def __init__(self, name, ip, port):
    	self.name = name
    	self.ip = ip
    	self.port = int(port)

    def get_vars(self):
        return (self.name, self.ip, self.port)

# Client code
class Client:
    RECV_ADDRESS = ""
    TTL = 1

    def __init__(self):
    	self.name = f"User{random.randint(0, 100)}"
    	self.get_socket()
    	self.local_prompt()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)
            
    def local_prompt(self):
        while True:
            self.terminalInput = input(f"{self.name}[local] Enter command: ")
            if self.local_input() == None:
                break
                
    def global_prompt(self):
        while True:
            self.terminalInput = input(f"{self.name}[CRDS] Enter command: ")
            if self.CRDS_input() == None:
                break
    
    def local_input(self):
        inputs = self.terminalInput.split()
        if (len(inputs) > 0):
            userInput = inputs[0].lower()
            if(userInput == "quit"):
            	return None
            elif(userInput == "connect"):
            	if self.socket._closed:
            	    self.get_socket()
            	self.connect_to_server()
            	self.global_prompt()
            	return True
            elif(userInput == "name"):
            	if (len(inputs) > 1):
            	    self.name = inputs[1]
            	else:
            	    print("ERROR: Please enter a proper name.")
            	return True
            elif(userInput == "chat"):
            	chatrooms = self.handle_getdirchat()
            	if(chatrooms == None):
            	    print("ERROR: Invalid room name.")
            	    return True
            	chatroom = chatrooms.get(inputs[1])
            	if chatroom != None:
            	    self.chatroom_name = inputs[1]
            	    self.handle_chat(chatroom)
            	else:
            	    print("ERROR: Invalid room name.")
            	    self.socket.close()
            	return True
    
    def CRDS_input(self):
        inputs = self.terminalInput.split()
        if (len(inputs) > 0):
            userInput = inputs[0].lower()
            if(userInput == "makeroom"):
            	try:
                    self.handle_makeroom(inputs[1], inputs[2], inputs[3])
                    self.handle_getdir()
            	except:
            	    print("ERROR: Invalid makeroom command.")
            	return True
            elif(userInput == "getdir"):
            	self.handle_getdir()
            	return True
            elif(userInput == "deleteroom"):
            	try:
            	    self.handle_deleteroom(inputs[1])
            	except:
            	    print("ERROR: Invalid deleteroom command.")
            	return True
            elif(userInput == "bye"):
            	self.socket.close()
            	return None
            else:
            	print("ERROR: Invalid command.")
            	return True
            	
            	
    def handle_getdir(self):
        sendv_str = "getdir"
        self.socket.sendall(sendv_str.encode(Server.ENCODER))

        recv_bytes = self.socket.recv(Server.BUFFER_SIZE)
        recv_str = recv_bytes.decode(Server.ENCODER)
        
        print(f"Server Response:\n{recv_str}")
        
    def handle_getdirchat(self):
        sendv_str = "getdir"
        if self.socket._closed:
            self.get_socket()
        self.connect_to_server()
        self.socket.sendall(sendv_str.encode(Server.ENCODER))

        recv_bytes = self.socket.recv(Server.BUFFER_SIZE)
        recv_str = recv_bytes.decode(Server.ENCODER)
        self.socket.close()
        
        chatrooms = recv_str.split("\n")
        chatrooms_dict = {}
        for chatroom in chatrooms:
            if len(chatroom) > 0:
            	data = chatroom.split(" ")
            	try:
            	    name = data[0].split(":")[1]
            	    ip = data[1].split(":")[1]
            	    port = data[2].split(":")[1]
            	    chatrooms_dict[name] = (ip, int(port))
            	except:
            	    return
        return chatrooms_dict
        
    def handle_makeroom(self, name, ip, port):
        pkt = f"makeroom {name} {ip} {port}".encode(Server.ENCODER)

        self.socket.sendall(pkt)
        
        recv_bytes = self.socket.recv(Server.BUFFER_SIZE)
        recv_str = recv_bytes.decode(Server.ENCODER)
        
        print(f"Server Response:\n{recv_str}")
        
    def handle_deleteroom(self, name):
        cmd = "deleteroom ".encode(Server.ENCODER)
        args = name.encode(Server.ENCODER)
        pkt = cmd + args

        self.socket.sendall(pkt)
        
    def handle_chat(self, chatroom):
        self.chatroom = chatroom
        self.create_rec_socket(chatroom[0], chatroom[1])
        rec_lock = threading.Lock()
        
        self.rec_thread = threading.Thread(target=self.rec_messages, args=(rec_lock,))
        self.rec_thread.daemon = True # Make the thread run in the background even after main thread exits
        self.rec_thread.start()
        self.user_chat(rec_lock, chatroom)
        self.rec_thread.do_run = False # Stop the thread
    
    def create_rec_socket(self, multicast_addr, multicast_port):
        try:
            self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            ############################################################
            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that determines what packets make it to the
            # UDP app.
            ############################################################
            self.recv_socket.bind(('0.0.0.0', multicast_port))
            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces. They must be in network
            # byte order.
            ############################################################
            multicast_group_bytes = socket.inet_aton(multicast_addr)
            # print("Multicast Group: ", self.multicast_addr)

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes
            # print("multicast_request = ", multicast_request)

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            #print("Adding membership (address/interface): ", multicast_addr,"/", RX_IFACE_ADDRESS)
            print()
            self.recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print("Method create_receiver_socket(): ", msg)
            sys.exit(1)


    def rec_messages(self, output_lock):
        t = threading.currentThread()
        while getattr(t, "do_run", True):
            data, address_port = self.recv_socket.recvfrom(Server.BUFFER_SIZE)
            if (getattr(t, "do_run", True) == False):
            	break
            data_str = data.decode(Server.ENCODER)
            person = data_str[:USER_SIZE].rstrip()
            if (person != self.name):
                msg = data_str[USER_SIZE:]
                output_lock.acquire()
                print(f"{person}@{self.chatroom_name}: {msg}")
                output_lock.release()
                
    def user_chat(self, output_lock, chatroom):
    
        try:
            print(f"You have entered chatroom: {self.chatroom_name} (Use ctrl+c to exit)")
            while True:
                self.terminalInput = input()
                print(f"\033[Ayou@{self.chatroom_name}: {self.terminalInput}")

                pkt = self.name.ljust(USER_SIZE) + self.terminalInput
                
                self.recv_socket.sendto(pkt.encode(Server.ENCODER), chatroom)
        except KeyboardInterrupt:
            print()
                
    def connect_to_server(self):
        try:
            self.socket.connect((Server.HOSTNAME, Server.PORT))
            print("Connected to \"{}\" on port {}".format(Server.HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

#terminal run code    
if __name__ == "__main__":
    roles = {'client': Client, 'server': Server}

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--role', choices=roles,
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()


