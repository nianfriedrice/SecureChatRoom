# SecureChatRoom

Secure Chat Room Application
Authors
-------
12250899 - Rachel R X Liang
12251119 - Sisi Rao 		

What is it?
-----------
This is a simple client-server based Java chatting program. It is designed to guarantee a secure
 chat between server and other clients which holds Confidentiality, Integrity, Authenticity and 
 Non-repudiation. This program uses SSL for connection and uses BouncyCastle library to generate
 certificates for authentication. RSA is used as the algorithm for Encryption and Decryption.

In this package, there are two sub-directories:

  - server -- source code to the chat server
  - client -- source code to the tty-based chat client
  

Package structure and class functions
-------------------------------------
ChatRoom
	-lib (external library)
	-src (source code)
		- server(chat server source code)
			-- ChatServer.java (Capable of establishing connection and transferring message)
			-- ChatServerThread.java (Capable of handling connection of each thread)
			-- ServerKeyController.java (Key and certificate management)
			-- Siger.java (Capable of creation of certificates of a chat room with users' public key)
		- client(chat client source code)
			-- ChatServer.java (Capable of establishing connection with server and handling user request)
			-- ChatServerThread.java (Capable of handling connection of each thread)
			-- ClientKeyController.java (Generate user key pair and import certificate of chat rooms)
		-Data(Generated automatically in runtime)

Security Design
---------------
Communication flow:

***Server Side******************								***Client Side**************
Generate keypair 												Generate a keypair 
and server certificate											
==============================	Start Program			==============================

									User public key (file)
								<<<----------------------- 
									(Offline)
									  
									1. signed-certificate
									2. server certificate
certificate (User public key)	----------------------->>>		import server certificate
									(offline)
									  
============================== 	Complete Preparation		==============================
Wait for client													Create a SSL connection 
																using server certificate
============================== 	SSL Connection Established	==============================

									signed-certificate
								<<<-----------------------
									(network)
									
								   E(public key, Random Number)
Verify certificate				----------------------->>>		Decrypt with user's public key
									(network)
									
									decrypted random number
Verify decrypted number			<<<-----------------------     
								    (network)
==============================	Authentication Complete		==============================
==============================	Start Communication			==============================
							
System-specific Notes
---------------------
The ChatServer and the ChatClient are tty-based (i.e., it should be run
 in text-mode).

Start multiple chat clients (on different ttys) to chat through the chat
room.

Server Side Configuration
-------------------------
Unzip chatroom.rar file and cd to src folder:
1.Compile the files in the "server" directory:

  javac -cp .;..\lib\* server\*.java

2.Create or Start the server by inputting the following in command prompt:

	java -cp .;..\lib\* server.ChatServer chatroomName host port_num
	
Note: 
      One server can have multiple chat rooms with unique names.
	  "host" : the name or IP address of the server.
	  "port_num": The port number used by the server to wait for chat 
	  clients' connection.
	  

3. Create certificate for userA in chatroomA:
Change public key file name to chatroomA-userA.key and input the following 
in command prompt:

	java -cp .;..\lib\* server.Signer path\of\publickeyFolder

Note:
	Default publick key folder: Data

Client Side Configuration
-------------------------
Unzip chatroom.rar file and cd to src folder:
1.Compile the following files in the "client" directory:

  javac -cp .;..\lib\* client\*.java

2. Using as a new user:

  java -cp .;..\lib\* client.ClientKeyController username

3.Enter a chat room

  java -cp .;..\lib\* client.ChatClient username chatroomName

Note: "username": Need to be the same as used in the Step 2.
	  "chatroomName": To enter a chatroom, you need 2 certificate in the Data folder: 
						1. Server certificate; 
						2. Signed certificate.
	  
Sample Test cases
---------------
Setting:
	Chatroom name		:	sampleChatroom
	username			:	sisi
	Server Port number	:	5432
	Server host			:	localhost

Server Side:
	After complied
	Input command: java -cp .;..\lib\* server.ChatServer sampleChatroom localhost 5432

Expected output:
1. Common-Line window output:
  | Creating keystore...
  | Creation Complete.
  | public key: 
  | (public key)
  | Please find server certificate in Data\sampleChatroom.cer
  | Binding to port 5432, please wait  ...
  | Server started: [SSL: ServerSocket[addr=0.0.0.0/0.0.0.0,localport=5432]]
  | Waiting for a new client...
  
  (When a client connect to the server)
  
  | Completed handshake!!!
  | Start authentication...
  | Authentication completed for sisi
  | Client accepted: 544164f8[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Socket[addr=/127.0.0.1,port=51984,localport=8080]]
  | Message sent to the client is: Client sisi enters the chat room.
  | Server Thread 51984 running.
  | total: 50

2．Under Data folder you can see:
  | server.keystore
  | sampleChatroom.cer
  

Client Side:
	After complied
	Input command:   java -cp .;..\lib\* client.ClientKeyController sisi

Expected output:
1. Common-Line window output:
  | Creating keystore...
  | Creation Complete.
  | public key: 
  | (public key)
  | Please find your public key file under Data folder.
 2．Under Data folder you can see:
  | sisi.keystore
  | sisi.key
  	
Offline operation: 
	copy sisi.key to server Data folder
	change the name to sampleChatroom-sisi.key
 
Server Side:
	Sign certificate with the following command:
	Input command:   java -cp .;..\lib\* server.Signer Data
	
Expected output:
1. Common-Line window output:
  | Certificate created: Data\sampleChatroom-sisi.cer
2．Under Data folder you can see:
  | sampleChatroom-sisi.cer

Offline operation: 
	copy sampleChatroom-sisi.cer and sampleChatroom.cer to client Data folder

Client Side:
	Start connection by using the following command:
	Input command:   java -cp .;..\lib\* client.ChatClient sisi sampleChatroom
	
Expected output:
1. Common-Line window output:
  | Certificate created: Data\sampleChatroom-sisi.cer
2．Under Data folder you can see:
  | Loading keystore...
  | Loading Complete.
  | Establishing connection. Please wait ...
  | Connected: 17f6480[SSL_NULL_WITH_NULL_NULL: Socket[addr=localhost/127.0.0.1,port=51984,localport=5432]]
  | Complete Handshake
  | Enter Chat room Successfully!!
  | Client sisi enters the chat room.
  | Current user in the chatroom: 1
  |   sisi
  |(You can type here to send msg to the chat room)
  
 Commands can be used in the chat room:
   .bye: to leave the chat room
   .list: to display the current users in the chat room
