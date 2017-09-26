package server;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * Created by LRX RSS on 2016/11/27.
 */
public class ChatServer implements Runnable, HandshakeCompletedListener
{  private ChatServerThread clients[] = new ChatServerThread[50];
   private SSLServerSocket server = null;
   private volatile Thread  thread = null;
   private int clientCount = 0;
   private ServerKeyController keyCon = null;

   //Initiate a chat room
   public ChatServer(String name, String host, int port)
   {
      try{
          keyCon = new ServerKeyController(name, host, port);
          System.out.println("Binding to port " + port + ", please wait  ...");
          server = createSSLSocket(port);
          System.out.println("Server started: " + server);
          start();
      }
      catch(IOException ioe)
      {  System.out.println("Can not bind to port " + port + ": " + ioe.getMessage()); }
      catch(KeyStoreException e)
      { System.out.println("KeyStoreException: "+ e.getMessage());}
      catch(Exception e)
      { System.out.println("SSL Socket Established Exception: "+ e.getMessage());}
   }

   private SSLServerSocket createSSLSocket(int port) throws  Exception{
      SSLContext sslContext = SSLContext.getInstance("TLSv1");
      sslContext.init(keyCon.getKeyManagers(), null, null);
      SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
      SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
      return sslServerSocket;
   }

   public void run()
   {  Thread thisThread = Thread.currentThread();
      while (thread == thisThread)
      {  try
         {
            System.out.println("Waiting for a new client...");
            SSLSocket client = (SSLSocket) server.accept();
            client.addHandshakeCompletedListener(this);
            client.startHandshake();
         }
         catch(IOException ioe)
         {  System.out.println("Server accept error: " + ioe); stop(); }
      }
   }


   public void start()
   {  if (thread == null)
      {  thread = new Thread(this); 
         thread.start();
      }
   }
   public void stop()
   {  if (thread != null)
      {  thread = null;
      }
   }
   private int findClient(int ID)
   {  for (int i = 0; i < clientCount; i++)
         if (clients[i].getID() == ID)
            return i;
      return -1;
   }
   public synchronized void handle(int ID, String input)
   {  if (input.equals(".bye"))
      {  clients[findClient(ID)].send(".bye");
         remove(ID); }
      else if (input.equals(".list"))
      {
         int count = clients.length;
         clients[findClient(ID)].send("Current user in the chatroom: " + clientCount);
         System.out.println("total: " + count);
         for(int i=0 ; i< clientCount;i++)
         {
            if(clients[i] != null) {
               clients[findClient(ID)].send("  "+clients[i].getClientName());
            }
         }
      }
      else
         for (int i = 0; i < clientCount; i++)
            clients[i].send(clients[findClient(ID)].getClientName() + ": " + input);
   }

   public synchronized void remove(int ID)
   {  int pos = findClient(ID);
      if (pos >= 0)
      {
         String cname = clients[pos].getClientName();
         ChatServerThread toTerminate = clients[pos];
         System.out.println("Removing client thread " + ID + " at " + pos);
         if (pos < clientCount-1)
            for (int i = pos+1; i < clientCount; i++)
               clients[i-1] = clients[i];
         clientCount--;
         try
         {  toTerminate.close();  }
         catch(IOException ioe)
         {  System.out.println("Error closing thread: " + ioe); }
         toTerminate.stopThread();
         broadcast(cname, " leaves");
      }

   }

   protected void addThread(Socket socket, String name)
   {
      if (clientCount < clients.length)
      {
         System.out.println("Client accepted: " + socket);
         clients[clientCount] = new ChatServerThread(this, socket, name);
         try
         {  clients[clientCount].open();
            clients[clientCount].start();
            clientCount++;
         }
         catch(IOException ioe)
         {  System.out.println("Error opening thread: " + ioe); } }
      else
         System.out.println("Client refused: maximum " + clients.length + " reached.");
   }

   private String authentication(SSLSocket client){
       String name = null;
       try {
           DataInputStream  in = new DataInputStream(client.getInputStream());
           DataOutputStream out = new DataOutputStream(client.getOutputStream());
           String tmpname = keyCon.checkCert(in);
           if (tmpname == null){
               //Telling client that the certificate is invalid
               out.writeInt(-1);
               return null;
           }
           //Generate a random number and encrypt using client's public key
           BigInteger msg = new BigInteger(32, new SecureRandom());
           byte[] enMsg = keyCon.encrypt(msg.toByteArray());
           if (enMsg == null){
               return null;
           }
           //Sending the length of the encrypted msg and the msg to client
           out.writeInt(enMsg.length);
           out.write(enMsg);
           out.flush();

           //Receive the decrypted message
           int length = in.readInt();
           //length <= 0 indicates there is some wrong in the client side.
           if(length>0) {
               enMsg = new byte[length];
               in.readFully(enMsg, 0, enMsg.length);
               BigInteger result = new BigInteger(enMsg);
               //Compare the decrypted number with the original
               if (result.equals(msg)){
                   //Return code 200 to indicate the authentication is completed successfully.
                   out.writeInt(200);
                   name = tmpname;
               } else {
                   //Return code 200 to indicate the authentication is completed successfully.
                   out.writeInt(-1);
               }
         } else {
             //Check whether the client is closed.
             if (client.isConnected())
                 out.writeInt(-1);
         }
      } catch (IOException ioe) {
//         e.printStackTrace();
         System.out.println("Connection Failed: "+ ioe.getMessage());
      }
      return name;
   }

   @Override
   public void handshakeCompleted(HandshakeCompletedEvent event) {
      System.out.println("Completed handshake!!!");
      SSLSocket client = event.getSocket();
      System.out.println("Start authentication...");
      String userName = authentication(client);
      if (userName != null) {
         System.out.println("Authentication completed for " + userName);
         addThread(client, userName);
         broadcast(userName," enters");
      } else {
         System.out.println("Authentication Failure!");
      }
   }

   public void broadcast(String name, String msg){
      String returnMessage = "Client " + name + msg + " the chat room.";
      DataOutputStream dos = null;
      for(ChatServerThread client: clients) {
         if(client != null&& (!client.getSocket().isClosed())) {
            try {
               dos = new DataOutputStream(client.getSocket().getOutputStream());
               dos.writeUTF(returnMessage);
               System.out.println("Message sent to the client is: " + returnMessage);
               dos.flush();

            } catch (IOException e) {
               e.printStackTrace();
            }
         }
      }
   }

   public static void main(String args[])
   {  ChatServer server = null;
      if (args.length != 3)
         System.out.println("Usage: java ChatServer ChatRoomName host port");
      else {
          server = new ChatServer(args[0], args[1], Integer.parseInt(args[2]));
      }
   }
}
