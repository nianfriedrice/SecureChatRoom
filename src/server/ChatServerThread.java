package server;

import java.net.*;
import java.io.*;

public class ChatServerThread extends Thread
{  private ChatServer       server    = null;
   private Socket           socket    = null;
   private int              ID        = -1;
   private String           name = "";
   private DataInputStream  streamIn  =  null;
   private DataOutputStream streamOut = null;
   private volatile Thread  thread    = null;

   public ChatServerThread(ChatServer _server, Socket _socket, String clientName)
   {  super();
      server = _server;
      socket = _socket;
      name = clientName;
      ID     = socket.getPort();
   }
   public void send(String msg)
   {   try
       {  streamOut.writeUTF(msg);
          streamOut.flush();
       }
       catch(IOException ioe)
       {  System.out.println(ID + " ERROR sending: " + ioe.getMessage());
          server.remove(ID);
          stopThread();
       }
   }
   public int getID()
   {  return ID;
   }
   public void run()
   {  System.out.println("Server Thread " + ID + " running.");
      Thread thisThread = Thread.currentThread();
      while (thread == thisThread)
      {  try
         {  server.handle(ID, streamIn.readUTF());
         }
         catch(IOException ioe)
         {  System.out.println(ID + " ERROR reading: " + ioe.getMessage());
            server.remove(ID);
            stopThread();
         }
      }
   }
   public void open() throws IOException
   {  streamIn = new DataInputStream(new 
                        BufferedInputStream(socket.getInputStream()));
      streamOut = new DataOutputStream(new
                        BufferedOutputStream(socket.getOutputStream()));
   }
   public void close() throws IOException
   {  if (socket != null)    socket.close();
      if (streamIn != null)  streamIn.close();
      if (streamOut != null) streamOut.close();
   }
   public void start()
   {  thread = new Thread(this);
      thread.start();
   }
   public void stopThread()
   {  thread = null;
   }
   public String getClientName(){
      return this.name;
   }
   public Socket getSocket(){
      return this.socket;
   }
}
