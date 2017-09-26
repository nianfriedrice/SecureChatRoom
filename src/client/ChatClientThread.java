package client;

import java.net.*;
import java.io.*;

public class ChatClientThread extends Thread
{  private Socket           socket   = null;
   private ChatClient       client   = null;
   private DataInputStream  streamIn = null;
   private volatile Thread  thread    = null;

   public ChatClientThread(ChatClient _client, Socket _socket)
   {  client   = _client;
      socket   = _socket;
      open();
      start();
   }
   public void open()
   {  try
      {  streamIn  = new DataInputStream(socket.getInputStream());
      }
      catch(IOException ioe)
      {  System.out.println("Error getting input stream: " + ioe);
         client.stop();
      }
   }
   public void close()
   {  try
      {  if (streamIn != null) streamIn.close();
      }
      catch(IOException ioe)
      {  System.out.println("Error closing input stream: " + ioe);
      }
   }
   public void run()
   {  Thread thisThread = Thread.currentThread();
      while (thread == thisThread)
      {  try
         {
            client.handle(streamIn.readUTF());
         }
         catch(IOException ioe)
         {
//            ioe.printStackTrace();
            System.out.println("Listening error: " + ioe.getMessage());
            client.stop();
         }
      }
   }
   public void start()
   {  thread = new Thread(this);
      thread.start();
   }
   public void stopThread()
   {  thread = null;
   }


}

 

