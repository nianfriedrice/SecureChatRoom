package client;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import javax.net.ssl.*;

public class ChatClient implements Runnable
{
    private SSLSocket socket              = null;
    private volatile Thread thread     = null;
    private BufferedReader   console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private ClientKeyController keyCon = null;

   public ChatClient(String userName, String crName)
   {
      try {
         keyCon = new ClientKeyController(userName, crName);
      } catch (Exception e){
         System.out.println("Exception: " + e.getMessage());
         System.exit(0);
      }
      try {
         String[] serverInfo = keyCon.getServerInfo().split(" ");
         System.out.println("Establishing connection. Please wait ...");
         socket = connect(serverInfo[0], Integer.parseInt(serverInfo[1]));
         System.out.println("Connected: " + socket);
      } catch (Exception e){
         System.out.println("Connection Failed: "+ e.getMessage());
         System.exit(0);
      }


      socket.getSession();
      System.out.println("Complete Handshake");
      try {
         //Authentication
         DataOutputStream out = new DataOutputStream(socket.getOutputStream());
         DataInputStream in = new DataInputStream(socket.getInputStream());
         byte[] cert = Files.readAllBytes(Paths.get("Data\\"+crName.toLowerCase() + "-" + userName.toLowerCase() +".cer"));
         out.write(cert);
         out.flush();
         int length = in.readInt();
         if(length>0) {
            byte[] enMsg = new byte[length];
            in.readFully(enMsg, 0, enMsg.length);
            enMsg = keyCon.decrypt(enMsg);
            out.writeInt(enMsg.length);
            out.write(enMsg);
         } else {
            System.out.println("Invalid Certificate");
            System.exit(0);
         }
         if (in.readInt() == 200) {
            System.out.println("Enter Chat room Successfully!!");
            start();
            streamOut.writeUTF(".list");
         } else {
            System.out.println("Authentication Failed.");
            System.exit(0);
         }
      } catch (Exception e){
         System.out.println("Connection Failed "+ e.getMessage());
         e.printStackTrace();
      }
   }

   private SSLSocket connect(String serverName, int serverPort) throws Exception{
      SSLContext sslContext = SSLContext.getInstance("TLSv1");
      sslContext.init(null, keyCon.getClientKeyManager(), null);
      SSLSocketFactory socketFactory = sslContext.getSocketFactory();
      SSLSocket socket = (SSLSocket) socketFactory.createSocket(serverName, serverPort);
      return socket;
   }

   public void run()
   {  Thread thisThread = Thread.currentThread();
      while (thread == thisThread)
      while (thread != null)
      {  try
         {  streamOut.writeUTF(console.readLine());
            streamOut.flush();
         }
         catch(IOException ioe)
         {  System.out.println("Sending error: " + ioe.getMessage());
            stop();
         }
      }
   }

   public void handle(String msg)
   {  if (msg.equals(".bye"))
      {  System.out.println("Good bye. Press RETURN to exit ...");
         stop();
      }
      else
         System.out.println(msg);
   }

   public void start() throws IOException
   {  console   = new BufferedReader(new InputStreamReader(System.in));
      streamOut = new DataOutputStream(socket.getOutputStream());
      if (thread == null)
      {  client = new ChatClientThread(this, socket);
         thread = new Thread(this);                   
         thread.start();
      }
   }
   public void stop()
   {  if (thread != null)
      {  thread = null;
      }
      try
      {  if (console   != null)  console.close();
         if (streamOut != null)  streamOut.close();
         if (socket    != null)  socket.close();
      }
      catch(IOException ioe)
      {  System.out.println("Error closing ..."); }
      client.close();  
      client.stopThread();
   }
   public static void main(String args[])
   {
      ChatClient client = null;
      if (args.length != 2)
         System.out.println("Usage: java ChatClient UserName ChatRoomName");
      else {
         client = new ChatClient(args[0], args[1]);
      }
   }
}
