package FaceBook.server;

import java.io.*;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Vector;

import FaceBook.Certificate;
import FaceBook.Profile;
import FaceBook.RSAProcessor;

public class FaceBookServer implements Runnable
{
	private ServerSocket _serverSocket;
	private int _listenPort;
	public List<Profile> Users; 


	public List<Certificate> CRL;
	public int SN = 0;

	public PublicKey ServerPublicKey;
	public PrivateKey ServerPrivateKey;
/*
 * FaceBookServer 
 * initialized the server, data, and keys
 */

	public FaceBookServer(int port)
	{
		super();
		_serverSocket = null;
		_listenPort = port;
		Users = new Vector<Profile>();

		CRL = new Vector<Certificate>();
	}

	public void run()
	{
		try
		{
			_serverSocket = new ServerSocket(_listenPort);
			System.out.println(_listenPort);
			System.out.println("Listening...");



			/* added //reades The keys from Files  */
			File file = new File("server.publickey");
	        ObjectInputStream inkey = new ObjectInputStream(new FileInputStream(file));
	        //PublicKey serverPublic = null;
			try {
				ServerPublicKey = (PublicKey)inkey.readObject();
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	        inkey.close();

	        file =new File("server.PrivateKey");
	        inkey = new ObjectInputStream(new FileInputStream(file));
	        //PrivateKey serverPrivate = null;
			try {
				ServerPrivateKey = (PrivateKey)inkey.readObject();
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	        inkey.close();
	        if (ServerPrivateKey!=null && ServerPublicKey!= null)
	        	System.out.println("Keys Read");
	        else System.out.println(" Ther is a problem");
	        /**/



		} catch (IOException e)
		{
			System.out.println("Cannot listen on port " + _listenPort);
		}

		while (true)
		{
			try
			{
				ConnectionHandler handler = new ConnectionHandler(_serverSocket.accept(), this);
				new Thread(handler).start();
			} catch (IOException e)
			{
				System.out.println("Failed to accept on port " + _listenPort);
			}

		}

	}

//	private void burnKeys() throws IOException, FileNotFoundException {
//		KeyPair pair = RSAProcessor.GenerateKeys();
//		ServerPublicKey = pair.getPublic();
//		ServerPrivateKey = pair.getPrivate();
//
//		ObjectOutput out = new ObjectOutputStream(new FileOutputStream("server.Publickey"));
//		out.writeObject(ServerPublicKey);
//
//
//		out.close();
//		out=new ObjectOutputStream(new FileOutputStream("server.privateKey"));
//		out.writeObject(ServerPrivateKey);
//		out.close();
//	}
/*
 * gets the user profile from vector
 */
	public Profile getProfile(int id){
		for(Profile p : Users)
			if(p.Certificate.ID == id)
				return p;

		return null;
	}

	public int getSN(){
		SN++;
		return SN;
	}

	// Closes the connection
	public void close() throws IOException
	{
		_serverSocket.close();
	}
	/*
	 * Checks if user with [id] is online
	 */
	public boolean isOnline(int id)
	{
		for (Profile p: Users)
		{
			if (p.Certificate.ID == id)
				return p.online;
		}
		return false;
	}

	public static void main(String[] args) throws IOException
	{
		KeyPair pair = RSAProcessor.GenerateKeys();

		// Get port
		int port = 1234;//Integer.decode(args[0]).intValue();

		FaceBookServer server = new FaceBookServer(port);
		Thread serverThread = new Thread(server);
		serverThread.start();
		try {
			serverThread.join();
		}
		catch (InterruptedException e)
		{
			System.out.println("Server stopped");
		}

	}

}
