package FaceBook.client;

import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.imageio.ImageIO;

import org.bouncycastle.util.encoders.Base64;

import FaceBook.Certificate;
import FaceBook.Content;
import FaceBook.Message;
import FaceBook.PTypes;
import FaceBook.Packet;
import FaceBook.PacketHelper;
import FaceBook.Profile;
import FaceBook.RSAProcessor;
import FaceBook.Serializer;

/*
 * Main client class, include the client to server connection handler
 * and client protocol
 */

public class Client
{
    static Socket _clientSocket = null; // the connection socket
    static ObjectOutputStream _out = null;
    static ObjectInputStream _in = null;
    static PublicKey _userPublicKey = null;
    static PrivateKey _userPrivateKey = null;
    static PublicKey _serverPublicKey = null;
    static Profile _myProfile;
    static private int MSG_SERVER_PORT = 4321;

    private static boolean _loggedIn;
    private static boolean _messageServerRunning;

    public static void main(String[] args) throws IOException
    {
        try
        {
            
            String host = "127.0.0.1";
            int port = 1234;// Integer.decode(args[1]).intValue();

            if(args.length == 2)
            {
                host = args[0];
                port = Integer.parseInt(args[1]);
            }
            
            System.out.println("*** Connecting to " + host + ":" + port);

            _clientSocket = new Socket(host, port); // host and port
            _out = new ObjectOutputStream(_clientSocket.getOutputStream());
            _in = new ObjectInputStream(_clientSocket.getInputStream());

            System.out.println("*** Connected to server!");
            System.out.println("*******************************************************");
            System.out.println("*   Welcome to the FaceBookCA Network!                *");
            System.out.println("*   ==================================                *");
            System.out.println("*                                                     *");
            System.out.println("*   Use: HELP to get available commands.              *");
            System.out.println("*******************************************************\n\n");
            File file = new File("server.publickey");
            ObjectInputStream inkey = new ObjectInputStream(
                    new FileInputStream(file));
            _serverPublicKey = (PublicKey) inkey.readObject();
            inkey.close();

            int myID = -1;
            String msg;
            BufferedReader userIn = new BufferedReader(new InputStreamReader(
                    System.in));





            //
            //run message server
            //


            System.out.print("> ");
            while (!(msg = userIn.readLine()).equals("quit"))
            {
                String[] splitmsg = msg.split("\\s+");


                //
                // should not allow login if certificate is in CRL
                // should check the public key in CRL!
                //
                if (splitmsg[0].equals("register"))
                {
                	if (splitmsg.length>=7)
                	{
                		myID = signupRegister(_clientSocket, splitmsg);
                    	print("success, your ID: " + myID);
                	}
                	else print("missing parameters Should be: regsiter <firstname> <lastname> <password> <birthday> <city> <country> (<picture>)");
                }

                //
                // login a user. don't allow login if user has his pubkey
                // or id in CRL.
                //
                else if (splitmsg[0].equals("login"))
                {
                    // login ID PASS
                    myID = Integer.parseInt(splitmsg[1]);
                    login(myID, splitmsg[2]);
                    if(!_loggedIn)
                        continue;
                    if(!_messageServerRunning)
                    {
                        new Thread(new MessageServer(MSG_SERVER_PORT,
                                _serverPublicKey,
                                _userPrivateKey,
                                _userPublicKey)).start();
                    }
                    _messageServerRunning = true;
                }
                else if (splitmsg[0].equals("logout"))
                {
                    logout(myID);
                    print("bye.");

                }

                //
                // get a user's detail, including certificate -- handle case when he's in CRL
                //

                else if (_loggedIn && splitmsg[0].equals("getuser"))
                {
                    if (splitmsg.length!=2) {
                        print("ilegal command- missing parameters");

                    }
                    else
                    {
                	Profile prof=UserRequests(PTypes.GetUser, Integer.parseInt(splitmsg[1]));
                	if (prof != null)
                	{
                	printProfile(prof);
                	if (prof.Picture != null)
                	{
                		try
                		{
                		// this will write the picture to afile
                		ByteArrayInputStream bas = new ByteArrayInputStream(prof.Picture);
                		BufferedImage img = ImageIO.read(bas);
                        File outFile = new File("user"+splitmsg[1]+".jpg");
                        ImageIO.write(img, "jpg", outFile);
                		print("Recived Picture: user"+splitmsg[1]+".jpg");
                		/*
                		 * opens Explorer with the picture
                		 */
                		Process process = new ProcessBuilder("explorer","user"+splitmsg[1]+".jpg").start();
                		
                		}
                		catch (Exception e)
                    	{
                    		print("couldn't save picture");
                    	}
                    }
                    }
                	else
                		print("Could not find user\n>");
                    }//if

                }
                //
                // list all registered users
                //

                else if (_loggedIn && splitmsg[0].equals("getallusers"))
                {
                	UserRequests(PTypes.GetAllUsers, 0);
                }

                //
                // list all online users
                //

                else if (_loggedIn && splitmsg[0].equals("online"))
                {
                	UserRequests(PTypes.GetOnlineUsers, 0);
                }

                //
                // send a user a message -- need to have his certificate, only if he's online
                // also, only if he is not in CRL
                //
                else if (_loggedIn && splitmsg[0].equals("send"))
                {
                    //build message object:
                    //  decrypt and get content (which is our prof+cert)
                    //    --it still has the server's signature
                    //  encrypt content with target's public
                    //  add my message

                    //sign encrypt with target's public
                    //send packet

                    //first get certificate of target with getuser.
                    if ((splitmsg.length>3)&&(splitmsg[2].equals(":")))
                     {
                            int targetId = Integer.parseInt(splitmsg[1]);
                            Profile prof = UserRequests(PTypes.GetUser,targetId);
                            if(prof == null)
                            {
                                print("cannot send message to user. may be revoked.");

                                continue;
                            }
                            if (!prof.online)
                            {
                            	print("cannot send message, user is offline!");
                            	   System.out.print(">");
                            	continue;
                            }

                            if(!RSAProcessor.Verify(prof.CertificateSignature, prof.Certificate, _serverPublicKey))
                            {
                                print("cannot verify user certificate.");
                                System.out.print(">");
                                continue;
                            }

                            else
                            {
                                PublicKey targetPublicKey = prof.Certificate.PublicKey;

                                Message m = new Message();
                                m.Message = msg.split("\\s*:\\s*")[1];
                                m.Sender = _myProfile;

                                Packet pkt = PacketHelper.EncryptAndSign(PTypes.Message, m, _userPrivateKey, targetPublicKey);

                            	String targetIP = prof.Certificate.IP;
                            	int targetPort  = prof.Certificate.Port;

                                Socket messageSocket = new Socket(targetIP.substring(1), MSG_SERVER_PORT); // host and port
                                ObjectOutputStream messageOutput = new ObjectOutputStream(messageSocket.getOutputStream());

                                messageOutput.writeObject(pkt);
                                print("message sent.");
                            }
                     }
                    else
                    {
                        print("illegal send messege command, try agian ");
                    }
                }

                //
                // delete a user and pass his cert. to CRL
                //
                else if (_loggedIn && splitmsg[0].equals("deleteme"))
                {
                	UserRequests(PTypes.DeleteUser, 0);
                }


                else if (splitmsg[0].equals("help"))
                {
                    printHelp();
                }
                else if(splitmsg[0].length() == 0)
                {
                    //
                }
                else
                {
                    print("Illegal command.");
                }
                System.out.print("> ");
            }

            System.out.println("Exiting...");

            _out.close();
            _in.close();
            userIn.close();
            _clientSocket.close();
            System.exit(0);
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }

    
    
/******************************************************************************************
 * prints the possible commands for a client at current state
 * 
 ******************************************************************************************/
    private static void printHelp()
    {
        print("HELP\n----");
        print("register <firstname> <lastname> <password> <birthday> <city> <country> (<picture>)");
        print("login <id> <password>");
        if(!_loggedIn)
            return;
        print("send <id> : <message>");
        print("getallusers");
        print("getuser <userid>");
        print("");
    }
    
    
    
    /******************************************************************************************
     * sends and receives all user request (get...)
     * 
     ******************************************************************************************/
    private static Profile UserRequests(PTypes type, int id) throws IOException, ClassNotFoundException
    {
    	if ((type == PTypes.GetAllUsers)||(type == PTypes.GetOnlineUsers))
    	{
			EncryptSignAndSend(type, null);
			Packet p = (Packet) _in.readObject();
	    	if (p.Type == PTypes.NACK)
	    	{
	    		error("could not get list");

	    	}
	    	if (p.Type == PTypes.UserList)
	    	{
	    		Content cont=PacketHelper.getVerifiedDecryptedContent(p, _userPrivateKey, _serverPublicKey);
	    		if (cont != null)
	    		{
	    			String ans= (String) cont.Data;
	    			print(ans);

	    		}
	    		else
	    		{
	    			print("List was not accepted");
	    		}
	    	}
	    	else print("Not a users list");
	    }
    	else if (type == PTypes.GetUser)
    	{
    		EncryptSignAndSend(type, id);
			Packet p = (Packet) _in.readObject();
	    	if (p.Type == PTypes.NACK)
	    	{
	    		error("could not get user");
	    		return null;
	    	}
	    	if (p.Type==PTypes.Profile)
	    	{
	    		Content cont=PacketHelper.getVerifiedDecryptedContent(p, _userPrivateKey, _serverPublicKey);
	    		if (cont == null)
	    		{
	    			print("problem");
	    			return null;
	    		}
	    		else
    			{
        			Profile prof= (Profile) cont.Data;
        			return prof;
    			}
	    	}
    	}
    	else if (type == PTypes.DeleteUser)
    	{
    		EncryptSignAndSend(PTypes.DeleteUser, "Please Delete Me");
    		Packet p= (Packet) _in.readObject();

    		if (p.Type == PTypes.NACK)
	    	{
	    		error("Server did not delete me");
	    	}
    		else if (p.Type == PTypes.ACK)
	    	{
	    		print(" I am deleted by server");
	    		_loggedIn=false;
	    		File f = new File(_myProfile.Certificate.ID + ".clientdata");
	    		f.delete();
	    		print("good bye!!");
	    		System.exit(0);

	    	}

    	}
    	return null;
    }
    
    
    /******************************************************************************************
     * User login
     * 
     ******************************************************************************************/
    private static void login(int myID, String password) throws Exception
    {
		if (!new File(myID + ".clientdata").exists()
				|| !new File(myID + ".clientdata").exists()) {
			error("user keys does not exist, please register.");
			return;
		}
		ClientData data = getData(myID);
		_userPrivateKey = data.Keys.getPrivate();
		_userPublicKey = data.Keys.getPublic();

        String loginmsg = myID + "," + password + ","
                + _clientSocket.getLocalAddress() + ","
                + _clientSocket.getPort();
        EncryptSignAndSend(PTypes.Login, loginmsg);
        Packet p = (Packet) _in.readObject();

        if (p.Type == PTypes.NACK)
        {
            error("server reports bad login.");
        }
        else if (p.Type == PTypes.ACK)
        {
            print("logged in.");

            // now get profile.
            Packet pkt = (Packet) _in.readObject();
            Content cont = PacketHelper.getVerifiedDecryptedContent(pkt, _userPrivateKey, _serverPublicKey);
            if (cont == null)
            {
                error("cannot verify server packet");
                return;
            }

            _myProfile = (Profile) cont.Data;

            printProfile(_myProfile);
        }
        else
            error("unrecognized packet");

        _loggedIn = true;
    }
    
    
    /******************************************************************************************
     * prints detalis of a profile
     * 
     ******************************************************************************************/
    private static void printProfile(Profile prof) {
		print("Your info:");
		print("ID: "+prof.Certificate.ID);
		print("Name: " + prof.Fullname + "\tBirthday: "+prof.Birthday);
		print("Living Area: " + prof.City+", " + prof.Country);
		print("IP Port: " +prof.Certificate.IP+":"+prof.Certificate.Port);
	}


	
	
	
	/******************************************************************************************
	 * Logout a user
	 * @param myID user id
	 ******************************************************************************************/
    private static void logout(int myID)
    {
        if (myID == -1)
        {
            error("you are not logged in.");
            return;
        }
        String logoutmsg = myID + "";
        EncryptSignAndSend(PTypes.Logout, logoutmsg);
        _loggedIn = false;
    }

    
    
    //
    //print error
    private static void error(String string)
    {
        print("ERROR: " + string);
    }

    //
    // print a message
    private static void print(String msg)
    {
        System.out.println(msg);
    }

    
    
/******************************************************************************************
 * handle initial signup of a new user
 * 
 ******************************************************************************************/
    private static int signupRegister(Socket clientSocket, String[] splitmsg)
            throws Exception
    {

        KeyPair pair = RSAProcessor.GenerateKeys();
        _userPrivateKey = pair.getPrivate();
        _userPublicKey = pair.getPublic();

        int myID = -1;
        Certificate cert = new Certificate();
        cert.IP = clientSocket.getLocalAddress().toString();
        cert.Port = clientSocket.getPort();
        cert.PublicKey = _userPublicKey;

        Content content = new Content();
        content.Data = cert;
        content.Signature = RSAProcessor.Sign(cert, _userPrivateKey);

        Packet p = new Packet();
        p.Content = Serializer.Serialize(content);
        p.Type = PTypes.SignUp;
        _out.writeObject(p);

        p = (Packet) _in.readObject();
        byte[] decr = RSAProcessor.Decrypt(p.Content, _userPrivateKey);
        Certificate cer = Serializer.getCertificate(decr);

        myID = cer.ID;
        Profile profile = new Profile();
        profile.Fullname = splitmsg[1] + " " + splitmsg[2];
        profile.Password = splitmsg[3];
        profile.Birthday = splitmsg[4];
        profile.City = splitmsg[5];
        profile.Country = splitmsg[6];
        if (splitmsg.length>6)
        {
        	try
        	{
            File inputFile = new File(splitmsg[7]);
            BufferedImage img = ImageIO.read(inputFile);
            ByteArrayOutputStream bas = new ByteArrayOutputStream();
            ImageIO.write(img, "jpg", bas);
            profile.Picture = bas.toByteArray();
        	}
        	catch (Exception e)
        	{
        		profile.Picture = null;
        	}
        }
        else profile.Picture = null ;
        profile.Certificate = cer;
        _myProfile = profile;
        EncryptSignAndSend(PTypes.Profile, profile);

        p = (Packet) _in.readObject();
        if (p.Type == PTypes.NACK)
        {
            System.out.println("NACK: " + PacketHelper.getVerifiedDecryptedContent(p, _userPrivateKey, _serverPublicKey));
        }

        burnData(pair, myID, profile.Password);
        return myID;
    }
    
    
    
/******************************************************************************************
 * This use Packer Helper class, Handle all encryption , signing , and sending of a new
 * packet
 ******************************************************************************************/
    private static void EncryptSignAndSend(PTypes packetType, Object data)
    {
        Packet pkt = PacketHelper.EncryptAndSign(packetType, data, _userPrivateKey, _serverPublicKey);
        try
        {
            _out.writeObject(pkt);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

    }

    
    /******************************************************************************************
     * decode and Gets data of the user from an encoded file(uses base 64)
     * 
     ******************************************************************************************/
	private static ClientData getData(int id) throws Exception {
		File datafile = new File(id + ".clientdata");

		ObjectInputStream inkey = new ObjectInputStream(new FileInputStream(
				datafile));
		ClientData cData = (ClientData)Serializer.getObject(
				Base64.decode((byte[])inkey.readObject()));
		inkey.close();

		if (cData != null)
			System.out.println("Data Read");
		else
			System.out.println(" Ther is a problem");

		return cData;
	}
	
	
/******************************************************************************************
 * encodes user detail (client data, and keys) and save it to file
 *
 ******************************************************************************************/
	private static void burnData(KeyPair pair, int id, String pass) throws IOException,
			FileNotFoundException {
		ClientData cData = new ClientData();
		cData.ID = id;
		cData.Pass = pass;
		cData.Keys = pair;

		ObjectOutput out = new ObjectOutputStream(new FileOutputStream(
				_myProfile.Certificate.ID + ".clientdata"));
		out.writeObject(Base64.encode(Serializer.Serialize(cData)));
		out.close();
	}

}
