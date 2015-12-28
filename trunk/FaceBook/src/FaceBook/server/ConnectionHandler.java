package FaceBook.server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;

import FaceBook.Certificate;
import FaceBook.Content;
import FaceBook.PTypes;
import FaceBook.Packet;
import FaceBook.PacketHelper;
import FaceBook.Profile;
import FaceBook.RSAProcessor;
import FaceBook.Serializer;
/*
 * Connection handler for Server- client 
 * and Server protocol
 */
public class ConnectionHandler implements Runnable
{

    private ObjectInputStream _in;
    private ObjectOutputStream _out;
    private Socket _clientSocket;
    private FaceBookServer _server;
    private boolean _logged;
    private int _userID;

    public ConnectionHandler(Socket acceptedSocket,
            FaceBookServer faceBookServer)
    {
        super();
        _in = null;
        _out = null;
        _clientSocket = acceptedSocket;
        _logged=false;
        _userID=-1;
        _server = faceBookServer;
        System.out.println("Accepted connection from client!");
        System.out.println("The client is from: "
                + acceptedSocket.getInetAddress() + ":"
                + acceptedSocket.getPort());
    }

    public void run()
    {

        try
        {
            initialize();
        }
        catch (IOException e)
        {
            System.out.println("Error in initializing I/O");
        }

        try {
			process();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        System.out.println("Connection closed - bye bye...");
        close();

    }

    public void process() throws IOException, ClassNotFoundException
    {
        while (true)
        {
            Packet p = (Packet) _in.readObject();

            System.out.println(p.Type);

            //
            // REGISTER
            //
            if (p.Type == PTypes.SignUp)
            {
                signup(p);
                p = (Packet) _in.readObject();
                if (p.Type != PTypes.Profile)
                    sendNACK("Bad protocol, signup before register");
                register(p);
            }
            else if (p.Type == PTypes.Login)
            {
                login(p);
            }
            else if (p.Type == PTypes.Logout)
            {
                logout(p);
            }
            /*
             * user requests:
             */
            else if (p.Type == PTypes.GetUser)
            {
            	getUserRequest(p);
            }
            else if (p.Type == PTypes.GetAllUsers)
            {
            	getAllUsersRequest(p);
            }
            else if (p.Type == PTypes.GetOnlineUsers)
            {
            	getAllOnlineRequest(p);
    		}
            else if (p.Type == PTypes.DeleteUser)
            {
            	deleteUser(p);
    		}
            else
            {
                sendNACK("Cannot handle this messagetype");
            }
        }
    }

/*
 * Handles deleteme request 
 * and deletes The user data
 * 
 */
	private void deleteUser(Packet p) throws IOException {
		if (!_logged)
		{
			sendNACK("Please log in first , dude...");
			return;
		}

	 	PublicKey userk= getConnectedUserPublic();
	 	//gets the Public key of connected user

		/// left verify password
	 	Content cont= PacketHelper.getVerifiedDecryptedContent(p, _server.ServerPrivateKey, userk);
		if (cont == null)
		{
			sendNACK("Signature  invalid!!! " );
			return;
		}

		//lets remove connected id
		Profile prToDelete = null;
		for(Profile pr : _server.Users)
		{
			if(pr.Certificate.ID == _userID)
			{
				Certificate cert = pr.Certificate;
				_server.CRL.add(cert); // adds certificate to CLR 
				prToDelete = pr;
				break;
			}
		}
		if(prToDelete!=null)
		{
			_server.Users.remove(prToDelete);
			sendACK();
		}
		else
		{// profile doesn't exist
			sendNACK("could not find you");
		}

		_in.close();
	}
/*
 * Get user request handler 
 */

	private void getUserRequest(Packet p) {
		if (!_logged)
		{
			sendNACK("Please log in first , dude...");
			return;
		}

	 	PublicKey userk= getConnectedUserPublic();
	 	//gets the Public key of conncted user

		/// left verify password
	 	Content cont= PacketHelper.getVerifiedDecryptedContent(p, _server.ServerPrivateKey, userk);
		if (cont == null)
		{
			sendNACK("Signature  invalid!!! " );
			return;
		}
		Profile proToSend = _server.getProfile((Integer)  cont.Data);

		if (proToSend == null)
		{ // Profile/user doen't exist
			sendNACK("user does not exist");
			return;
		}


		if (isUserRevoked(proToSend.Certificate.ID))
        	{//user is revoked
            	sendNACK("requested user is Revoked.");
            	return;
        	}




    	EncryptSignAndSend(PTypes.Profile, proToSend, userk);
	}
/*
 * Get all online user request handler
 */
private void getAllOnlineRequest(Packet p) {
    	
   if (!_logged)
	{
		sendNACK("Please log in first , dude...");
		return;
	}

    String requestAns="userId\t\tName\n********************************\n";
	for (Profile prof : _server.Users)
	{
		if (!(isUserRevoked(prof.Certificate.ID))&&(prof.online))

			requestAns+="("+prof.Certificate.ID+")\t\t"+prof.Fullname +"\n";
	}

	EncryptSignAndSend(PTypes.UserList, requestAns, getConnectedUserPublic());
	//Packet Pack=PacketHelper.EncryptAndSign(packetType, data, signKey, encryptKey).


}

/*
 * Get all online user request handler
 */
 private void getAllUsersRequest(Packet p) {
	    	//missing to check if he is logged in...
	   if (!_logged)
		{
			sendNACK("Please log in first , dude...");
			return;
		}

	   String requestAns="userId\t\tName\n********************************\n";
    	for (Profile prof : _server.Users)
    	{
    		if (!isUserRevoked(prof.Certificate.ID))
    			requestAns+="("+prof.Certificate.ID+")\t\t"+prof.Fullname +"\n";
    	}

    	EncryptSignAndSend(PTypes.UserList, requestAns, getConnectedUserPublic());
    	//Packet Pack=PacketHelper.EncryptAndSign(packetType, data, signKey, encryptKey)

	}
/*
 * logout request handler
 */
	private void logout(Packet p)
    {
        Content cont = PacketHelper.decryptAndGetContent(p.Content,
                _server.ServerPrivateKey);

        String loginMsg = cont.Data.toString();

        Profile pro = _server.getProfile(Integer.parseInt(loginMsg));

        if (pro == null)
        {
            sendNACK("User doesn't exist... Please register!");
            System.out.println("User doesn't exist...");
            return;
        }

        PublicKey userk = pro.Certificate.PublicKey;

        if (!RSAProcessor.Verify(cont.Signature, cont.Data, userk))
        {
            sendNACK("cannot verify packet");
            System.out.println("cannot verify packet");
            return;
        }
        System.out.println("Logout user " + pro.Fullname + "ID: "
                + pro.Certificate.ID);
        _logged=false;
        _server.getProfile(Integer.parseInt(loginMsg)).online=false;

    }
/*
 * login request handler
 */
    private void login(Packet p)
    {
        Content cont = PacketHelper.decryptAndGetContent(p.Content,
                _server.ServerPrivateKey);

        String loginMsg = cont.Data.toString();

        String[] loginArr = loginMsg.split(",+");

        _userID = Integer.parseInt(loginArr[0]);
        Profile pro = _server.getProfile(_userID);

        if (pro == null)
        {
            sendNACK("User doesn't exist... Please register!");
            System.out.println("ID:" + _userID + " User doesn't exist...");
            return;
        }

        PublicKey userk = pro.Certificate.PublicKey;

        if (!RSAProcessor.Verify(cont.Signature, cont.Data, userk))
        {
            sendNACK("cannot verify packet");
            System.out.println("ID:" + _userID + " cannot verify packet");
            return;
        }

        // check that he's not revoked
        if (isUserRevoked(_userID, userk))
        {
            sendNACK("Your certificate is revoked. Please re-register.");
            System.out.println("ID:" + _userID + " Request revoked");
            return;
        }

        if (!pro.Password.equals(loginArr[1]))
        {
            sendNACK("Bad Password. try again.");
            System.out.println("ID:" + _userID + " Bad Password.");
            return;
        }

        System.out.println("Login user " + pro.Fullname + "ID: "
                + pro.Certificate.ID);
        sendACK();



        pro.Certificate.IP = loginArr[2];
        pro.Certificate.Port = Integer.parseInt(loginArr[3]);
        pro.CertificateSignature =RSAProcessor.Sign(pro.Certificate, _server.ServerPrivateKey);
        EncryptSignAndSend(PTypes.Profile, pro, userk);

        _server.getProfile(_userID).online=true;


        _logged=true;
    }

    /*
     * SIGNUP & REGISTER
     */

    /*
     * checks if user certificate is in the CRL
     */

    private boolean isUserRevoked(int userID, PublicKey userk)
    {
        for (Certificate c : _server.CRL)
        {
            if (userID == c.ID || userk.equals(c.PublicKey))
                return true;
        }
        return false;
    }
    /*
     * checks if user certificate is in the CRL
     */
    private boolean isUserRevoked(int userID)
    {
        for (Certificate c : _server.CRL)
        {
            if (userID == c.ID)
                return true;
        }
        return false;
    }
/*
 * signup a user
 */
    private void signup(Packet p) throws IOException
    {
        Content cont = new Content();

        Certificate fromUser = Serializer.getCertificate(p.Content);

        Certificate cer = new Certificate();
        cer.ID = _server.getSN();
        cer.IP = fromUser.IP;
        cer.Port = fromUser.Port;
        cer.PublicKey = fromUser.PublicKey;

        Packet pac = new Packet();
        pac.Type = PTypes.Certificate;

        cont.Data = (Object) cer;
        cont.Signature = new byte[] {};

        pac.Content = RSAProcessor.Encrypt(cont, fromUser.PublicKey);
        _out.writeObject(pac);
    }
/*
 * register user
 */
    private void register(Packet p)
    {
        Content cont = PacketHelper.decryptAndGetContent(p.Content,
                _server.ServerPrivateKey);
        // Content cont = (Content)Serializer.getObject(p.Content);
        Profile prof = (Profile) cont.Data;

        PublicKey userk = prof.Certificate.PublicKey;

        if (!RSAProcessor.Verify(cont.Signature, cont.Data, userk))
        {
            sendNACK("cannot verify packet");
            return;
        }

        if (isUserRevoked(prof.Certificate.ID, userk))
        {
            sendNACK("your public key is revoked. Please generate a new public key and register.");
            return;
        }

        System.out.println("Adding user " + prof.Fullname);
        Certificate cer=prof.Certificate;
        prof.CertificateSignature = RSAProcessor.Sign(cer, _server.ServerPrivateKey);
        _server.Users.add(prof);
        sendACK();
    }
/*
 * sends a NAck
 */
    private void sendNACK(String string)
    {
        Packet p = new Packet();
        p.Type = PTypes.NACK;
        try
        {
            _out.writeObject(p);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

    }
/*
 * send ack
 */
    private void sendACK()
    {
        Packet p = new Packet();
        p.Type = PTypes.ACK;
        try
        {
            _out.writeObject(p);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    /*
     * Encrypt data, adds it and sing it
     * Create a packet of data to send
     * and send it
     */
    private void EncryptSignAndSend(PTypes packetType, Object data,
            PublicKey userPublicKey)
    {
        Packet p = PacketHelper.EncryptAndSign(packetType, data, _server.ServerPrivateKey, userPublicKey);

        try
        {
            _out.writeObject(p);
        }
        catch (IOException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    // Starts listening
    public void initialize() throws IOException
    {

        _in = new ObjectInputStream(_clientSocket.getInputStream());
        _out = new ObjectOutputStream(_clientSocket.getOutputStream());

        System.out.println("I/O initialized");
    }

    // Closes the connection
    public void close()
    {
        try
        {
            if (_in != null)
            {
                _in.close();
            }
            if (_out != null)
            {
                _out.close();
            }

            _clientSocket.close();
        }
        catch (IOException e)
        {
            System.out.println("Exception in closing I/O");
        }
    }
    /*
     * Gets the Key of a different user (for sending a msg)
     */
    private PublicKey getConnectedUserPublic()
    {
    	Profile connectedUser = _server.getProfile(_userID);
	 	PublicKey userk= connectedUser.Certificate.PublicKey;
	 	return userk;
    }
    public void print(String toprint)
    {
    	System.out.println(toprint);
    }

}
