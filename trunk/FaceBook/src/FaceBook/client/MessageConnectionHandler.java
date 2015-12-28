package FaceBook.client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;

import FaceBook.Content;
import FaceBook.Message;
import FaceBook.PTypes;
import FaceBook.Packet;
import FaceBook.PacketHelper;
import FaceBook.Profile;
import FaceBook.RSAProcessor;
/*
 * this class is the connection handler for client - client messages
 */
public class MessageConnectionHandler implements Runnable
{

    private ObjectInputStream _in;
    private ObjectOutputStream _out;
    private Socket _clientSocket;
    private MessageServer _messageServer;

    /**
     * Connection handler for the messages server
     * @param acceptedSocket client requeting handle
     * @param messageServer main message server
     */
    public MessageConnectionHandler(Socket acceptedSocket,
            MessageServer messageServer)
    {
        super();
        _in = null;
        _out = null;
        _clientSocket = acceptedSocket;
        _messageServer = messageServer;
        System.out.println("MSG from: "
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

        process();

        close();

    }

    public void process()
    {
        //
        // read a message from someone
        // our key pair is at _messageServer.ServerPublic/Private
        try
        {
            Packet p = (Packet) _in.readObject();
            if(p.Type != PTypes.Message)
            {
            	_messageServer.acceptMessage("bad message packet");
            	return;
            }

            // decrypt message object
            // from message:
            //  1. decrypt Message
            //  2. get sender's Certificate
            //  3.  ==verify certificate against CA
            //  4. get the public key
            //  5.  ==verify message with the public key
            //  6. pass the message to server

            Content content = PacketHelper.decryptAndGetContent(p, _messageServer.ServerPrivateKey);
            Message m = (Message)content.Data;

            Profile prof = m.Sender;

            if(!RSAProcessor.Verify(prof.CertificateSignature, prof.Certificate, _messageServer.CAPublicKey))
        	{
            	System.out.println("MessageConnectionHandler: dropped message CA doesnt verify cert.");
            	return;
        	}

            PublicKey senderpub = prof.Certificate.PublicKey;

            if(!RSAProcessor.Verify(content.Signature, content.Data, senderpub))
            {
            	System.out.println("MessageConnectionHandler: dropped message cannot verify packet.");
            	return;
            }

            _messageServer.acceptMessage("<"+prof.Fullname+"("+prof.Certificate.ID+")> " + m.Message);
            
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }





    // Starts listening
    public void initialize() throws IOException
    {

        _in = new ObjectInputStream(_clientSocket.getInputStream());
        _out = new ObjectOutputStream(_clientSocket.getOutputStream());
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

}
