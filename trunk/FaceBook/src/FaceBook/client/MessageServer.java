package FaceBook.client;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.PrivateKey;
import java.security.PublicKey;
/*
 * this Class is the message Server for client - client massages
 */
public class MessageServer implements Runnable
{
    private ServerSocket _serverSocket;
    private int _listenPort = 4321;

    public PublicKey ServerPublicKey;
    public PrivateKey ServerPrivateKey;
    public PublicKey CAPublicKey;

    private boolean _stop = false;

    public MessageServer(int port, PublicKey CAPublicKey, PrivateKey privateKey, PublicKey publicKey)
    {
        super();
        _serverSocket = null;
        _listenPort = port;
        ServerPrivateKey = privateKey;
        ServerPublicKey = publicKey;
        this.CAPublicKey = CAPublicKey;
    }

    public void run()
    {
        try
        {
            _serverSocket = new ServerSocket(_listenPort);
        }
        catch (IOException e)
        {
            System.out.println("Cannot listen on port " + _listenPort);
        }

        while (!_stop)
        {
            try
            {
                MessageConnectionHandler handler = new MessageConnectionHandler(
                        _serverSocket.accept(), this);
                new Thread(handler).start();
            }
            catch (IOException e)
            {
                System.out.println("Failed to accept on port " + _listenPort);
            }
        }
    }

    public void Stop()
    {
        _stop = true;
    }

    // Closes the connection
    public void close() throws IOException
    {
        _serverSocket.close();
    }

    public void acceptMessage(String message)
    {
        synchronized (System.out)
        {
            System.out.println(message);
            System.out.print(">");
        }
    }


}
