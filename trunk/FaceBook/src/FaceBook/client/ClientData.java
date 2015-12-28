package FaceBook.client;

import java.io.Serializable;
import java.security.KeyPair;

public class ClientData implements Serializable {
	/**
     *	Client data that will be saved into file
     */
    private static final long serialVersionUID = 1L;
    public KeyPair Keys;
	public int ID;
	public String Pass;
}
