package FaceBook;

import java.io.Serializable;
import java.security.PublicKey;

public class Certificate implements Serializable
{
	/**
	 * This is the Certificate object
	 */
	private static final long serialVersionUID = 1L;
	public PublicKey PublicKey;
	public int ID;
	public String IP;
	public int Port;
	
}
