package FaceBook;

import java.io.Serializable;

public class Packet implements Serializable
{
	/*
	 * Packet Object
	 */
	
	private static final long serialVersionUID = 1L;
	public PTypes Type;
	public byte[] Content;
}
