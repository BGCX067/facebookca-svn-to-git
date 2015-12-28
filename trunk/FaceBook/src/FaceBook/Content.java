package FaceBook;

import java.io.Serializable;

public class Content implements Serializable
{ 
	/*
	 * this Object hold the message content, including the Signing
	 */
	private static final long serialVersionUID = 1L;
	public Object Data;
	public byte [] Signature;
}