package FaceBook;

import java.io.Serializable;

public class Profile implements Serializable
{
	/*
	 *  This class hold profile information.
	 *   The user certificate as well as the certificate authority
	 *  signing, is included, as well as profile details of the user.
	 */
	private static final long serialVersionUID = 1L;
	public Certificate Certificate;
	public byte [] CertificateSignature;

	public boolean online;
	public String Fullname;
	public String Password;
	public String Birthday;
	public String City;
	public String Country;
	public byte[] Picture;
}
