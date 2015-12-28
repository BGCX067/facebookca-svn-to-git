package FaceBook;

import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
/*
 * This class is the RSA main processor
 */
public class RSAProcessor {
	{
		Security.addProvider(new BouncyCastleProvider());
	}
/*
 * Hash Serialized data using SHA-1 algorithm
 */
	public static byte[] SHA1(byte[] bytes) throws NoSuchAlgorithmException,
			UnsupportedEncodingException {
		MessageDigest md;
		md = MessageDigest.getInstance("SHA-1");
		md.update(bytes, 0, bytes.length);
		return md.digest();
	}
/*
 *  Serialize and Hash object using SHA-1 algorithm
 */
	public static byte[] SHA1(Object obj) throws NoSuchAlgorithmException,
			UnsupportedEncodingException {
		byte[] bytes = Serializer.Serialize(obj);
		return SHA1(bytes);
	}

/*
 * Sign an Object
 */
	public static byte[] Sign(Object obj, PrivateKey key) {

		byte[] cipherText = null;
		try {
			byte[] sha1 = SHA1(obj);
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(sha1);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/***
	 * verify  received object data, using sender public key 
	 * 
	 * @return
	 */
	public static boolean Verify(byte[] signature, Object data, PublicKey key) {
		try {
			byte[] clearText = null;
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);
			clearText = cipher.doFinal(signature);

			byte[] hashed = SHA1(data);

			boolean valid = true;

			for (int i = 0; i < hashed.length; i++)
				if (hashed[i] != clearText[i]) {
					valid = false;
					break;
				}

			return valid;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
/*
 * Encrypt method. uses receiver public key
 * uses RSA algorithm.
 */

	public static byte[] Encrypt(Object o, PublicKey key) {
		byte [] data = Serializer.Serialize(o);
		byte[] dest = new byte[(((data.length - 1) / 100) + 1) * 128];

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);

			int ixdata = 0;
			int ixdest = 0;
			while (data.length - ixdata > 100) {
				ixdest += cipher.doFinal(data, ixdata, 100, dest, ixdest);
				ixdata += 100;
			}
			cipher.doFinal(data, ixdata, data.length - ixdata, dest, ixdest);

		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return dest;
	}
/*
 * Decrypt method. uses own private key
 * uses RSA algorithm.
 */

	public static byte[] Decrypt(byte[] code, PrivateKey key) {
		byte[] plain = new byte[code.length];

		byte[] ret = null;

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);

			int ixplain = 0;
			int ixcode = 0;
			while ((code.length - ixcode) > 128) {
				ixplain += cipher.doFinal(code, ixcode, 128, plain, ixplain);
				ixcode += 128;
			}
			ixplain += cipher.doFinal(code, ixcode, code.length - ixcode,
					plain, ixplain);

			ret = new byte[ixplain];
			for(int i=0; i<ixplain; i++){
				ret[i] = plain[i];
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

/*
 * This generate keyPair
 */

	public static KeyPair GenerateKeys() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			return keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}
}
