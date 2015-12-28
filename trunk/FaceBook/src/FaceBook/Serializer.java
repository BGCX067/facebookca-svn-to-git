package FaceBook;

import java.io.*;

public class Serializer {

	/*
	 * Makes an object into a sendable byte[], Serialize an object
	 */
	public static byte[] Serialize(Object o){
		ByteArrayOutputStream bos = new ByteArrayOutputStream() ;
		try {
	        ObjectOutput out;
			out = new ObjectOutputStream(bos);
			out.writeObject(o);
	        out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        return bos.toByteArray();
	}
/*
 * Deserialize a byte[] To an Object
 */
	public static Object getObject(byte[] bytes){
		ObjectInputStream is;
		try {
			is = new ObjectInputStream(new ByteArrayInputStream(bytes));
			return is.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	public static Certificate getCertificate(byte[] bytes){
		return (Certificate)((Content)getObject(bytes)).Data;
	}



}
