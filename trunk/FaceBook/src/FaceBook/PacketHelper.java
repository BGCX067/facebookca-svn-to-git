package FaceBook;

import java.security.PrivateKey;
import java.security.PublicKey;
/*
 * This class contains helping method in  signing ,sending and Receiving  packets  
 */
public class PacketHelper
{

	/*
	 *  Method for verify signing for a Received  packet.
	 */
    public static Content getVerifiedDecryptedContent(Packet p, PrivateKey decryptionKey, PublicKey verifyKey)
    {

        Content cont = decryptAndGetContent(p.Content,
                decryptionKey);
        if (!RSAProcessor.Verify(cont.Signature, cont.Data, verifyKey))
        {
            return null;
        }

        return cont;
    }

    /*
     * Decrypt received packet with own public key  and get it's content.
     */
    public static Content decryptAndGetContent(Packet p,
            PrivateKey serverPrivateKey) {
    	byte [] content = p.Content;
        return decryptAndGetContent(content, serverPrivateKey);
    }
    /*
     * Decrypt received packet with own private key  and get it's content.
     */
    public static Content decryptAndGetContent(byte[] content,
            PrivateKey serverPrivateKey) {
        byte[] decryptedContent = RSAProcessor.Decrypt(content, serverPrivateKey);
        return (Content)Serializer.getObject(decryptedContent);
    }

    /*
     * Builds a packet - according to content, Encrypt with public key of receiver
     * and sign it.
     */
    public static Packet EncryptAndSign(PTypes packetType, Object data,
            PrivateKey signKey, PublicKey encryptKey)
    {
        Packet p = new Packet();
        Content content = new Content();
        content.Data = data;
        content.Signature = RSAProcessor.Sign(data, signKey);

        p.Type = packetType;
        p.Content = RSAProcessor.Encrypt(content, encryptKey);
        return p;
    }

}
