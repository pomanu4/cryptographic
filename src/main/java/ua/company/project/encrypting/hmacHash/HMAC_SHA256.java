package ua.company.project.encrypting.hmacHash;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class HMAC_SHA256 {

    private static final String DEFAULT_CHARSET = "UTF-8";
    private static final String ALGORYTHM = "HmacSHA256";

    public static String generateHashString(String message, String key) {
        try {
            Mac sha256 = Mac.getInstance(ALGORYTHM);
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(DEFAULT_CHARSET), ALGORYTHM);
            sha256.init(keySpec);
            byte[] bytes = sha256.doFinal(message.getBytes(DEFAULT_CHARSET));
            String encode = new String(Hex.encodeHex(bytes));
            return encode;
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException ex) {
            ex.printStackTrace();
            return null;
        }
    }
    
    public static void main(String[] args) {
        String message = "MAXEXPRESS!\\#o2MMJxnV@\\#";
        
        try{
            MessageDigest md = MessageDigest.getInstance("sha-256");
            md.update(message.getBytes("utf8"));
            String encoded = new String(Hex.encodeHex(md.digest()));

            System.out.println(encoded);
        }catch(NoSuchAlgorithmException | UnsupportedEncodingException ex){
            ex.printStackTrace();
        }
    }

}
