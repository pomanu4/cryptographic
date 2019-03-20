package ua.company.project.encrypting;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class MainClass {
    
    public static void main(String ... args) throws UnsupportedEncodingException {
        
//        CruptoUtill cu = new CruptoUtill();
//        String message = "AES Optionally encode it with e.g. Base64 if you require a string representation. Android does have a standard implementation of this encoding, the JDK only from version 8 on (I would avoid Apache Commons C" ;
//        byte[] enc = cu.encryptByRSApublicKey(message);
//        String encodeToString = Base64.getEncoder().encodeToString(enc);
//        
//        byte[] decrypt = cu.decryptByRSAprivateKey(enc);
//        String decMessage = new String(decrypt);
//        
//        System.out.println("encoded mess " + encodeToString);
//        System.out.println("decrypt message " + decMessage);
        
        AEScryptoUtill aesu = new AEScryptoUtill();
        String encryptAES = aesu.encryptAES("Optionally encode it with e.g. Base64 if you require a string representation. Android does have a standard implementation of this encoding, the JDK only from version 8 on (I would avoid Apache Commons Codec if possible since it is slow and a messy implementation).And that’s basically it for encryption. For constructing the message, the length of the IV, the IV, the encrypted data and the authentication tag are appended to a single byte array. (in Java the authentication tag is automatically appended to the message, there is no way to handle it yourself with the standard crypto API).It is best practice to try to wipe sensible data like a cryptographic key or IV from memory as fast as possible. Since Java is a language with automatic memory management, we don’t have any guarantees that the following works as intended, but it should in most cases:");
        System.out.println(encryptAES);
        
        String decryptAES = aesu.decryptAES(encryptAES);
        System.out.println(decryptAES);
        
    }
}
