package ua.company.project.encrypting;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

public class MainClass {

    public static void main(String... args) {
Security.addProvider(new BouncyCastleProvider());

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
//        AEScryptoUtill aesu = new AEScryptoUtill();
//        String encryptAES = aesu.encryptAES("Optionally encode it with e.g. Base64 if you require a string representation. Android does have a standard implementation of this encoding, the JDK only from version 8 on (I would avoid Apache Commons Codec if possible since it is slow and a messy implementation).And that’s basically it for encryption. For constructing the message, the length of the IV, the IV, the encrypted data and the authentication tag are appended to a single byte array. (in Java the authentication tag is automatically appended to the message, there is no way to handle it yourself with the standard crypto API).It is best practice to try to wipe sensible data like a cryptographic key or IV from memory as fast as possible. Since Java is a language with automatic memory management, we don’t have any guarantees that the following works as intended, but it should in most cases:");
//        System.out.println(encryptAES);
//        
//        String decryptAES = aesu.decryptAES(encryptAES);
//        System.out.println(decryptAES);
        RSAkeyGenerator rsag = new RSAkeyGenerator();
        
        PrivateKey privateKey = rsag.getPrivateKeyFromFile("D:\\providerIntegration\\UPCintegration\\private.pem");
        PublicKey publicKey = rsag.getPublicKeyFromFile("D:\\providerIntegration\\UPCintegration\\public.pem");
       
        try {
            String docFromFile = DocUtill.stringFromFile("D:\\garbage\\qwer.txt");
            String canonic = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>LjKF5JoZiFckk1uNsFfgldUiVaw=</DigestValue></Reference></SignedInfo>";
            
            
            String hashSHA1base64generator = DocUtill.hashSHA1base64generator(docFromFile);
            System.out.println(hashSHA1base64generator);
            
            String proDig = "LjKF5JoZiFckk1uNsFfgldUiVaw=";
            byte[] proDigByte = Base64.getDecoder().decode(proDig);
                      
            
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initSign(privateKey);
            sign.update(canonic.getBytes("utf-8"));
            byte[] signB = sign.sign(); //(sign.sign()),charset);
            byte[] encode = Base64.getEncoder().encode(signB);
            String sig = new String(encode, "utf-8");
            System.out.println(sig);
              
            
            
            Document doc = DocUtill.stringToDocument(docFromFile);
                        
            
            String signDocument = rsag.signDocument(privateKey, doc);
//            System.out.println(signDocument);            
            boolean verifyDocument = rsag.verifyDocument(publicKey, doc);
            System.out.println(verifyDocument);
            
   
                    
                    
                    
//            LjKF5JoZiFckk1uNsFfgldUiVaw=    get from calc  
//            LjKF5JoZiFckk1uNsFfgldUiVaw=    from signer
//            a37aAlrl/9tpO3XhbHXg9alW0Azooi1+3J0xfw16SY75BCkIs/r9mVD+b8agU7H8KY9BmIy69KuOTeyOWii7a/Z+AQPnCkkXMDWwpiCAFyX+I4Oq5rGRqc7yS4CtWINH3wRPdMRrxQ3NLPlCcIYF0pmL9i7W3JrO33ezpHKWYPI=

            
        } catch (Exception ex) {
            Logger.getLogger(MainClass.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    

}
