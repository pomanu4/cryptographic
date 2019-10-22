package ua.company.project.encrypting;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
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
        CruptoUtill utill = new CruptoUtill();
        
//        PrivateKey privateKey = rsag.getPrivateKeyFromFile("D:\\providerIntegration\\privatTransfer\\priv.pem");
//        PublicKey publicKey = rsag.getPublicKeyFromFile("D:\\providerIntegration\\betconst\\publicKey.pem");
        
        try {
//            String docFromFile = DocUtill.stringFromFile("D:\\garbage\\qwer.txt");
//            String canonic = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>LjKF5JoZiFckk1uNsFfgldUiVaw=</DigestValue></Reference></SignedInfo>";
//
//            
//            String hashSHA1base64generator = DocUtill.hashSHA1base64generator(docFromFile);
//            System.out.println(hashSHA1base64generator);
//            
//            String proDig = "LjKF5JoZiFckk1uNsFfgldUiVaw=";
//            byte[] proDigByte = Base64.getDecoder().decode(proDig);
//
//            
//            Signature sign = Signature.getInstance("SHA1withRSA");
//            sign.initSign(privateKey);
//            sign.update(canonic.getBytes("utf-8"));
//            byte[] signB = sign.sign(); //(sign.sign()),charset);
//            byte[] encode = Base64.getEncoder().encode(signB);
//            String sig = new String(encode, "utf-8");
//            System.out.println(sig);
//            Document doc = DocUtill.stringToDocument(docFromFile);
//
//            
//            String signDocument = rsag.signDocument(privateKey, doc);
//            System.out.println(signDocument);            
//            boolean verifyDocument = rsag.verifyDocument(publicKey, doc);
//            System.out.println(verifyDocument);
    PrivateKey prK = rsag.getPrivateKeyFromFile("D:\\garbage\\private.pem");
    X509Certificate cert = rsag.getCertificate("D:\\garbage\\CMStest\\cert.pem");
    PublicKey pubK = rsag.getPublicKeyFromFile("D:\\garbage\\CMStest\\pubkey.pem");
    PublicKey pubKK = rsag.getPublicKeyFromFile("D:\\garbage\\publicKey.pem");
//    PrivateKey prKK = rsag.getPrivateRSAkeyFromFile("D:\\garbageKey\\privateKeyP.pem");
    PrivateKey prKK = rsag.getPrivateRSAkeyFromFile("D:\\garbage\\privateQWERTY.pem");
    
        
        CMScrypto cms = new CMScrypto();
//        byte[] cr = cms.getCryptoMessage("hello kitty", cert, prKK, pubK);

////retrive object from byte array
//        ContentInfo conInf = ContentInfo.getInstance(ASN1Sequence.fromByteArray(cr));
//        CMSSignedData data = new CMSSignedData(conInf);
//        byte[] name = (byte[])data.getSignedContent().getContent();
//            System.out.println(new String(name));


//    List<String> readAllLines = Files.readAllLines(Paths.get("D:\\garbage\\doc.txt"));
//    StringBuilder builder = new StringBuilder();
//            for (String readAllLine : readAllLines) {
//               builder.append(readAllLine);
//            }
//    String str = builder.toString();
//    byte[] byt = Files.readAllBytes(Paths.get("D:\\garbage\\doc.txt"));
//    String str = new String(byt, "utf-8");
//            System.out.println(str);
String filepath = "D:\\garbage\\familnyAdvanced.txt";
    byte[] bb = Files.readAllBytes(Paths.get(filepath));
    String req = new String(bb, "utf-8");
            System.out.println(req);

String source = "";
    String sign = utill.sign(req, prKK);
            System.out.println(sign);
        
     
    
//        String sig = "uZDQa7PhZKeduQk0VxqLyF4HXARpwe3VZGtDcVauhgbFL7isb0l5FRs0dZeoc+nuTq33f5HwvcqOU6E8iDwHt34UVzJpr5JmnmCsjiWxUxLRrB/RYQyvss36j2QT2bZqposLJWtJn2SXWAFwllN5O0nEqtMRwsT7BtPRSFPMfcs=";
//    boolean verify = utill.verify(source, sig, pubKK);
//    System.out.println(verify);

    
//String filePath = "C:\\Users\\Leo-admin\\Downloads\\Telegram Desktop\\test.png";
//File file = new File(filePath);
//    byte[] all = Files.readAllBytes(file.toPath());
//    String string = new String(Base64.getEncoder().encode(all));
//            System.out.println(string.length());

        } catch (Exception ex) {
            Logger.getLogger(MainClass.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
