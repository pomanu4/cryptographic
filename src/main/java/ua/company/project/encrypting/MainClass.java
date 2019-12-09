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
    X509Certificate cert = rsag.getCertificate("D:\\garbage\\CMStest\\cert.pem");
    PublicKey pubK = rsag.getPublicKeyFromFile("D:\\garbage\\CMStest\\pubkey.pem");
    PublicKey pubKK = rsag.getPublicKeyFromFile("D:\\garbage\\xxxpublic.pem");
//    PrivateKey prKK = rsag.getPrivateRSAkeyFromFile("D:\\garbage\\CMStest\\private.key", "qwerty");
    PrivateKey prKK = rsag.getPrivateRSAkeyFromFile("D:\\garbage\\rsaPrivate.pem", null);
    
        
        CMScrypto cms = new CMScrypto();
        byte[] cr = cms.getCryptoMessage("hello kitty", cert, prKK, null);

//retrive object from byte array
        ContentInfo conInf = ContentInfo.getInstance(ASN1Sequence.fromByteArray(cr));
        CMSSignedData data = new CMSSignedData(conInf);
        byte[] name = (byte[])data.getSignedContent().getContent();
            System.out.println(new String(cr));


//    List<String> readAllLines = Files.readAllLines(Paths.get("D:\\garbage\\doc.txt"));
//    StringBuilder builder = new StringBuilder();
//            for (String readAllLine : readAllLines) {
//               builder.append(readAllLine);
//            }
//    String str = builder.toString();
//    byte[] byt = Files.readAllBytes(Paths.get("D:\\garbage\\doc.txt"));
//    String str = new String(byt, "utf-8");
//            System.out.println(str);
//String filepath = "D:\\garbage\\familnyAdvanced.txt";
//    byte[] bb = Files.readAllBytes(Paths.get(filepath));
//    String req = new String(bb, "utf-8");
//            System.out.println(req);

String source = "<?xml version=\"1.0\" encoding=\"windows-1251\"?>\n" +
"<Data>\n" +
"<OperationData>\n" +
"<OperationType>PS_MerchantRegistrate</OperationType>\n" +
"<LocalDate>26.11.2019 17:11:21</LocalDate>\n" +
"<TerminalID>SwiftGarant_test</TerminalID>\n" +
"<ExtTranID>1</ExtTranID>\n" +
"<SenderSign></SenderSign>\n" +
"</OperationData>\n" +
"<MerchantData>\n" +
"<MemberMerchantID>leo_sub_077</MemberMerchantID>\n" +
"<MemberSubProviderID></MemberSubProviderID>\n" +
"<RegionCod></RegionCod>\n" +
"<MerchantOKPO>38536980</MerchantOKPO>\n" +
"<MerchantName>leo_sub</MerchantName>\n" +
"<ContractNumber>qwerty-1234</ContractNumber>\n" +
"<ContractDate>25.05.2013</ContractDate>\n" +
"<AccountMFO>321842</AccountMFO>\n" +
"<AccountNumber>26002053146681</AccountNumber>\n" +
"<MemberIsActive>1</MemberIsActive>\n" +
"<MemberLockComment></MemberLockComment>\n" +
"</MerchantData>\n" +
"</Data>";
    
    String generateHash = DocUtill.generateHash(source);
            System.out.println(generateHash);
    
    String sign = utill.sign(source, prKK);
            System.out.println(sign);
        
     
    
        String sig = "THmMap0vO8rU4E9C7GORejwTuGhz+jgTFu2c3zO+ryFAQlnCmo3UfbqntdKnBAb5FFS1uFUootG4j1hmr6JXSUoU/S5F96cuCthvRMGl0sd8btXRTkA2osxen2lO1GNxp8hmLtkf8AHZFelY8SSoKINlO3YmjjtD/A+dYI2eZIQ=";
    boolean verify = utill.verify(source, sig, pubKK);
    System.out.println(verify);

    
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
