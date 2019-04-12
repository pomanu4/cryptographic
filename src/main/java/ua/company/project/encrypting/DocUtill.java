package ua.company.project.encrypting;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class DocUtill {
    
    public static Document stringToDocument(String xml) throws ParserConfigurationException, SAXException, IOException{
        InputSource inputSource = new InputSource(new StringReader(xml));
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        
	final Document document = factory.newDocumentBuilder().parse(inputSource);
    
//	.getDocumentElement();
        return document;
    }
    
    public static String hashSHA1base64generator(String message){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(message.getBytes("utf8"));
            return new String(Base64.getEncoder().encode(md.digest()),"UTF-8");
        }catch(Exception e){
            return null;
        }
    }
    
    public static String stringFromFile(String filePath) throws IOException{
        Path path = Paths.get(filePath);
        byte[] b = Files.readAllBytes(path); 
        String result = new String(b, "utf-8");
        return result;
    }
    
    public static String documentToString(Document doc) throws TransformerException {
        DOMSource domSource = new DOMSource(doc);
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        StringWriter sw = new StringWriter();
        StreamResult sr = new StreamResult(sw);
        transformer.transform(domSource, sr);
        String toString = sw.toString();
        
        return toString;
    }
    
}
