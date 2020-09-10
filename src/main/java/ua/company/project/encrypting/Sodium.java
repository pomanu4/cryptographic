package ua.company.project.encrypting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;

public class Sodium {
	
	public static void main(String[] args) throws SodiumLibraryException, IOException {
		
		/// nonce is added to result string in the begine so actualy we transfer nnoce ro receiver
		
		SodiumLibrary.setLibraryPath("D:\\sodium\\libsodium.dll");
		
		byte[] nonce =  new byte[24];
		byte[] message = "qwertyqwertyqwertyqwertyqwertyqwerty".getBytes(StandardCharsets.UTF_8);
		byte[] key = new byte[32];
		
		byte[] key1 = Files.readAllBytes(Paths.get("D:\\garbage\\transit\\x25519.pub"));
		
//		byte[] cryptoBoxSeal = SodiumLibrary.cryptoSecretBoxEasy(message, nonce, key);
//		
//		byte[] encode = Base64.getEncoder().encode(cryptoBoxSeal);
//		
//		String result = new String(encode);
//		System.out.println(result);
//		
//		
//		byte[] byteMessage = Base64.getDecoder().decode(encode);
//		byte[] decrypt = SodiumLibrary.cryptoSecretBoxOpenEasy(byteMessage, nonce, key);
//		String result2 = new String(decrypt);
//		System.out.println(result2);
		
		byte[] cryptoBoxSeal2 = SodiumLibrary.cryptoBoxSeal(message, key1);
		byte[] encode = Base64.getEncoder().encode(cryptoBoxSeal2);
		String result = new String(encode);
		System.out.println(result);
		
	}

}
