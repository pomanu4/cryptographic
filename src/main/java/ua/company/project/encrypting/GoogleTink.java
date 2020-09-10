package ua.company.project.encrypting;

import java.security.GeneralSecurityException;
import com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenRecipient;

public class GoogleTink {
	
	public static void main(String[] args) throws GeneralSecurityException {
		
		String pr = new PaymentMethodTokenRecipient.Builder()
				.addSenderVerifyingKey("qwerty")
				.recipientId("merchant:qwerty")
				.protocolVersion("ECv2")
				.addRecipientPrivateKey("qwerty key")
				.build()
				.unseal("cryptomessage");
		
		System.out.println(pr);
		
	}

}
