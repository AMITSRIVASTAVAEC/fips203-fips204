import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KEM;
import java.security.*;

public class PQCAgentSecurity {
    public static void main(String[] args) throws Exception {
        // 1. Setup the Post-Quantum Provider
        Security.addProvider(new BouncyCastleProvider());

        // 2. Generate ML-KEM Key Pair (Receiver Side)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        KeyPair receiverKeyPair = kpg.generateKeyPair();

        // 3. Encapsulate (Sender Side - e.g., the AI Agent)
        KEM kemSender = KEM.getInstance("ML-KEM", "BC");
        // The Agent uses the receiver's Public Key to create a secret
        KEM.Encapsulator encapsulator = kemSender.newEncapsulator(receiverKeyPair.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        
        byte[] secretKeySender = encapsulated.key().getEncoded();
        byte[] encapsulationMessage = encapsulated.encapsulation(); // Send this to receiver

        // 4. Decapsulate (Receiver Side - e.g., the Secure Vault)
        KEM kemReceiver = KEM.getInstance("ML-KEM", "BC");
        KEM.Decapsulator decapsulator = kemReceiver.newDecapsulator(receiverKeyPair.getPrivate());
        byte[] secretKeyReceiver = decapsulator.decapsulate(encapsulationMessage).getEncoded();

        // Success: Both parties now share the same 256-bit AES key
        System.out.println("Shared Secret Established: " + (MessageDigest.isEqual(secretKeySender, secretKeyReceiver)));
    }
}