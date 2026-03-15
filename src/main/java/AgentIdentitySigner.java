import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;

public class AgentIdentitySigner {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1. Generate ML-DSA Key Pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        KeyPair agentKeyPair = kpg.generateKeyPair();

        // 2. Sign a command (The "Agent's Intent")
        String agentCommand = "ACTION: TRANSFER_FUNDS; AMOUNT: 100; FROM: ACCT_A; TO: ACCT_B";
        Signature sig = Signature.getInstance("ML-DSA", "BC");
        sig.initSign(agentKeyPair.getPrivate());
        sig.update(agentCommand.getBytes());
        byte[] signature = sig.sign();

        // 3. Verify the signature (The "Guardian/Sandbox" side)
        Signature verifier = Signature.getInstance("ML-DSA", "BCPQC");
        verifier.initVerify(agentKeyPair.getPublic());
        verifier.update(agentCommand.getBytes());
        
        boolean isValid = verifier.verify(signature);
        System.out.println("Is Agent Command Authenticated? " + isValid);
    }
}