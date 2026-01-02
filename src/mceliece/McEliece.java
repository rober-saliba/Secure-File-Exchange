package mceliece;

import java.security.SecureRandom;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * McEliece (simplified) per-user key manager.
 * This class ONLY generates/stores keys. Encryption/decryption comes next.
 */
public final class McEliece {

    // Small demo parameters (we can tune later)
    public record Params(int n, int k, int t) {
        public int r() { return n - k; }
    }

    // Public key: Generator matrix G (k x n)
    public record PublicKey(Params params, BitSet[] Grows) {}

    // Private key: Parity-check matrix H (r x n)
    public record PrivateKey(Params params, BitSet[] Hrows) {}

    public record KeyPair(PublicKey publicKey, PrivateKey privateKey) {}

    private final SecureRandom rnd = new SecureRandom();
    private final Map<String, KeyPair> keysByUser = new HashMap<>();

    public McEliece() {
        // same demo users
        ensureUser("helalha");
        ensureUser("rober");
        ensureUser("sherbel");
    }

    public void ensureUser(String username) {
        keysByUser.computeIfAbsent(username, u -> generateKeyPair(new Params(64, 32, 2)));
    }

    public PublicKey getPublicKey(String username) {
        KeyPair kp = keysByUser.get(username);
        if (kp == null) throw new IllegalArgumentException("No McEliece keys for user: " + username);
        return kp.publicKey();
    }

    public PrivateKey getPrivateKey(String username) {
        KeyPair kp = keysByUser.get(username);
        if (kp == null) throw new IllegalArgumentException("No McEliece keys for user: " + username);
        return kp.privateKey();
    }

    // -------------------------
    // Key generation: build systematic G = [I | A] and H = [A^T | I]
    // -------------------------
    private KeyPair generateKeyPair(Params p) {
        BitSet[] G = randomSystematicG(p);
        BitSet[] H = parityCheckFromSystematicG(G, p);

        return new KeyPair(new PublicKey(p, G), new PrivateKey(p, H));
    }

    private BitSet[] randomSystematicG(Params p) {
        BitSet[] rows = new BitSet[p.k()];
        for (int i = 0; i < p.k(); i++) {
            BitSet row = new BitSet(p.n());
            row.set(i); // Identity part

            // Random A part
            for (int j = p.k(); j < p.n(); j++) {
                if (rnd.nextBoolean()) row.set(j);
            }
            rows[i] = row;
        }
        return rows;
    }

    // For G=[I|A], H=[A^T | I]
    private BitSet[] parityCheckFromSystematicG(BitSet[] G, Params p) {
        int r = p.r();
        BitSet[] H = new BitSet[r];

        for (int i = 0; i < r; i++) {
            BitSet row = new BitSet(p.n());

            // A^T part (left side)
            for (int rr = 0; rr < p.k(); rr++) {
                if (G[rr].get(p.k() + i)) row.set(rr);
            }

            // I part (right side)
            row.set(p.k() + i);

            H[i] = row;
        }
        return H;
    }
}
