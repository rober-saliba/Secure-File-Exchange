package camellia;

import java.security.SecureRandom;
import java.util.Arrays;

public final class CamelliaOFB {
    public static final int BLOCK_SIZE = 16;

    private final Camellia cam;

    public CamelliaOFB(Camellia cam) {
        if (cam == null) throw new IllegalArgumentException("cam is null");
        this.cam = cam;
    }

    /**
     * OFB transform (encrypt/decrypt): output = input XOR keystream
     * keystream block i = E_K(keystream block i-1), starting from IV.
     */
    public byte[] transform(byte[] iv16, byte[] input) {
        if (iv16 == null || iv16.length != BLOCK_SIZE)
            throw new IllegalArgumentException("IV must be 16 bytes");
        if (input == null)
            throw new IllegalArgumentException("input is null");

        byte[] out = new byte[input.length];

        // OFB state = previous output block (starts with IV)
        byte[] ofb = Arrays.copyOf(iv16, BLOCK_SIZE);

        int off = 0;
        while (off < input.length) {
            // Generate next keystream block
            ofb = cam.encryptBlock(ofb);

            int n = Math.min(BLOCK_SIZE, input.length - off);
            for (int i = 0; i < n; i++) {
                out[off + i] = (byte) (input[off + i] ^ ofb[i]);
            }
            off += n;
        }
        return out;
    }

    /** Utility: generate a random 16-byte IV. */
    public static byte[] randomIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /** Utility: generate a random 16-byte Camellia-128 session key. */
    public static byte[] randomSessionKey() {
        byte[] key = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(key);
        return key;
    }
}
