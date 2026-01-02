package mceliece;

import keydelivery.KeyEncapsulator;

import java.security.SecureRandom;
import java.util.BitSet;

public final class McElieceKeyDelivery implements KeyEncapsulator {

    private final McEliece mceliece;
    private final SecureRandom rnd = new SecureRandom();

    public McElieceKeyDelivery(McEliece mceliece) {
        this.mceliece = mceliece;
    }

    /**
     * Encrypt 16-byte session key using recipient public key.
     * Params are fixed in McEliece.java: n=64, k=32, t=2
     *
     * Output: 4 blocks * 8 bytes = 32 bytes
     */
    @Override
    public byte[] encryptSessionKey(byte[] sessionKey, String recipient) {
        if (sessionKey == null || sessionKey.length != 16) {
            throw new IllegalArgumentException("Session key must be 16 bytes");
        }

        McEliece.PublicKey pk = mceliece.getPublicKey(recipient);
        McEliece.Params p = pk.params();

        if (p.n() != 64 || p.k() != 32) {
            throw new IllegalStateException("This delivery expects params n=64,k=32");
        }

        byte[] out = new byte[32]; // 4 ciphertext blocks * 8 bytes

        // 16 bytes => 4 blocks of 4 bytes (32-bit)
        for (int block = 0; block < 4; block++) {
            byte[] mBytes = new byte[4];
            System.arraycopy(sessionKey, block * 4, mBytes, 0, 4);

            BitSet m = bytesToBits(mBytes, 32);
            BitSet c = encryptBlock(m, pk);

            byte[] cBytes = bitsToBytes(c, 64); // 8 bytes
            System.arraycopy(cBytes, 0, out, block * 8, 8);
        }

        return out;
    }

    /**
     * Decrypt 32-byte encrypted session key using recipient private key.
     * Output: 16 bytes
     */
    @Override
    public byte[] decryptSessionKey(byte[] encryptedSessionKey, String recipient) {
        if (encryptedSessionKey == null || encryptedSessionKey.length != 32) {
            throw new IllegalArgumentException("Encrypted session key must be 32 bytes");
        }

        McEliece.PrivateKey sk = mceliece.getPrivateKey(recipient);
        McEliece.Params p = sk.params();

        if (p.n() != 64 || p.k() != 32) {
            throw new IllegalStateException("This delivery expects params n=64,k=32");
        }

        byte[] out = new byte[16]; // 4 plaintext blocks * 4 bytes

        for (int block = 0; block < 4; block++) {
            byte[] cBytes = new byte[8];
            System.arraycopy(encryptedSessionKey, block * 8, cBytes, 0, 8);

            BitSet c = bytesToBits(cBytes, 64);
            BitSet m = decryptBlock(c, sk);

            byte[] mBytes = bitsToBytes(m, 32); // 4 bytes
            System.arraycopy(mBytes, 0, out, block * 4, 4);
        }

        return out;
    }

    // =========================================================
    // Core McEliece-like block operations (n=64, k=32, t=2)
    // =========================================================

    // Encrypt one 32-bit block -> 64-bit ciphertext
    private BitSet encryptBlock(BitSet m, McEliece.PublicKey pk) {
        McEliece.Params p = pk.params();

        // codeword = m * G (G is k rows, each row is n bits)
        BitSet codeword = mulVectorByRows(m, pk.Grows(), p.n());

        // add random error of weight t
        BitSet e = randomErrorVector(p.n(), p.t());
        codeword.xor(e);

        return codeword;
    }

    // Decrypt one 64-bit ciphertext -> 32-bit message (systematic => first k bits)
    private BitSet decryptBlock(BitSet c, McEliece.PrivateKey sk) {
        McEliece.Params p = sk.params();

        // syndrome s = H * c^T  (H has r rows)
        BitSet s = syndrome(sk.Hrows(), c, p.r());

        // find error vector e of weight <= t such that H*e^T = s
        BitSet e = findErrorByBruteforce(sk.Hrows(), s, p.n(), p.t());
        if (e == null) throw new IllegalStateException("McEliece decoding failed");

        // codeword = c XOR e
        BitSet codeword = (BitSet) c.clone();
        codeword.xor(e);

        // systematic G=[I|A] => message is first k bits
        return codeword.get(0, p.k());
    }

    // =========================================================
    // Helpers (GF(2) operations)
    // =========================================================

    // Multiply a k-bit vector m by a matrix represented as k rows of BitSet (each n bits): out = m * G
    private static BitSet mulVectorByRows(BitSet m, BitSet[] rows, int n) {
        BitSet out = new BitSet(n);
        for (int i = 0; i < rows.length; i++) {
            if (m.get(i)) out.xor(rows[i]);
        }
        return out;
    }

    // syndrome: for each row i in H, dot(H[i], c) mod 2
    private static BitSet syndrome(BitSet[] Hrows, BitSet c, int r) {
        BitSet s = new BitSet(r);
        for (int i = 0; i < r; i++) {
            BitSet tmp = (BitSet) Hrows[i].clone();
            tmp.and(c);
            if ((tmp.cardinality() & 1) == 1) s.set(i);
        }
        return s;
    }

    private BitSet randomErrorVector(int n, int t) {
        BitSet e = new BitSet(n);
        int placed = 0;
        while (placed < t) {
            int pos = rnd.nextInt(n);
            if (!e.get(pos)) {
                e.set(pos);
                placed++;
            }
        }
        return e;
    }

    /**
     * Bruteforce decoding for n=64, t=2:
     * Try all 1-error and 2-error patterns until syndrome matches.
     */
    private static BitSet findErrorByBruteforce(BitSet[] Hrows, BitSet targetSyndrome, int n, int t) {
        // Try weight 0 (rare but possible)
        BitSet e0 = new BitSet(n);
        if (syndrome(Hrows, e0, targetSyndrome.length()).equals(targetSyndrome)) return e0;

        // Try weight 1
        if (t >= 1) {
            for (int i = 0; i < n; i++) {
                BitSet e = new BitSet(n);
                e.set(i);
                if (syndrome(Hrows, e, targetSyndrome.length()).equals(targetSyndrome)) return e;
            }
        }

        // Try weight 2
        if (t >= 2) {
            for (int i = 0; i < n; i++) {
                for (int j = i + 1; j < n; j++) {
                    BitSet e = new BitSet(n);
                    e.set(i);
                    e.set(j);
                    if (syndrome(Hrows, e, targetSyndrome.length()).equals(targetSyndrome)) return e;
                }
            }
        }

        return null;
    }

    // =========================================================
    // Bit conversion (big-endian bit order per byte)
    // =========================================================

    private static BitSet bytesToBits(byte[] data, int bitLen) {
        BitSet bs = new BitSet(bitLen);
        for (int i = 0; i < bitLen; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            int bit = (data[byteIndex] >>> bitIndex) & 1;
            if (bit == 1) bs.set(i);
        }
        return bs;
    }

    private static byte[] bitsToBytes(BitSet bs, int bitLen) {
        int byteLen = (bitLen + 7) / 8;
        byte[] out = new byte[byteLen];
        for (int i = 0; i < bitLen; i++) {
            if (bs.get(i)) {
                int byteIndex = i / 8;
                int bitIndex = 7 - (i % 8);
                out[byteIndex] |= (byte) (1 << bitIndex);
            }
        }
        return out;
    }
}
