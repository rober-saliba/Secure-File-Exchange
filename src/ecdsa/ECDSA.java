package ecdsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class ECDSA {
    private static final SecureRandom rnd = new SecureRandom();

    public record Signature(BigInteger r, BigInteger s) {}

    // Generate a private key (random integer < n)
    // Between [1,p-1] , EC
    public static BigInteger generatePrivateKey() {
        BigInteger k;
        do {
            k = new BigInteger(EllipticCurve.n.bitLength(), rnd);
        } while (k.equals(BigInteger.ZERO) || k.compareTo(EllipticCurve.n) >= 0);
        return k;
    }

    // Generate public key: Q = d * G (x,y)
    // G is the base point
    public static ECPoint generatePublicKey(BigInteger privateKey) {
        return EllipticCurve.multiply(privateKey, EllipticCurve.G);
    }

    // 1. SIGN: (r, s)
    public static Signature sign(byte[] message, BigInteger privateKey) {
        BigInteger z = hashToInt(message); //z is H(m) z is the shorts of the result of the hash
        BigInteger r, s;

        while (true) {
            // k = random integer in [1, n-1]
            BigInteger k;
            do {
                k = new BigInteger(EllipticCurve.n.bitLength(), rnd);
            } while (k.equals(BigInteger.ZERO) || k.compareTo(EllipticCurve.n) >= 0);

            // Point = k * G
            ECPoint p = EllipticCurve.multiply(k, EllipticCurve.G);

            // r = x1 mod n
            r = p.x().mod(EllipticCurve.n);
            if (r.equals(BigInteger.ZERO)) continue;

            // s = k^-1 * (z + r * privateKey) mod n
            BigInteger kInv = k.modInverse(EllipticCurve.n);
            s = kInv.multiply(z.add(r.multiply(privateKey))).mod(EllipticCurve.n);

            //if s=0
            if (!s.equals(BigInteger.ZERO)) break;
        }
        return new Signature(r, s);
    }

    // 2. VERIFY check the signature it allows the receiver  to mathematically prove that the file came from the sender  and hasn't been tampered with.
    // This function takes the message, the signature (r, s), and the public key Q (x,y), and decides if they match.
    public static boolean verify(byte[] message, Signature sig, ECPoint publicKey) {

        //It ensures the signature values r and s are valid positive numbers. If they are 0 or bigger than the curve size n, the signature is fake.
        if (sig.r.compareTo(BigInteger.ONE) < 0 || sig.r.compareTo(EllipticCurve.n) >= 0) return false;
        if (sig.s.compareTo(BigInteger.ONE) < 0 || sig.s.compareTo(EllipticCurve.n) >= 0) return false;

        //w=s^-1 mod q
        BigInteger z = hashToInt(message);
        BigInteger w = sig.s.modInverse(EllipticCurve.n);

        //u1=H(m)*w mod q ; u2=r*w mod q
        BigInteger u1 = z.multiply(w).mod(EllipticCurve.n);
        BigInteger u2 = sig.r.multiply(w).mod(EllipticCurve.n);

        // P = u1*G + u2*Q
        ECPoint p1 = EllipticCurve.multiply(u1, EllipticCurve.G);
        ECPoint p2 = EllipticCurve.multiply(u2, publicKey);
        ECPoint P = EllipticCurve.add(p1, p2);

        if (P.isInfinity()) return false;

        // Valid if P.x == r
        return P.x().mod(EllipticCurve.n).equals(sig.r);
    }

    // the hash function
    // Helper: SHA-256 hash of message converted to Integer
    private static BigInteger hashToInt(byte[] message) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(message);
            return new BigInteger(1, digest); // positive integer
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}