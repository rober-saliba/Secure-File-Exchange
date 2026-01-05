package ecdsa;

import java.math.BigInteger;

public class EllipticCurve {
    // NIST P-256 Parameters
    // y^2 = x^3 + ax + b (mod p)

    //p prime>3
    public static final BigInteger p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    //a is the constant in the curve equation
    public static final BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    // b is the constant in the curve equation
    public static final BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    // n is the order of the base point G
    public static final BigInteger n = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    // Base Point G coordinates
    public static final BigInteger Gx = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    public static final BigInteger Gy = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);

    // The Base Point G itself
    public static final ECPoint G = new ECPoint(Gx, Gy);

    /**
     * Point Addition: P + Q
     */
    //the three cases for the solution of the addition
    public static ECPoint add(ECPoint P, ECPoint Q) {
        if (P.isInfinity()) return Q;
        if (Q.isInfinity()) return P;

        BigInteger x1 = P.x(), y1 = P.y();
        BigInteger x2 = Q.x(), y2 = Q.y();

        if (x1.equals(x2) && !y1.equals(y2)) {
            return ECPoint.INFINITY; // P + (-P) = 0
        }

        BigInteger m;
        if (x1.equals(x2)) {
            // Point Doubling: m = (3x^2 + a) / 2y
            m = x1.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                    .multiply(y1.multiply(BigInteger.TWO).modInverse(p));
        } else {
            // Point Addition: m = (y2 - y1) / (x2 - x1)
            m = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p));
        }

        m = m.mod(p); // ensure slope is in field

        // x3 = m^2 - x1 - x2
        BigInteger x3 = m.pow(2).subtract(x1).subtract(x2).mod(p);

        // y3 = m(x1 - x3) - y1
        BigInteger y3 = m.multiply(x1.subtract(x3)).subtract(y1).mod(p);

        // Handle negative results from modulo
        if (x3.compareTo(BigInteger.ZERO) < 0) x3 = x3.add(p);
        if (y3.compareTo(BigInteger.ZERO) < 0) y3 = y3.add(p);

        return new ECPoint(x3, y3);
    }

    /**
     * Scalar Multiplication: k * P (using Double-and-Add algorithm)
     */
    //2a,3a,4a....
    public static ECPoint multiply(BigInteger k, ECPoint P) {
        ECPoint R = ECPoint.INFINITY;
        ECPoint tmp = P;

        // Iterate bits of k from right to left
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) {
                R = add(R, tmp);
            }
            tmp = add(tmp, tmp); // Double
        }
        return R;
    }
}