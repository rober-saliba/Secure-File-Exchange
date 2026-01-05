package ecdsa;

import java.math.BigInteger;


//takes the x,y and return to u a package holding the location in the EC
public record ECPoint(BigInteger x, BigInteger y) {
    public static final ECPoint INFINITY = new ECPoint(null, null);

    public boolean isInfinity() {
        return x == null && y == null;
    }
}