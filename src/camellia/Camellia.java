package camellia;

import static camellia.CamelliaTables.*;

public final class Camellia {

    private final CamelliaKeySchedule ks;

    public Camellia(byte[] key16) {
        this.ks = new CamelliaKeySchedule(key16);
    }

    public byte[] encryptBlock(byte[] plaintext16) {
        if (plaintext16 == null || plaintext16.length != 16) {
            throw new IllegalArgumentException("Plaintext block must be 16 bytes");
        }

        long d1 = CamelliaUtil.bytesToLong(plaintext16, 0);
        long d2 = CamelliaUtil.bytesToLong(plaintext16, 8);

        // Prewhitening
        d1 ^= ks.kw[0];
        d2 ^= ks.kw[1];

        // Rounds 1..6
        d2 ^= F(d1, ks.k[0]);
        d1 ^= F(d2, ks.k[1]);
        d2 ^= F(d1, ks.k[2]);
        d1 ^= F(d2, ks.k[3]);
        d2 ^= F(d1, ks.k[4]);
        d1 ^= F(d2, ks.k[5]);

        // FL / FLINV
        d1 = FL(d1, ks.ke[0]);
        d2 = FLINV(d2, ks.ke[1]);

        // Rounds 7..12
        d2 ^= F(d1, ks.k[6]);
        d1 ^= F(d2, ks.k[7]);
        d2 ^= F(d1, ks.k[8]);
        d1 ^= F(d2, ks.k[9]);
        d2 ^= F(d1, ks.k[10]);
        d1 ^= F(d2, ks.k[11]);

        // FL / FLINV
        d1 = FL(d1, ks.ke[2]);
        d2 = FLINV(d2, ks.ke[3]);

        // Rounds 13..18
        d2 ^= F(d1, ks.k[12]);
        d1 ^= F(d2, ks.k[13]);
        d2 ^= F(d1, ks.k[14]);
        d1 ^= F(d2, ks.k[15]);
        d2 ^= F(d1, ks.k[16]);
        d1 ^= F(d2, ks.k[17]);

        // Postwhitening
        d2 ^= ks.kw[2];
        d1 ^= ks.kw[3];

        // Output is (D2 || D1)
        byte[] out = new byte[16];
        CamelliaUtil.longToBytes(d2, out, 0);
        CamelliaUtil.longToBytes(d1, out, 8);
        return out;
    }

    public byte[] decryptBlock(byte[] ciphertext16) {
        if (ciphertext16 == null || ciphertext16.length != 16) {
            throw new IllegalArgumentException("Ciphertext block must be 16 bytes");
        }

        // Read as RFC defines ciphertext: C = (D2<<64)|D1
        long d1 = CamelliaUtil.bytesToLong(ciphertext16, 0);  // this is D2 from encryption
        long d2 = CamelliaUtil.bytesToLong(ciphertext16, 8);  // this is D1 from encryption

        // Prewhitening uses kw3,kw4 (swap kw1<->kw3, kw2<->kw4)
        d1 ^= ks.kw[2];
        d2 ^= ks.kw[3];

        // Rounds with reversed k (k18..k1)
        d2 ^= F(d1, ks.k[17]);
        d1 ^= F(d2, ks.k[16]);
        d2 ^= F(d1, ks.k[15]);
        d1 ^= F(d2, ks.k[14]);
        d2 ^= F(d1, ks.k[13]);
        d1 ^= F(d2, ks.k[12]);

        // FL/FLINV with swapped ke (ke1<->ke4, ke2<->ke3)
        d1 = FL(d1, ks.ke[3]);
        d2 = FLINV(d2, ks.ke[2]);

        d2 ^= F(d1, ks.k[11]);
        d1 ^= F(d2, ks.k[10]);
        d2 ^= F(d1, ks.k[9]);
        d1 ^= F(d2, ks.k[8]);
        d2 ^= F(d1, ks.k[7]);
        d1 ^= F(d2, ks.k[6]);

        d1 = FL(d1, ks.ke[1]);
        d2 = FLINV(d2, ks.ke[0]);

        d2 ^= F(d1, ks.k[5]);
        d1 ^= F(d2, ks.k[4]);
        d2 ^= F(d1, ks.k[3]);
        d1 ^= F(d2, ks.k[2]);
        d2 ^= F(d1, ks.k[1]);
        d1 ^= F(d2, ks.k[0]);

        // Postwhitening uses kw1,kw2
        d2 ^= ks.kw[0];
        d1 ^= ks.kw[1];

        // Output plaintext is also produced as (D2||D1) by the same structure
        byte[] out = new byte[16];
        CamelliaUtil.longToBytes(d2, out, 0);
        CamelliaUtil.longToBytes(d1, out, 8);
        return out;
    }


    // F-function (RFC 3713)
    private static long F(long in, long ke) {
        long x = in ^ ke;

        int t1 = (int) ((x >>> 56) & 0xFF);
        int t2 = (int) ((x >>> 48) & 0xFF);
        int t3 = (int) ((x >>> 40) & 0xFF);
        int t4 = (int) ((x >>> 32) & 0xFF);
        int t5 = (int) ((x >>> 24) & 0xFF);
        int t6 = (int) ((x >>> 16) & 0xFF);
        int t7 = (int) ((x >>>  8) & 0xFF);
        int t8 = (int) ( x         & 0xFF);

        t1 = SBOX1[t1];
        t2 = SBOX2[t2];
        t3 = SBOX3[t3];
        t4 = SBOX4[t4];
        t5 = SBOX2[t5];
        t6 = SBOX3[t6];
        t7 = SBOX4[t7];
        t8 = SBOX1[t8];

        int y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
        int y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
        int y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
        int y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
        int y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
        int y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
        int y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
        int y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

        return ((long)(y1 & 0xFF) << 56)
                | ((long)(y2 & 0xFF) << 48)
                | ((long)(y3 & 0xFF) << 40)
                | ((long)(y4 & 0xFF) << 32)
                | ((long)(y5 & 0xFF) << 24)
                | ((long)(y6 & 0xFF) << 16)
                | ((long)(y7 & 0xFF) <<  8)
                | ((long)(y8 & 0xFF));
    }

    // FL (RFC 3713)
    private static long FL(long in, long ke) {
        int x1 = (int) (in >>> 32);
        int x2 = (int) (in & 0xFFFFFFFFL);

        int k1 = (int) (ke >>> 32);
        int k2 = (int) (ke & 0xFFFFFFFFL);

        x2 ^= CamelliaUtil.rotl32(x1 & k1, 1);
        x1 ^= (x2 | k2);

        return ((long)x1 << 32) | (x2 & 0xFFFFFFFFL);
    }

    // FLINV (RFC 3713)
    private static long FLINV(long in, long ke) {
        int y1 = (int) (in >>> 32);
        int y2 = (int) (in & 0xFFFFFFFFL);

        int k1 = (int) (ke >>> 32);
        int k2 = (int) (ke & 0xFFFFFFFFL);

        y1 ^= (y2 | k2);
        y2 ^= CamelliaUtil.rotl32(y1 & k1, 1);

        return ((long)y1 << 32) | (y2 & 0xFFFFFFFFL);
    }
}
