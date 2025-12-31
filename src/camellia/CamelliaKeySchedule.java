package camellia;


import static camellia.CamelliaTables.*;

public final class CamelliaKeySchedule {

    // Camellia-128 uses:
    // kw1..kw4 (4)
    // k1..k18  (18)
    // ke1..ke4 (4)
    public final long[] kw = new long[4];
    public final long[] k  = new long[18];
    public final long[] ke = new long[4];

    public CamelliaKeySchedule(byte[] key16) {
        if (key16 == null || key16.length != 16) {
            throw new IllegalArgumentException("Camellia-128 key must be 16 bytes");
        }

        // KL = K, KR = 0
        long klHi = CamelliaUtil.bytesToLong(key16, 0);
        long klLo = CamelliaUtil.bytesToLong(key16, 8);
        long krHi = 0L, krLo = 0L;

        // Compute KA from KL and KR (RFC 3713 key schedule)
        // D1 = (KL ^ KR) >> 64 ; D2 = (KL ^ KR) & MASK64
        long d1 = klHi ^ krHi;
        long d2 = klLo ^ krLo;

        d2 ^= F(d1, SIGMA1);
        d1 ^= F(d2, SIGMA2);

        d1 ^= klHi;
        d2 ^= klLo;

        d2 ^= F(d1, SIGMA3);
        d1 ^= F(d2, SIGMA4);

        long kaHi = d1;
        long kaLo = d2;

        // Now generate subkeys for 128-bit key (exact rotation list from RFC)
        // kw1 = (KL <<< 0) >> 64 ; kw2 = (KL <<< 0) & MASK64
        kw[0] = klHi;
        kw[1] = klLo;

        // k1..k2 from KA<<<0
        k[0] = kaHi;
        k[1] = kaLo;

        // KL<<<15
        long[] r = CamelliaUtil.rotl128(klHi, klLo, 15);
        k[2] = r[0];
        k[3] = r[1];

        // KA<<<15
        r = CamelliaUtil.rotl128(kaHi, kaLo, 15);
        k[4] = r[0];
        k[5] = r[1];

        // ke1..ke2 from KA<<<30
        r = CamelliaUtil.rotl128(kaHi, kaLo, 30);
        ke[0] = r[0];
        ke[1] = r[1];

        // KL<<<45 -> k7,k8
        r = CamelliaUtil.rotl128(klHi, klLo, 45);
        k[6] = r[0];
        k[7] = r[1];

        // KA<<<45 -> k9 (only hi) ; and KL<<<60 -> k10 (only lo)
        r = CamelliaUtil.rotl128(kaHi, kaLo, 45);
        k[8] = r[0];

        r = CamelliaUtil.rotl128(klHi, klLo, 60);
        k[9] = r[1];

        // KA<<<60 -> k11,k12
        r = CamelliaUtil.rotl128(kaHi, kaLo, 60);
        k[10] = r[0];
        k[11] = r[1];

        // KL<<<77 -> ke3,ke4
        r = CamelliaUtil.rotl128(klHi, klLo, 77);
        ke[2] = r[0];
        ke[3] = r[1];

        // KL<<<94 -> k13,k14
        r = CamelliaUtil.rotl128(klHi, klLo, 94);
        k[12] = r[0];
        k[13] = r[1];

        // KA<<<94 -> k15,k16
        r = CamelliaUtil.rotl128(kaHi, kaLo, 94);
        k[14] = r[0];
        k[15] = r[1];

        // KL<<<111 -> k17,k18
        r = CamelliaUtil.rotl128(klHi, klLo, 111);
        k[16] = r[0];
        k[17] = r[1];

        // KA<<<111 -> kw3,kw4
        r = CamelliaUtil.rotl128(kaHi, kaLo, 111);
        kw[2] = r[0];
        kw[3] = r[1];
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
}
