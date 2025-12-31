package camellia;

public final class CamelliaTables {

    // Sigma constants (64-bit)
    public static final long SIGMA1 = 0xA09E667F3BCC908BL;
    public static final long SIGMA2 = 0xB67AE8584CAA73B2L;
    public static final long SIGMA3 = 0xC6EF372FE94F82BEL;
    public static final long SIGMA4 = 0x54FF53A5F1D36F1CL;
    public static final long SIGMA5 = 0x10E527FADE682D1DL;
    public static final long SIGMA6 = 0xB05688C2B3E6C1FDL;

    // SBOX1 (given by spec / RFC)
    public static final int[] SBOX1 = {
            112,130,44,236,179,39,192,229,228,133,87,53,234,12,174,65,
            35,239,107,147,69,25,165,33,237,14,79,78,29,101,146,189,
            134,184,175,143,124,235,31,206,62,48,220,95,94,197,11,26,
            166,225,57,202,213,71,93,61,217,1,90,214,81,86,108,77,
            139,13,154,102,251,204,176,45,116,18,43,32,240,177,132,153,
            223,76,203,194,52,126,118,5,109,183,169,49,209,23,4,215,
            20,88,58,97,222,27,17,28,50,15,156,22,83,24,242,34,
            254,68,207,178,195,181,122,145,36,8,232,168,96,252,105,80,
            170,208,160,125,161,137,98,151,84,91,30,149,224,255,100,210,
            16,196,0,72,163,247,117,219,138,3,230,218,9,63,221,148,
            135,92,131,2,205,74,144,51,115,103,246,243,157,127,191,226,
            82,155,216,38,200,55,198,59,129,150,111,75,19,190,99,46,
            233,121,167,140,159,110,188,142,41,245,249,182,47,253,180,89,
            120,152,6,106,231,70,113,186,212,37,171,66,136,162,141,250,
            114,7,185,85,248,238,172,10,54,73,42,104,60,56,241,164,
            64,40,211,123,187,201,67,193,21,227,173,244,119,199,128,158
    };

    // Derived S-boxes per RFC:
    // SBOX2[x] = SBOX1[x] <<< 1
    // SBOX3[x] = SBOX1[x] <<< 7
    // SBOX4[x] = SBOX1[x <<< 1]
    public static final int[] SBOX2 = new int[256];
    public static final int[] SBOX3 = new int[256];
    public static final int[] SBOX4 = new int[256];

    static {
        for (int x = 0; x < 256; x++) {
            int s1 = SBOX1[x] & 0xFF;

            // rotate within 8-bit
            int rol1 = ((s1 << 1) | (s1 >>> 7)) & 0xFF;
            int rol7 = ((s1 << 7) | (s1 >>> 1)) & 0xFF;

            SBOX2[x] = rol1;
            SBOX3[x] = rol7;

            int xRol1 = ((x << 1) | (x >>> 7)) & 0xFF;
            SBOX4[x] = SBOX1[xRol1] & 0xFF;
        }
    }

    private CamelliaTables() {}
}
