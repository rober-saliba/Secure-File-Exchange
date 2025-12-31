package camellia;

public final class CamelliaUtil {

    public static long bytesToLong(byte[] b, int offset) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[offset + i] & 0xFFL);
        return v;
    }

    public static void longToBytes(long v, byte[] b, int offset) {
        for (int i = 7; i >= 0; i--) {
            b[offset + i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
    }

    public static long rotl64(long x, int n) {
        return (x << n) | (x >>> (64 - n));
    }

    public static int rotl32(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    /**
     * Rotate-left a 128-bit value represented as (hi, lo) by n bits (0..127).
     * Returns long[]{newHi, newLo}.
     */
    public static long[] rotl128(long hi, long lo, int n) {
        n &= 127;
        if (n == 0) return new long[]{hi, lo};

        if (n < 64) {
            long newHi = (hi << n) | (lo >>> (64 - n));
            long newLo = (lo << n) | (hi >>> (64 - n));
            return new long[]{newHi, newLo};
        } else {
            int m = n - 64;
            long newHi = (lo << m) | (hi >>> (64 - m));
            long newLo = (hi << m) | (lo >>> (64 - m));
            return new long[]{newHi, newLo};
        }
    }

    // tiny helpers for your debugging/tests
    public static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if ((hex.length() & 1) != 0) throw new IllegalArgumentException("Odd hex length");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2*i), 16);
            int lo = Character.digit(hex.charAt(2*i+1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Bad hex char");
            out[i] = (byte)((hi << 4) | lo);
        }
        return out;
    }

    public static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private CamelliaUtil() {}
}
