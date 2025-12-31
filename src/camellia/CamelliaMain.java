package camellia;

public class CamelliaMain {
    public static void main(String[] args) {
        byte[] key = CamelliaUtil.hexToBytes("0123456789abcdeffedcba9876543210");
        byte[] pt  = CamelliaUtil.hexToBytes("000102030405060708090a0b0c0d0e0f");

        Camellia c = new Camellia(key);
        byte[] ct = c.encryptBlock(pt);
        byte[] back = c.decryptBlock(ct);

        System.out.println("CT  = " + CamelliaUtil.bytesToHex(ct));
        System.out.println("PT' = " + CamelliaUtil.bytesToHex(back));
    }
}
