package crypto;

import camellia.Camellia;
import camellia.CamelliaOFB;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FileCrypto {

    public static byte[] encryptFileBytes(byte[] fileBytes, byte[] sessionKey16, byte[] iv16) {
        Camellia cam = new Camellia(sessionKey16);
        CamelliaOFB ofb = new CamelliaOFB(cam);
        return ofb.transform(iv16, fileBytes);
    }

    public static byte[] decryptFileBytes(byte[] cipherBytes, byte[] sessionKey16, byte[] iv16) {
        // same operation in OFB
        Camellia cam = new Camellia(sessionKey16);
        CamelliaOFB ofb = new CamelliaOFB(cam);
        return ofb.transform(iv16, cipherBytes);
    }

    public static void encryptFile(Path in, Path out, byte[] sessionKey16, byte[] iv16) throws IOException {
        byte[] data = Files.readAllBytes(in);
        byte[] ct = encryptFileBytes(data, sessionKey16, iv16);
        Files.write(out, ct);
    }

    public static void decryptFile(Path in, Path out, byte[] sessionKey16, byte[] iv16) throws IOException {
        byte[] ct = Files.readAllBytes(in);
        byte[] pt = decryptFileBytes(ct, sessionKey16, iv16);
        Files.write(out, pt);
    }
}
