package keydelivery;

public interface KeyEncapsulator {
    byte[] encryptSessionKey(byte[] sessionKey, String recipient) throws Exception;
    byte[] decryptSessionKey(byte[] encryptedSessionKey, String recipient) throws Exception;
}
