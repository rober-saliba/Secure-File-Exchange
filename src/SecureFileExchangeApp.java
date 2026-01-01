import authentication.Authentication;
import authentication.User;
import camellia.Camellia;
import camellia.CamelliaOFB;

import java.io.IOException;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;

public class SecureFileExchangeApp {

    private static final Path DATA_DIR = Path.of("data");
    private static final Path INBOX_DIR = DATA_DIR.resolve("inbox");
    private static final Path SENT_DIR  = DATA_DIR.resolve("sent");

    private final Authentication auth;
    private final Scanner scanner;

    private User loggedInUser; // null when logged out

    public SecureFileExchangeApp(Authentication auth) {
        this.auth = auth;
        this.scanner = new Scanner(System.in);
    }

    public void run() throws Exception {
        initStorage();

        while (true) {
            if (loggedInUser == null) {
                showLoggedOutMenu();
            } else {
                showLoggedInMenu();
            }
        }
    }

    // -------------------------
    // Menus
    // -------------------------
    private void showLoggedOutMenu() {
        System.out.println("\n=== Secure File Exchange ===");
        System.out.println("1) Login");
        System.out.println("0) Exit");
        System.out.print("Choose: ");

        String choice = scanner.nextLine().trim();
        switch (choice) {
            case "1" -> loginFlow();
            case "0" -> {
                System.out.println("Bye.");
                System.exit(0);
            }
            default -> System.out.println("Invalid option.");
        }
    }

    private void showLoggedInMenu() throws Exception {
        System.out.println("\n=== Logged in as: " + loggedInUser.getUsername() + " ===");
        System.out.println("1) Send (encrypt) a file");
        System.out.println("2) View my inbox (encrypted files)");
        System.out.println("3) Decrypt a file from my inbox");
        System.out.println("4) Logout");
        System.out.println("0) Exit");
        System.out.print("Choose: ");

        String choice = scanner.nextLine().trim();
        switch (choice) {
            case "1" -> sendFileFlow();
            case "2" -> listInboxFlow();
            case "3" -> decryptFromInboxFlow();
            case "4" -> logoutFlow();
            case "0" -> {
                System.out.println("Bye.");
                System.exit(0);
            }
            default -> System.out.println("Invalid option.");
        }
    }

    // -------------------------
    // Auth
    // -------------------------
    private void loginFlow() {
        System.out.print("Username: ");
        String u = scanner.nextLine().trim();
        System.out.print("Password: ");
        String p = scanner.nextLine().trim();

        User candidate = new User(u, p);
        if (auth.authenticate(candidate)) {
            loggedInUser = candidate;
            System.out.println("✅ Login successful.");
        } else {
            System.out.println("❌ Login failed.");
        }
    }

    private void logoutFlow() {
        System.out.println("✅ Logged out.");
        loggedInUser = null;
    }

    // -------------------------
    // Send (encrypt) file
    // -------------------------
    private void sendFileFlow() throws Exception {
        System.out.println("\n--- Send File ---");
        System.out.print("Enter recipient username (e.g. rober / sherbel / helalha): ");
        String recipient = scanner.nextLine().trim();

        // Basic recipient folder existence check
        Path recipientInbox = INBOX_DIR.resolve(recipient);
        if (!Files.exists(recipientInbox)) {
            System.out.println("❌ Recipient not found (no inbox folder).");
            return;
        }

        System.out.print("Enter path of file to send: ");
        String filePathStr = scanner.nextLine().trim();
        Path filePath = Path.of(filePathStr);

        if (!Files.exists(filePath) || Files.isDirectory(filePath)) {
            System.out.println("❌ File not found or is a directory.");
            return;
        }

        byte[] fileBytes = Files.readAllBytes(filePath);

        // Generate session key + IV
        byte[] sessionKey = randomBytes(16);
        byte[] iv = randomBytes(16);

        // Encrypt with Camellia-OFB
        Camellia cam = new Camellia(sessionKey);
        CamelliaOFB ofb = new CamelliaOFB(cam);
        byte[] ciphertext = ofb.transform(iv, fileBytes);

        // Save to recipient inbox
        String baseName = filePath.getFileName().toString();
        String messageId = UUID.randomUUID().toString().substring(0, 8);

        Path encOut = recipientInbox.resolve(baseName + "." + messageId + ".enc");
        Files.write(encOut, ciphertext);

        // TEMP KEY STORAGE (ONLY until McEliece key delivery is added)
        // TODO: Replace this .key file with McEliece encryption of (sessionKey||iv).
        Path keyOut = recipientInbox.resolve(baseName + "." + messageId + ".key");
        Files.writeString(keyOut,
                "sender=" + loggedInUser.getUsername() + "\n" +
                        "recipient=" + recipient + "\n" +
                        "sessionKeyHex=" + toHex(sessionKey) + "\n" +
                        "ivHex=" + toHex(iv) + "\n"
        );

        // Save a copy in sender 'sent' folder (optional but nice)
        Path senderSent = SENT_DIR.resolve(loggedInUser.getUsername());
        Files.write(senderSent.resolve(baseName + "." + messageId + ".enc"), ciphertext);

        System.out.println("✅ Sent encrypted file to " + recipient);
        System.out.println("📨 Saved: " + encOut.toAbsolutePath());
        System.out.println("⚠️ TEMP key file (will be McEliece later): " + keyOut.toAbsolutePath());
    }

    // -------------------------
    // Inbox list
    // -------------------------
    private void listInboxFlow() throws IOException {
        System.out.println("\n--- My Inbox ---");
        Path myInbox = INBOX_DIR.resolve(loggedInUser.getUsername());

        List<Path> encFiles = listFilesByExtension(myInbox, ".enc");
        if (encFiles.isEmpty()) {
            System.out.println("(empty)");
            return;
        }

        for (int i = 0; i < encFiles.size(); i++) {
            System.out.println((i + 1) + ") " + encFiles.get(i).getFileName());
        }
    }

    // -------------------------
    // Decrypt from inbox
    // -------------------------
    private void decryptFromInboxFlow() throws Exception {
        System.out.println("\n--- Decrypt From Inbox ---");
        Path myInbox = INBOX_DIR.resolve(loggedInUser.getUsername());

        List<Path> encFiles = listFilesByExtension(myInbox, ".enc");
        if (encFiles.isEmpty()) {
            System.out.println("(empty)");
            return;
        }

        for (int i = 0; i < encFiles.size(); i++) {
            System.out.println((i + 1) + ") " + encFiles.get(i).getFileName());
        }

        System.out.print("Choose file number to decrypt: ");
        String numStr = scanner.nextLine().trim();
        int idx;
        try {
            idx = Integer.parseInt(numStr) - 1;
        } catch (NumberFormatException e) {
            System.out.println("Invalid number.");
            return;
        }
        if (idx < 0 || idx >= encFiles.size()) {
            System.out.println("Invalid selection.");
            return;
        }

        Path encFile = encFiles.get(idx);

        // Find matching .key file
        String encName = encFile.getFileName().toString();
        String keyName = encName.replace(".enc", ".key");
        Path keyFile = myInbox.resolve(keyName);

        if (!Files.exists(keyFile)) {
            System.out.println("❌ Missing .key file (temporary key delivery placeholder).");
            return;
        }

        Map<String, String> keyData = readKeyFile(keyFile);
        byte[] sessionKey = fromHex(keyData.get("sessionKeyHex"));
        byte[] iv = fromHex(keyData.get("ivHex"));

        byte[] ciphertext = Files.readAllBytes(encFile);

        Camellia cam = new Camellia(sessionKey);
        CamelliaOFB ofb = new CamelliaOFB(cam);
        byte[] plaintext = ofb.transform(iv, ciphertext);

        // Output decrypted file to a "downloads" folder
        Path downloads = DATA_DIR.resolve("downloads").resolve(loggedInUser.getUsername());
        Files.createDirectories(downloads);

        String outName = encName.replace(".enc", ".decrypted");
        Path outFile = downloads.resolve(outName);

        Files.write(outFile, plaintext);

        System.out.println("✅ Decrypted file created:");
        System.out.println(outFile.toAbsolutePath());
        System.out.println("Sender: " + keyData.getOrDefault("sender", "(unknown)"));
    }

    // -------------------------
    // Storage init
    // -------------------------
    private void initStorage() throws IOException {
        Files.createDirectories(INBOX_DIR);
        Files.createDirectories(SENT_DIR);

        // Create inbox/sent folders for known users (demo users)
        for (String u : List.of("helalha", "rober", "sherbel")) {
            Files.createDirectories(INBOX_DIR.resolve(u));
            Files.createDirectories(SENT_DIR.resolve(u));
        }
    }

    // -------------------------
    // Utilities
    // -------------------------
    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static List<Path> listFilesByExtension(Path dir, String ext) throws IOException {
        if (!Files.exists(dir)) return List.of();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*" + ext)) {
            List<Path> files = new ArrayList<>();
            for (Path p : ds) files.add(p);
            files.sort(Comparator.comparing(a -> a.getFileName().toString()));
            return files;
        }
    }

    private static Map<String, String> readKeyFile(Path keyFile) throws IOException {
        Map<String, String> map = new HashMap<>();
        List<String> lines = Files.readAllLines(keyFile);
        for (String line : lines) {
            int eq = line.indexOf('=');
            if (eq <= 0) continue;
            String k = line.substring(0, eq).trim();
            String v = line.substring(eq + 1).trim();
            map.put(k, v);
        }
        return map;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte x : data) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] fromHex(String hex) {
        if (hex == null) throw new IllegalArgumentException("hex is null");
        hex = hex.trim();
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("Invalid hex length");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid hex char");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        new SecureFileExchangeApp(new Authentication()).run();
    }
}
