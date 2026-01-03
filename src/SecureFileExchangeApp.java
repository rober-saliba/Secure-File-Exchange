import authentication.Authentication;
import authentication.User;
import camellia.Camellia;
import camellia.CamelliaOFB;
import keydelivery.KeyEncapsulator;
import mceliece.McEliece;
import mceliece.McElieceKeyDelivery;

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

    // Key delivery (McEliece)
    private final McEliece mceliece;
    private final KeyEncapsulator keyDelivery;

    public SecureFileExchangeApp(Authentication auth) {
        this.auth = auth;
        this.scanner = new Scanner(System.in);

        this.mceliece = new McEliece();
        this.keyDelivery = new McElieceKeyDelivery(mceliece);
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
        System.out.println("5) View my McEliece keys (public/private)");
        System.out.println("0) Exit");
        System.out.print("Choose: ");

        String choice = scanner.nextLine().trim();
        switch (choice) {
            case "1" -> sendFileFlow();
            case "2" -> listInboxFlow();
            case "3" -> decryptFromInboxFlow();
            case "4" -> logoutFlow();
            case "5" -> viewMyKeysFlow();
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
        String messageId = UUID.randomUUID().toString().substring(0, 8);
        Path bundleDir = recipientInbox.resolve(messageId);
        Files.createDirectories(bundleDir);

        Path encOut = bundleDir.resolve("payload.enc");
        Files.write(encOut, ciphertext);

        byte[] encryptedSessionKey = keyDelivery.encryptSessionKey(sessionKey, recipient);

        Path keyOut = bundleDir.resolve("key.txt");
        Files.writeString(keyOut,
                "sender=" + loggedInUser.getUsername() + "\n" +
                        "recipient=" + recipient + "\n" +
                        "originalFilename=" + filePath.getFileName() + "\n" +
                        "encryptedSessionKeyHex=" + toHex(encryptedSessionKey) + "\n" +
                        "ivHex=" + toHex(iv) + "\n"
        );


        // Save a copy in sender 'sent' folder (optional)
        Path senderSent = SENT_DIR.resolve(loggedInUser.getUsername()).resolve(messageId);
        Files.createDirectories(senderSent);
        Files.write(senderSent.resolve("payload.enc"), ciphertext);
        Files.writeString(senderSent.resolve("key.txt"), Files.readString(keyOut));


        System.out.println("✅ Sent encrypted file to " + recipient);
        System.out.println("📨 Saved: " + encOut.toAbsolutePath());
        System.out.println("🔐 Encrypted session key saved in: " + keyOut.toAbsolutePath());
    }

    // -------------------------
    // Inbox list
    // -------------------------
    private void listInboxFlow() throws IOException {
        System.out.println("\n--- My Inbox ---");
        Path myInbox = INBOX_DIR.resolve(loggedInUser.getUsername());

        List<Path> bundles = listDirectories(myInbox);
        if (bundles.isEmpty()) { System.out.println("(empty)"); return; }

        for (int i = 0; i < bundles.size(); i++) {
            System.out.println((i + 1) + ") " + bundles.get(i).getFileName());
        }

    }

    //helper for list Inbox flow ()
    private static List<Path> listDirectories(Path dir) throws IOException {
        if (!Files.exists(dir)) return List.of();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            List<Path> out = new ArrayList<>();
            for (Path p : ds) if (Files.isDirectory(p)) out.add(p);
            out.sort(Comparator.comparing(a -> a.getFileName().toString()));
            return out;
        }
    }


    // -------------------------
    // Decrypt from inbox
    // -------------------------
    private void decryptFromInboxFlow() throws Exception {
        System.out.println("\n--- Decrypt From Inbox ---");
        Path myInbox = INBOX_DIR.resolve(loggedInUser.getUsername());

        // 1) list message bundles (directories)
        List<Path> bundles = listDirectories(myInbox);
        if (bundles.isEmpty()) {
            System.out.println("(empty)");
            return;
        }

        // show bundle IDs (folder names)
        for (int i = 0; i < bundles.size(); i++) {
            System.out.println((i + 1) + ") " + bundles.get(i).getFileName());
        }

        System.out.print("Choose message number to decrypt: ");
        String numStr = scanner.nextLine().trim();
        int idx;
        try {
            idx = Integer.parseInt(numStr) - 1;
        } catch (NumberFormatException e) {
            System.out.println("Invalid number.");
            return;
        }
        if (idx < 0 || idx >= bundles.size()) {
            System.out.println("Invalid selection.");
            return;
        }

        // 2) selected bundle directory
        Path bundleDir = bundles.get(idx);

        // 3) expected files inside bundle
        Path encFile = bundleDir.resolve("payload.enc");
        Path keyFile = bundleDir.resolve("key.txt");

        if (!Files.exists(encFile)) {
            System.out.println("❌ Missing payload.enc in: " + bundleDir.getFileName());
            return;
        }
        if (!Files.exists(keyFile)) {
            System.out.println("❌ Missing key.txt in: " + bundleDir.getFileName());
            return;
        }

        // 4) read key data
        Map<String, String> keyData = readKeyFile(keyFile);

        byte[] encryptedSessionKey = fromHex(keyData.get("encryptedSessionKeyHex"));
        byte[] sessionKey = keyDelivery.decryptSessionKey(encryptedSessionKey, loggedInUser.getUsername());

        byte[] iv = fromHex(keyData.get("ivHex"));

        // 5) decrypt payload.enc
        byte[] ciphertext = Files.readAllBytes(encFile);

        Camellia cam = new Camellia(sessionKey);
        CamelliaOFB ofb = new CamelliaOFB(cam);
        byte[] plaintext = ofb.transform(iv, ciphertext);

        // 6) output decrypted file
        Path downloads = DATA_DIR.resolve("downloads").resolve(loggedInUser.getUsername());
        Files.createDirectories(downloads);

        String originalName = keyData.getOrDefault("originalFilename", bundleDir.getFileName().toString());
        String outName = originalName + ".decrypted";

        Path outFile = downloads.resolve(outName);
        Files.write(outFile, plaintext);

        System.out.println("✅ Decrypted file created:");
        System.out.println(outFile.toAbsolutePath());
        System.out.println("Sender: " + keyData.getOrDefault("sender", "(unknown)"));
        System.out.println("Message ID: " + bundleDir.getFileName());
    }


    // -------------------------
    // View keys (demo/debug)
    // -------------------------
    private void viewMyKeysFlow() {
        System.out.println("\n--- My McEliece Keys ---");

        String u = loggedInUser.getUsername();

        McEliece.PublicKey pk = mceliece.getPublicKey(u);
        McEliece.PrivateKey sk = mceliece.getPrivateKey(u);

        System.out.println("User: " + u);
        System.out.println("Params: n=" + pk.params().n() + ", k=" + pk.params().k() + ", t=" + pk.params().t());
        System.out.println();

        System.out.println("Public Key (G matrix) rows (k rows, each is n bits):");
        printMatrix(pk.Grows(), pk.params().n());

        System.out.println();
        System.out.println("Private Key (H matrix) rows (r rows, each is n bits):");
        printMatrix(sk.Hrows(), sk.params().n());

        System.out.println("\n⚠️ Note: Showing private keys is only for demo/testing.");
    }

    private static void printMatrix(BitSet[] rows, int nBits) {
        for (int i = 0; i < rows.length; i++) {
            System.out.printf("Row %02d: %s%n", i, bitSetTo01(rows[i], nBits));
        }
    }

    private static String bitSetTo01(BitSet bs, int nBits) {
        StringBuilder sb = new StringBuilder(nBits);
        for (int i = 0; i < nBits; i++) {
            sb.append(bs.get(i) ? '1' : '0');
        }
        return sb.toString();
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
            mceliece.ensureUser(u); // ensure McEliece keys exist for each user
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
