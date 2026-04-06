package vaultlink.server;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Properties;

/**
 * Server GUI: scrollable log, active connections list, register new account, "View Audit Log" button.
 */
public class ServerGUI extends JFrame implements ClientHandler.ServerGUICallback {

    private final JTextArea logArea;
    private final JList<String> connectionsList;
    private final DefaultListModel<String> connectionsModel;
    private final AuditLogger auditLogger;
    private final AccountManager accountManager;
    private final ServerKeyStore serverKeys;
    private final File serverKeyFile;

    public ServerGUI(AuditLogger auditLogger, AccountManager accountManager, ServerKeyStore serverKeys, File serverKeyFile) {
        this.auditLogger = auditLogger;
        this.accountManager = accountManager;
        this.serverKeys = serverKeys;
        this.serverKeyFile = serverKeyFile;
        setTitle("VaultLink Bank Server");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(700, 500);
        setLayout(new BorderLayout(10, 10));

        logArea = new JTextArea(15, 50);
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(logArea);

        connectionsModel = new DefaultListModel<>();
        connectionsList = new JList<>(connectionsModel);
        connectionsList.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane connScroll = new JScrollPane(connectionsList);
        JPanel connPanel = new JPanel(new BorderLayout());
        connPanel.add(new JLabel("Active connections"), BorderLayout.NORTH);
        connPanel.add(connScroll, BorderLayout.CENTER);

        JButton registerButton = new JButton("Register New Account");
        registerButton.addActionListener(e -> showRegisterDialog());
        JButton viewAuditButton = new JButton("View Audit Log");
        viewAuditButton.addActionListener(e -> showAuditLog());
        JButton deleteAccountButton = new JButton("Delete Account");
        deleteAccountButton.addActionListener(e -> showDeleteAccountDialog());

        JPanel top = new JPanel(new BorderLayout());
        top.add(logScroll, BorderLayout.CENTER);
        JPanel right = new JPanel(new BorderLayout());
        right.add(connPanel, BorderLayout.CENTER);
        JPanel rightButtons = new JPanel(new GridLayout(3, 1, 0, 5));
        rightButtons.add(registerButton);
        rightButtons.add(deleteAccountButton);
        rightButtons.add(viewAuditButton);
        right.add(rightButtons, BorderLayout.SOUTH);
        add(top, BorderLayout.CENTER);
        add(right, BorderLayout.EAST);
    }

    @Override
    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    @Override
    public void connectionJoined(String id) {
        SwingUtilities.invokeLater(() -> connectionsModel.addElement(id));
    }

    @Override
    public void connectionLeft(String id) {
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < connectionsModel.getSize(); i++) {
                if (connectionsModel.get(i).equals(id)) {
                    connectionsModel.remove(i);
                    break;
                }
            }
        });
    }

    /**
     * COE817: customers register username/password on the server; K_pre must match the ATM config file for that user.
     */
    private void showRegisterDialog() {
        JTextField userField = new JTextField(16);
        JPasswordField passField = new JPasswordField(16);
        JTextField balanceField = new JTextField("0", 10);
        JTextField kpreField = new JTextField(32);
        JPanel panel = new JPanel(new GridLayout(0, 1, 5, 5));
        panel.add(new JLabel("Username:"));
        panel.add(userField);
        panel.add(new JLabel("Password:"));
        panel.add(passField);
        panel.add(new JLabel("Initial balance:"));
        panel.add(balanceField);
        panel.add(new JLabel("K_pre (32 hex chars, same as ATM config k_pre):"));
        panel.add(kpreField);
        int ok = JOptionPane.showConfirmDialog(this, panel, "Register New Account", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) return;
        String username = userField.getText().trim();
        char[] password = passField.getPassword();
        String kpre = kpreField.getText().trim();
        if (username.isEmpty() || password.length == 0) {
            JOptionPane.showMessageDialog(this, "Username and password are required.");
            return;
        }
        if (kpre.length() != 32 || !kpre.matches("[0-9A-Fa-f]+")) {
            JOptionPane.showMessageDialog(this, "K_pre must be exactly 32 hexadecimal characters.");
            return;
        }
        double bal;
        try {
            bal = Double.parseDouble(balanceField.getText().trim());
            if (bal < 0) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "Invalid initial balance.");
            return;
        }
        try {
            accountManager.setPassword(username, password);
            accountManager.ensureAccount(username, bal);
            serverKeys.putKpreAndSave(username, kpre);
            accountManager.saveToFile();
            log("Registered user: " + username + " (K_pre saved to " + serverKeyFile.getPath() + ")");
            File atmConfig = createAtmConfigFile(username, kpre);
            String msg = "Account registered.\n"
                    + "ATM config created: " + atmConfig.getPath() + "\n"
                    + "Run client with: java -cp out vaultlink.client.ATMClient " + atmConfig.getPath();
            JOptionPane.showMessageDialog(this, msg);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Registration failed: " + ex.getMessage());
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private File createAtmConfigFile(String username, String kpreHex) throws Exception {
        File configDir = serverKeyFile.getParentFile();
        if (configDir == null) configDir = new File(".");
        if (!configDir.exists() && !configDir.mkdirs())
            throw new IllegalStateException("Could not create config directory: " + configDir.getPath());

        int n = 1;
        File atmFile;
        while (true) {
            atmFile = new File(configDir, "atm" + n + ".properties");
            if (!atmFile.exists()) break;
            n++;
            if (n > 9999) throw new IllegalStateException("Could not find free atmN.properties filename");
        }

        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(atmFile.toPath(), StandardCharsets.UTF_8))) {
            w.println("# ATM Client " + n + " - Pre-shared key (K_pre)");
            w.println("username=" + username);
            w.println("k_pre=" + kpreHex);
        }
        log("Wrote ATM config: " + atmFile.getPath());
        return atmFile;
    }

    private void showDeleteAccountDialog() {
        JTextField userField = new JTextField(16);
        JPanel panel = new JPanel(new GridLayout(0, 1, 5, 5));
        panel.add(new JLabel("Username to delete:"));
        panel.add(userField);
        int ok = JOptionPane.showConfirmDialog(this, panel, "Delete Account", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) return;
        String username = userField.getText().trim();
        if (username.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter a username.");
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this,
                "Permanently delete account \"" + username + "\"?\n"
                        + "Balance, password, and K_pre will be removed from disk.\n"
                        + "Matching ATM config file(s) in the config folder will be deleted.",
                "Confirm delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;
        try {
            boolean hadAccount = accountManager.removeAccount(username);
            boolean hadKey = serverKeys.removeKpreAndSave(username);
            if (!hadAccount && !hadKey) {
                JOptionPane.showMessageDialog(this, "No account or key found for: " + username);
                return;
            }
            accountManager.saveToFile();
            removeAtmConfigFilesForUsername(username);
            log("Deleted account: " + username);
            JOptionPane.showMessageDialog(this, "Account deleted: " + username);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Delete failed: " + ex.getMessage());
        }
    }

    /** Remove atmN.properties whose username= property matches. */
    private void removeAtmConfigFilesForUsername(String username) {
        File configDir = serverKeyFile.getParentFile();
        if (configDir == null || !configDir.isDirectory()) return;
        File[] files = configDir.listFiles((dir, name) -> name.matches("atm\\d+\\.properties"));
        if (files == null) return;
        for (File f : files) {
            try {
                Properties p = new Properties();
                try (FileInputStream fis = new FileInputStream(f)) {
                    p.load(fis);
                }
                String u = p.getProperty("username");
                if (u != null && username.equals(u.trim())) {
                    Files.deleteIfExists(f.toPath());
                    log("Removed ATM config: " + f.getPath());
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void showAuditLog() {
        try {
            List<String> entries = auditLogger.readAndDecryptAll();
            StringBuilder sb = new StringBuilder();
            for (String s : entries) {
                sb.append(s).append("\n");
            }
            JDialog dlg = new JDialog(this, "Audit Log (decrypted)", true);
            JTextArea area = new JTextArea(sb.length() > 0 ? sb.toString() : "(empty)", 20, 60);
            area.setEditable(false);
            area.setFont(new Font("Monospaced", Font.PLAIN, 12));
            dlg.add(new JScrollPane(area));
            dlg.pack();
            dlg.setLocationRelativeTo(this);
            dlg.setVisible(true);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error reading audit log: " + ex.getMessage());
        }
    }
}
