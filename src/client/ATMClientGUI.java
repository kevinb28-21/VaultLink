package vaultlink.client;

import vaultlink.common.MessageFormat;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * ATM Client GUI: Login screen (username, password, Login), Main menu (Deposit, Withdraw, Balance, amount, result, status).
 */
public class ATMClientGUI extends JFrame {

    private final JTextField usernameField;
    private final JPasswordField passwordField;
    private final JLabel statusLabel;
    private final JPanel loginPanel;
    private final JPanel mainPanel;
    private final JTextField amountField;
    private final JTextArea resultArea;
    private final JLabel mainStatusLabel;
    private final CardLayout cardLayout;
    private final JPanel cards;
    private final String configPath;
    private final String serverHost;
    private final int serverPort;

    private ATMClientSession session;
    private byte[] kPre;
    private String configUsername;

    public ATMClientGUI(String configPath, String serverHost, int serverPort) {
        this.configPath = configPath;
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        setTitle("VaultLink ATM");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(450, 400);
        setLayout(new BorderLayout());

        cardLayout = new CardLayout();
        cards = new JPanel(cardLayout);

        // --- Login panel ---
        loginPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.EAST;
        loginPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1;
        usernameField = new JTextField(15);
        loginPanel.add(usernameField, gbc);
        gbc.gridx = 0; gbc.gridy = 1;
        loginPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        passwordField = new JPasswordField(15);
        loginPanel.add(passwordField, gbc);
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JButton loginButton = new JButton("Login");
        loginPanel.add(loginButton, gbc);
        gbc.gridy = 3;
        statusLabel = new JLabel(" ");
        statusLabel.setForeground(Color.GRAY);
        loginPanel.add(statusLabel, gbc);

        loginButton.addActionListener(e -> doLogin());

        // --- Main panel ---
        mainPanel = new JPanel(new BorderLayout(10, 10));
        JPanel buttonsPanel = new JPanel(new FlowLayout());
        JButton depositBtn = new JButton("Deposit");
        JButton withdrawBtn = new JButton("Withdraw");
        JButton balanceBtn = new JButton("Balance Inquiry");
        JButton logoutBtn = new JButton("Logout");
        buttonsPanel.add(depositBtn);
        buttonsPanel.add(withdrawBtn);
        buttonsPanel.add(balanceBtn);
        buttonsPanel.add(logoutBtn);
        mainPanel.add(buttonsPanel, BorderLayout.NORTH);
        amountField = new JTextField(10);
        JPanel amountPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        amountPanel.add(new JLabel("Amount:"));
        amountPanel.add(amountField);
        JPanel centerWrap = new JPanel(new BorderLayout());
        centerWrap.add(amountPanel, BorderLayout.NORTH);
        resultArea = new JTextArea(8, 30);
        resultArea.setEditable(false);
        resultArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        centerWrap.add(new JScrollPane(resultArea), BorderLayout.CENTER);
        mainPanel.add(centerWrap, BorderLayout.CENTER);
        mainStatusLabel = new JLabel("Connected");
        mainStatusLabel.setForeground(new Color(0, 128, 0));
        mainPanel.add(mainStatusLabel, BorderLayout.SOUTH);

        depositBtn.addActionListener(e -> doTransaction("DEPOSIT"));
        withdrawBtn.addActionListener(e -> doTransaction("WITHDRAW"));
        balanceBtn.addActionListener(e -> doTransaction("BALANCE"));
        logoutBtn.addActionListener(e -> doLogout());

        cards.add(loginPanel, "login");
        cards.add(mainPanel, "main");
        add(cards, BorderLayout.CENTER);
    }

    private void loadKpre() throws Exception {
        Properties p = new Properties();
        try (FileInputStream fis = new FileInputStream(configPath)) {
            p.load(fis);
        }
        String u = p.getProperty("username");
        if (u != null && !(u = u.trim()).isEmpty()) {
            configUsername = u;
        }
        String kPreStr = p.getProperty("k_pre");
        if (kPreStr == null || kPreStr.isEmpty()) throw new IllegalArgumentException("k_pre not found in config");
        kPre = MessageFormat.decodeKpre(kPreStr.trim());
    }

    private void doLogin() {
        String user = usernameField.getText().trim();
        String pass = new String(passwordField.getPassword());
        if (user.isEmpty() || pass.isEmpty()) {
            statusLabel.setText("Enter username and password");
            statusLabel.setForeground(Color.RED);
            return;
        }
        statusLabel.setText("Connecting...");
        statusLabel.setForeground(Color.GRAY);
        new Thread(() -> {
            try {
                if (kPre == null) loadKpre();
                if (configUsername != null && !configUsername.equals(user)) {
                    final String msg = "Config is for " + configUsername + " (wrong ATM config for this username)";
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(msg);
                        statusLabel.setForeground(Color.RED);
                    });
                    return;
                }
                ATMClientSession s = ATMClientSession.connect(serverHost, serverPort, user, pass, kPre);
                if (s == null) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Login failed: invalid credentials or connection error");
                        statusLabel.setForeground(Color.RED);
                    });
                    return;
                }
                session = s;
                SwingUtilities.invokeLater(() -> {
                    cardLayout.show(cards, "main");
                    resultArea.setText("");
                    mainStatusLabel.setText("Connected as " + session.getCustomerId());
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Error: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                });
            }
        }).start();
    }

    private void doTransaction(String action) {
        if (session == null || session.isClosed()) {
            resultArea.append("Not connected.\n");
            return;
        }
        double amount = 0;
        if ("DEPOSIT".equals(action) || "WITHDRAW".equals(action)) {
            try {
                amount = Double.parseDouble(amountField.getText().trim());
                if (amount <= 0) {
                    resultArea.append("Enter a positive amount.\n");
                    return;
                }
            } catch (NumberFormatException e) {
                resultArea.append("Invalid amount.\n");
                return;
            }
        }
        resultArea.append("Processing " + action + " ...\n");
        final double amountToSend = amount;
        final String actionFinal = action;
        new Thread(() -> {
            try {
                MessageFormat.ResponsePlaintext resp = session.request(actionFinal, amountToSend);
                SwingUtilities.invokeLater(() -> {
                    if (resp == null) {
                        resultArea.append("Error: no response or integrity check failed.\n");
                        mainStatusLabel.setText("Error");
                        mainStatusLabel.setForeground(Color.RED);
                        return;
                    }
                    if (resp.success) {
                        resultArea.append("Success. " + resp.message + " Balance: " + resp.balance + "\n");
                        mainStatusLabel.setForeground(new Color(0, 128, 0));
                    } else {
                        resultArea.append("Failed: " + resp.message + " Balance: " + resp.balance + "\n");
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    resultArea.append("Error: " + ex.getMessage() + "\n");
                    mainStatusLabel.setText("Error");
                    mainStatusLabel.setForeground(Color.RED);
                });
            }
        }).start();
    }

    private void doLogout() {
        if (session != null) {
            session.logout();
            session = null;
        }
        cardLayout.show(cards, "login");
        statusLabel.setText("Logged out.");
        statusLabel.setForeground(Color.GRAY);
    }
}
