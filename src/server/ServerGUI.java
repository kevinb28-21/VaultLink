package vaultlink.server;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Server GUI: scrollable log, active connections list, "View Audit Log" button.
 */
public class ServerGUI extends JFrame implements ClientHandler.ServerGUICallback {

    private final JTextArea logArea;
    private final JList<String> connectionsList;
    private final DefaultListModel<String> connectionsModel;
    private final AuditLogger auditLogger;
    private final AccountManager accountManager;

    public ServerGUI(AuditLogger auditLogger, AccountManager accountManager) {
        this.auditLogger = auditLogger;
        this.accountManager = accountManager;
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

        JButton viewAuditButton = new JButton("View Audit Log");
        viewAuditButton.addActionListener(e -> showAuditLog());

        JPanel top = new JPanel(new BorderLayout());
        top.add(logScroll, BorderLayout.CENTER);
        JPanel right = new JPanel(new BorderLayout());
        right.add(connPanel, BorderLayout.CENTER);
        right.add(viewAuditButton, BorderLayout.SOUTH);
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
