package vaultlink.client;

import vaultlink.common.ProtocolConstants;

import javax.swing.*;

/**
 * ATM Client entry point. Usage: java vaultlink.client.ATMClient [configPath [host [port]]]
 * Default: src/config/atm1.properties, localhost, 9000
 */
public class ATMClient {

    public static void main(String[] args) {
        String configPath = "src/config/atm1.properties";
        String host = "localhost";
        int port = ProtocolConstants.SERVER_PORT;
        if (args.length > 0) configPath = args[0];
        if (args.length > 1) host = args[1];
        if (args.length > 2) port = Integer.parseInt(args[2]);

        String finalConfigPath = configPath;
        String finalHost = host;
        int finalPort = port;
        SwingUtilities.invokeLater(() -> {
            ATMClientGUI gui = new ATMClientGUI(finalConfigPath, finalHost, finalPort);
            gui.setVisible(true);
        });
    }
}
