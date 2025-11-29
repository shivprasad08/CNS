import java.io.*;
import java.net.*;
import java.util.*;

// Defines the structure for data packets, identical to the server's version.
class Packet implements Serializable {
    private static final long serialVersionUID = 1L;
    
    enum PacketType {
        DATA, ACK, EOT, CREDIT, DEBIT, HISTORY, RESPONSE
    }
    
    private PacketType type;
    private int sequenceNumber;
    private String data;
    
    public Packet(PacketType type, int sequenceNumber, String data) {
        this.type = type;
        this.sequenceNumber = sequenceNumber;
        this.data = data;
    }
    
    public PacketType getType() { return type; }
    public int getSequenceNumber() { return sequenceNumber; }
    public String getData() { return data; }
    
    @Override
    public String toString() {
        return String.format("Packet[type=%s, seq=%d, data=%s]", type, sequenceNumber, 
                             data != null && data.length() > 50 ? data.substring(0, 50) + "..." : data);
    }
}

// Main client class that provides the user interface.
public class ClientBank {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 5000;
    
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private Scanner scanner;
    
    public ClientBank() {
        scanner = new Scanner(System.in);
    }
    
    public static void main(String[] args) {
        ClientBank client = new ClientBank();
        client.start();
    }
    
    // Initializes the client, connects to the server, and shows the menu.
    public void start() {
        try {
            displayWelcome();
            connect();
            showMenu();
        } catch (Exception e) {
            System.err.println("\nClient error: " + e.getMessage());
            if (e instanceof ConnectException) {
                System.err.println("Could not connect to the server. Please ensure the server is running.");
            }
        } finally {
            disconnect();
        }
    }
    
    private void displayWelcome() {
        System.out.println("===========================================");
        System.out.println("           DIGITAL WALLET CLIENT");
        System.out.println("===========================================");
    }
    
    // Establishes a connection with the server.
    private void connect() throws IOException {
        System.out.println("Attempting to connect to server at " + SERVER_HOST + ":" + SERVER_PORT + "...");
        socket = new Socket(SERVER_HOST, SERVER_PORT);
        out = new ObjectOutputStream(socket.getOutputStream());
        out.flush();
        in = new ObjectInputStream(socket.getInputStream());
        System.out.println("SUCCESS: Connected to the server.\n");
    }
    
    // Closes all resources cleanly.
    private void disconnect() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (socket != null) socket.close();
            scanner.close();
            System.out.println("\nSUCCESS: You have been disconnected from the server. Goodbye!");
        } catch (IOException e) {
            System.err.println("Error while closing connection: " + e.getMessage());
        }
    }
    
    // Main menu loop for user interaction.
    private void showMenu() {
        while (true) {
            System.out.println("\n+----------------------------------------+");
            System.out.println("|              WALLET MENU               |");
            System.out.println("+----------------------------------------+");
            System.out.println("|  1. Credit Funds                       |");
            System.out.println("|  2. Debit Funds                        |");
            System.out.println("|  3. View Transaction History           |");
            System.out.println("|  4. Exit                               |");
            System.out.println("+----------------------------------------+");
            System.out.print("Enter your choice (1-4): ");
            
            String choice = scanner.nextLine().trim();
            
            try {
                switch (choice) {
                    case "1":
                        handleCredit();
                        break;
                    case "2":
                        handleDebit();
                        break;
                    case "3":
                        handleHistory();
                        break;
                    case "4":
                        System.out.println("\nExiting application...");
                        return;
                    default:
                        System.out.println("ERROR: Invalid choice. Please enter a number from 1 to 4.");
                }
            } catch (Exception e) {
                System.err.println("ERROR: An error occurred while processing your request: " + e.getMessage());
                System.out.println("The connection to the server may have been lost. Please restart the client.");
                return;
            }
        }
    }
    
    // Handles the credit operation.
    private void handleCredit() throws IOException, ClassNotFoundException {
        System.out.println("\n--- CREDIT OPERATION ---");
        System.out.print("Enter amount to credit: Rs. ");
        String input = scanner.nextLine().trim();
        
        try {
            double amount = Double.parseDouble(input);
            
            if (amount <= 0) {
                System.out.println("ERROR: Amount must be a positive number.");
                return;
            }
            
            System.out.println("Sending credit request to the server...");
            Packet request = new Packet(Packet.PacketType.CREDIT, 0, String.valueOf(amount));
            out.writeObject(request);
            out.flush();
            
            Packet response = (Packet) in.readObject();
            System.out.println("\nServer Response: " + response.getData());
            
        } catch (NumberFormatException e) {
            System.out.println("ERROR: Invalid input. Please enter a valid number.");
        }
    }
    
    // Handles the debit operation.
    private void handleDebit() throws IOException, ClassNotFoundException {
        System.out.println("\n--- DEBIT OPERATION ---");
        System.out.print("Enter amount to debit: Rs. ");
        String input = scanner.nextLine().trim();
        
        try {
            double amount = Double.parseDouble(input);
            
            if (amount <= 0) {
                System.out.println("ERROR: Amount must be a positive number.");
                return;
            }
            
            System.out.println("Sending debit request to the server...");
            Packet request = new Packet(Packet.PacketType.DEBIT, 0, String.valueOf(amount));
            out.writeObject(request);
            out.flush();
            
            Packet response = (Packet) in.readObject();
            System.out.println("\nServer Response: " + response.getData());
            
        } catch (NumberFormatException e) {
            System.out.println("ERROR: Invalid input. Please enter a valid number.");
        }
    }
    
    // Initiates the request for transaction history.
    private void handleHistory() throws IOException, ClassNotFoundException {
        System.out.println("\n--- TRANSACTION HISTORY ---");
        System.out.println("Requesting transaction history from the server...");
        System.out.println("(This uses the Go-Back-N protocol for reliable delivery)\n");
        
        Packet request = new Packet(Packet.PacketType.HISTORY, 0, null);
        out.writeObject(request);
        out.flush();
        
        // The actual reception is handled by the Go-Back-N logic.
        receiveHistoryWithGoBackN();
    }
    
    // Implements the receiver side of the Go-Back-N protocol.
    private void receiveHistoryWithGoBackN() throws IOException, ClassNotFoundException {
        int expectedSeqNum = 0;
        List<String> receivedData = new ArrayList<>();
        
        System.out.println("Receiving packets from server...\n");
        
        while (true) {
            Packet packet = (Packet) in.readObject();
            
            // End of Transmission packet marks the end of the history.
            if (packet.getType() == Packet.PacketType.EOT) {
                System.out.println("  [EOT RECEIVED] Full transaction history received.\n");
                break;
            }
            
            if (packet.getType() == Packet.PacketType.DATA) {
                int seqNum = packet.getSequenceNumber();
                
                // If the packet is the one we expect, process it.
                if (seqNum == expectedSeqNum) {
                    receivedData.add(packet.getData());
                    System.out.println("  SUCCESS: Packet " + seqNum + " received in order.");
                    
                    // Send an ACK for the received packet.
                    Packet ack = new Packet(Packet.PacketType.ACK, seqNum, null);
                    out.writeObject(ack);
                    out.flush();
                    System.out.println("  -> ACK for packet " + seqNum + " sent.");
                    
                    expectedSeqNum++;
                } else {
                    // If an out-of-order packet arrives, discard it and resend the last ACK.
                    System.out.println("  WARN: Packet " + seqNum + " received out of order (expected " + 
                                       expectedSeqNum + "). Discarding.");
                    
                    if (expectedSeqNum > 0) {
                        Packet ack = new Packet(Packet.PacketType.ACK, expectedSeqNum - 1, null);
                        out.writeObject(ack);
                        out.flush();
                        System.out.println("  -> ACK for packet " + (expectedSeqNum - 1) + " resent.");
                    }
                }
            }
        }
        
        // Display the fully received transaction history.
        System.out.println("+--------------------------------------------------------------------------+");
        System.out.println("|                         TRANSACTION HISTORY                              |");
        System.out.println("+--------------------------------------------------------------------------+");
        
        if (receivedData.isEmpty()) {
            System.out.println("No data was received from the server.");
        } else {
            for (String line : receivedData) {
                System.out.println(line);
            }
        }
        
        System.out.println("----------------------------------------------------------------------------");
    }
}

