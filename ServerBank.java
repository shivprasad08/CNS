import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;

// Defines the structure for data packets sent between server and client.
class Packet implements Serializable {
    private static final long serialVersionUID = 1L;
    
    // Enum to specify the type of packet.
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

// Represents a single financial transaction.
class Transaction {
    private String timestamp;
    private String type;
    private double amount;
    private double newBalance;
    
    public Transaction(String type, double amount, double newBalance) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.timestamp = sdf.format(new Date());
        this.type = type;
        this.amount = amount;
        this.newBalance = newBalance;
    }
    
    @Override
    public String toString() {
        return String.format("[%s] %s: Rs.%.2f | New Balance: Rs.%.2f", 
                             timestamp, type, amount, newBalance);
    }
}

// Main server class that manages the wallet and handles client connections.
public class ServerBank {
    // --- Server Configuration ---
    private static final int PORT = 5000;
    private static final double MIN_BALANCE = 2000.0;
    private static final int WINDOW_SIZE = 4; // For Go-Back-N
    private static final int TIMEOUT_MS = 2000; // For Go-Back-N
    private static final double PACKET_LOSS_RATE = 0.2; // To simulate network issues
    
    private double balance;
    private List<Transaction> transactionHistory;
    private Random random;
    
    public ServerBank() {
        this.balance = 5000.0; // Initial account balance
        this.transactionHistory = new ArrayList<>();
        this.random = new Random();
        System.out.println("===========================================");
        System.out.println("           WALLET SERVER APPLICATION");
        System.out.println("===========================================");
        System.out.println("Server initialized with balance: Rs." + balance);
        System.out.println("Minimum balance requirement: Rs." + MIN_BALANCE);
    }
    
    public static void main(String[] args) {
        ServerBank server = new ServerBank();
        server.start();
    }
    
    // Starts the server and listens for incoming client connections.
    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);
            System.out.println("Waiting for client connection...\n");
            
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println(">>> Client connected: " + clientSocket.getInetAddress());
                // Creates a new thread for each client to handle them concurrently.
                new ClientHandler(clientSocket).start();
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // Processes a credit request. Synchronized to prevent race conditions.
    private synchronized String processCredit(double amount) {
        if (amount <= 0) {
            return "ERROR: Amount must be positive.";
        }
        balance += amount;
        transactionHistory.add(new Transaction("CREDITED", amount, balance));
        System.out.println("SUCCESS: Credit processed: Rs." + amount + " | New Balance: Rs." + balance);
        return String.format("SUCCESS: Rs.%.2f credited to the account. New Balance: Rs.%.2f", 
                             amount, balance);
    }
    
    // Processes a debit request. Synchronized to ensure thread safety.
    private synchronized String processDebit(double amount) {
        if (amount <= 0) {
            return "ERROR: Amount must be positive.";
        }
        if (balance - amount < MIN_BALANCE) {
            System.out.println("DENIED: Debit of Rs." + amount + " would breach minimum balance.");
            return String.format("ERROR: Insufficient funds. A minimum balance of Rs.%.2f must be maintained. Current Balance: Rs.%.2f", 
                                 MIN_BALANCE, balance);
        }
        balance -= amount;
        transactionHistory.add(new Transaction("DEBITED", amount, balance));
        System.out.println("SUCCESS: Debit processed: Rs." + amount + " | New Balance: Rs." + balance);
        return String.format("SUCCESS: Rs.%.2f debited from the account. New Balance: Rs.%.2f", 
                             amount, balance);
    }
    
    // Retrieves the formatted transaction history.
    private synchronized List<String> getTransactionHistory() {
        List<String> history = new ArrayList<>();
        if (transactionHistory.isEmpty()) {
            history.add("No transactions have been recorded yet.");
        } else {
            history.add("=== Transaction History ===");
            for (Transaction t : transactionHistory) {
                history.add(t.toString());
            }
            history.add(String.format("=== Current Balance: Rs.%.2f ===", balance));
        }
        return history;
    }
    
    // Thread to handle communication with a single client.
    class ClientHandler extends Thread {
        private Socket socket;
        private ObjectOutputStream out;
        private ObjectInputStream in;
        
        public ClientHandler(Socket socket) {
            this.socket = socket;
        }
        
        @Override
        public void run() {
            try {
                out = new ObjectOutputStream(socket.getOutputStream());
                out.flush();
                in = new ObjectInputStream(socket.getInputStream());
                
                // Main loop to listen for client requests.
                while (true) {
                    Packet request = (Packet) in.readObject();
                    System.out.println("\n[REQUEST] Received " + request.getType() + " from client");
                    
                    switch (request.getType()) {
                        case CREDIT:
                            double creditAmount = Double.parseDouble(request.getData());
                            String creditResponse = processCredit(creditAmount);
                            out.writeObject(new Packet(Packet.PacketType.RESPONSE, 0, creditResponse));
                            out.flush();
                            break;
                            
                        case DEBIT:
                            double debitAmount = Double.parseDouble(request.getData());
                            String debitResponse = processDebit(debitAmount);
                            out.writeObject(new Packet(Packet.PacketType.RESPONSE, 0, debitResponse));
                            out.flush();
                            break;
                            
                        case HISTORY:
                            System.out.println("Client requested history. Starting Go-Back-N transmission...");
                            sendHistoryWithGoBackN();
                            break;
                            
                        default:
                             // Handle unknown packet types if necessary
                            break;
                    }
                }
                
            } catch (EOFException e) {
                // This exception is expected when a client disconnects cleanly.
                System.out.println(">>> Client " + socket.getInetAddress() + " disconnected.");
            } catch (Exception e) {
                System.err.println("Client handler error: " + e.getMessage());
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
        
        // Implements the Go-Back-N protocol to send transaction history reliably.
        private void sendHistoryWithGoBackN() throws IOException, ClassNotFoundException {
            List<String> history = getTransactionHistory();
            List<Packet> packets = new ArrayList<>();
            
            // Convert history lines into data packets.
            for (int i = 0; i < history.size(); i++) {
                packets.add(new Packet(Packet.PacketType.DATA, i, history.get(i)));
            }
            
            int base = 0;
            int nextSeqNum = 0;
            
            System.out.println("Go-Back-N Details: Total packets = " + packets.size() + ", Window size = " + WINDOW_SIZE);
            
            while (base < packets.size()) {
                // Send all packets within the current window.
                while (nextSeqNum < base + WINDOW_SIZE && nextSeqNum < packets.size()) {
                    Packet packet = packets.get(nextSeqNum);
                    
                    // Simulate packet loss to test reliability.
                    if (random.nextDouble() < PACKET_LOSS_RATE) {
                        System.out.println("  [SIMULATED LOSS] Packet " + nextSeqNum + " was not sent.");
                    } else {
                        out.writeObject(packet);
                        out.flush();
                        System.out.println("  [SENT] Packet " + nextSeqNum);
                    }
                    nextSeqNum++;
                }
                
                // Set a timeout to wait for an ACK.
                socket.setSoTimeout(TIMEOUT_MS);
                try {
                    Packet ack = (Packet) in.readObject();
                    
                    if (ack.getType() == Packet.PacketType.ACK) {
                        int ackNum = ack.getSequenceNumber();
                        System.out.println("  [ACK RECEIVED] For packet " + ackNum);
                        
                        // Slide the window forward.
                        if (ackNum >= base) {
                           base = ackNum + 1;
                        }
                    }
                } catch (SocketTimeoutException e) {
                    // If timeout occurs, retransmit from the base of the window.
                    System.out.println("  [TIMEOUT] No ACK received. Retransmitting from packet " + base);
                    nextSeqNum = base; 
                }
            }
            
            // Send End of Transmission packet.
            Packet eot = new Packet(Packet.PacketType.EOT, packets.size(), "END");
            out.writeObject(eot);
            out.flush();
            System.out.println("  [EOT SENT] History transmission complete.\n");
        }
    }
}

