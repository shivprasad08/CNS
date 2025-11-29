import java.io.*;
import java.net.*;
import java.util.*;

public class GoBackNServer {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        while (true) {
            System.out.println("\n===== Go-Back-N Server Menu =====");
            System.out.println("1. Start Server");
            System.out.println("2. Exit");
            System.out.print("Enter your choice: ");
            int choice = sc.nextInt();
            if (choice == 1) {
                startServer();
            } else if (choice == 2) {
                System.out.println("Exiting Server...");
                break;

            } else {
                System.out.println("Invalid choice. Try again.");
            }
        }
        sc.close();
    }

    public static void startServer() throws Exception {
        ServerSocket ss = new ServerSocket(5000);
        System.out.println("Waiting for client to connect...");
        Socket s = ss.accept();
        System.out.println("Client connected.");
        
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        DataInputStream in = new DataInputStream(s.getInputStream());
        Scanner sc = new Scanner(System.in);

        System.out.print("Enter total frames to send: ");
        int totalFrames = sc.nextInt();
        System.out.print("Enter window size: ");
        int windowSize = sc.nextInt();
        sc.nextLine(); // consume newline

        String[] frameData = new String[totalFrames];
        for (int i = 0; i < totalFrames; i++) {
            System.out.print("Enter data for Frame" + i + ": ");
            frameData[i] = sc.nextLine();
        }

        int base = 0;
        int nextFrame = 0;

        while (base < totalFrames) {
            // Send all frames in the current window
            while (nextFrame < base + windowSize && nextFrame < totalFrames) {
                String frame = "Frame" + nextFrame + ":" + frameData[nextFrame];
                System.out.println("Sent: " + frame);
                out.writeUTF(frame);
                nextFrame++;
            }

            // Wait for ACK
            // In a real Go-Back-N, you'd have a timer and handle timeouts/retransmissions
            String ack = in.readUTF();
            int ackNum = Integer.parseInt(ack.replace("ACK", ""));
            System.out.println("Received: " + ack);

            // Slide the window base
            base = ackNum + 1;
            
            // In this simple simulation, if an ACK is received for frame N,
            // it implies all frames up to N are received.
            
            Thread.sleep(500); // Small delay for simulation
        }
        System.out.println("All frames sent successfully.");
        out.writeUTF("END");
        s.close();
        ss.close();
    }
}