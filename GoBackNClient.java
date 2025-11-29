import java.io.*;
import java.net.*;

public class GoBackNClient {
    public static void main(String[] args) throws Exception {
        java.util.Scanner sc = new java.util.Scanner(System.in);
        while (true) {
            System.out.println("\n===== Go-Back-N Client Menu =====");
            System.out.println("1. Start Client");
            System.out.println("2. Exit");
            System.out.print("Enter your choice: ");
            int choice = sc.nextInt();
            if (choice == 1) {
                startClient();
            } else if (choice == 2) {
                System.out.println("Exiting Client...");
                break;
            } else {
                System.out.println("Invalid choice. Try again.");
            }
        }
        sc.close();
    }

    public static void startClient() throws Exception {
        Socket s = null;
        try {
            s = new Socket("localhost", 5000);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            int expectedFrame = 0;
            System.out.println("Client started... Waiting for frames...\n");

            while (true) {
                String frame = in.readUTF();
                if (frame.equals("END"))
                    break;

                int sep = frame.indexOf(":");
                // Basic error check
                if (sep == -1 || frame.length() <= 5) {
                    System.out.println("Received malformed frame: " + frame);
                    continue;
                }
                
                int frameNum = Integer.parseInt(frame.substring(5, sep));
                String data = frame.substring(sep + 1);
                
                System.out.println("Received: " + frame);

                // If this is the frame we are expecting
                if (frameNum == expectedFrame) {
                    System.out.println("Accepted: Frame" + frameNum + " Data=" + data);
                    // Send ACK for this frame
                    out.writeUTF("ACK" + frameNum);
                    // Move expectation to the next frame
                    expectedFrame++;
                } else {
                    // Discard the out-of-order frame
                    System.out.println("Discarded: " + frame + " (Expected Frame" + expectedFrame + ")");
                    // Resend ACK for the *last* frame we successfully received
                    out.writeUTF("ACK" + (expectedFrame - 1));
                }
            }
            System.out.println("\nAll frames received successfully.");

        } catch (Exception e) {
            System.out.println("Error in client: " + e.getMessage());
        } finally {
            if (s != null)
                s.close();
        }
    }
}