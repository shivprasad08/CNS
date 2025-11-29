import java.io.*;
import java.net.*;
import java.util.Scanner;

public class GBNSocketServer {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(12345);
            System.out.println("Server started. Waiting for client...");

            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected.");

            DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());

            int[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            int windowSize = dis.readInt();
            System.out.println("Client requested window size: " + windowSize);

            int base = 0;
            while(base < data.length) {
                for(int i = 0; i < windowSize && (base + 1) < data.length; i++) {
                    int packet = data[base + 1];
                    System.out.println("Server sending packet: " + packet);
                    dos.writeInt(packet);
                    Thread.sleep(500);
                }

                int ack = dis.readInt();
                System.out.println("Server recieved ACK for packet: " + ack);

                base = ack + 1;
            }

            System.out.println("All packt sent. Closing connection.");
            dos.writeInt(-1);
            clientSocket.close();
            serverSocket.close();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
