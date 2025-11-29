import java.io.*;
import java.net.*;
import java.util.Scanner;

public class GBNSocketClient {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 12345);
            System.out.println("Connected to server.");

            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            Scanner scanner = new Scanner(System.in);

            System.out.print("Enter the window size: ");
            int windowSize = scanner.nextInt();
            dos.writeInt(windowSize);

            int recievedPacket;
            while((recievedPacket = dis.readInt()) != -1) {
                System.out.println("CLient recieved packet: " + recievedPacket);

                dos.writeInt(recievedPacket);
                System.out.println("Client sending ACK for packet: " + recievedPacket);
            }

            System.out.println("End of transmission. Closing connection.");
            socket.close();
            scanner.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
