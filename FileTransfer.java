import java.io.*;
import static java.lang.System.in;
import java.security.*;
import java.net.*;
import java.nio.file.Files;
import java.security.interfaces.*;
import java.util.*;
import javax.crypto.*;
import static javax.crypto.Cipher.WRAP_MODE;
import static javax.crypto.Cipher.getInstance;

public class FileTransfer {
	private static SecretKey secretKey;

	public static void main(String[] args) throws IOException, Exception {
		String option = args[0];
		if (option.equals("makekeys")) {
			makekeys();
		}
		if (option.equals("server")) {
			server(args);
		}
		if (option.equals("client")) {
			client(args);
		}
	}

	public static void makekeys() {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(4096);
			KeyPair kp = gen.genKeyPair();
			PrivateKey privatekey = kp.getPrivate();
			PublicKey publickey = kp.getPublic();
			try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) {
				out.writeObject(publickey);
			} catch (Exception e) {
			}
			try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
				out.writeObject(privatekey);
			} catch (Exception e) {
			}
		} catch (Exception e) {
		}
	}

	public static void client(String[] arg) throws Exception {
		String publicKey = arg[1];
		String host = arg[2];
		int port = Integer.parseInt(arg[3]);
		byte[] sessionKey = createSessionKey(publicKey);
		try (Socket socket = new Socket(host, port)) {
			if (socket.isConnected()) {
				Scanner kb = new Scanner(System.in);
				System.out.println("Connected to Server");
				while (true) {
					System.out.print("Enter Output File: ");
					String outputFileName = kb.nextLine();
					if (outputFileName.equals("quit")) {
						StopMessage stop = new StopMessage(outputFileName);
						OutputStream os = socket.getOutputStream();
						ObjectOutputStream oos = new ObjectOutputStream(os);
						oos.writeObject(stop);
						System.exit(0);
					}
					File outputFile = new File(outputFileName);
					long fileSize = 0;
					int numOfChunks = 0;
					int chunkSize = 0;
					if (outputFile.exists()) {
						fileSize = outputFile.length();
						System.out.print("Enter chunk size[default:1024]: ");
						String chunkStr = kb.nextLine();

						if (chunkStr.length() == 0)
							chunkSize = 1024;
						else
							chunkSize = Integer.parseInt(chunkStr);
						numOfChunks = (int) Math.ceil(((double) fileSize / (double) chunkSize));
					}
					System.out.println("Sending: " + outputFileName + "\tFile Size: " + fileSize + "bytes in "
							+ numOfChunks + " chunks.");
					sendFile(outputFile, numOfChunks, socket, chunkSize, sessionKey);
					System.out.println("Enter 'quit' to quit");
				}
			}

		}
	}

	public static void server(String[] arg) throws IOException, Exception {
		String privateKeyName = arg[1];
		int port = Integer.parseInt(arg[2]);
		try (ServerSocket serverSocket = new ServerSocket(port)) {
			Socket socket = serverSocket.accept();
			String address = socket.getInetAddress().getHostAddress();
			InputStream is = socket.getInputStream();
			ObjectInputStream in = new ObjectInputStream(is);
			OutputStream os = socket.getOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(os);
			while (true) {
				try {
					StartMessage sm = (StartMessage) in.readObject();
					AckMessage am = new AckMessage(0);
					out.writeObject(am);
					Cipher cipher = getInstance("RSA");
					ObjectInputStream importPrivateKey = new ObjectInputStream(new FileInputStream(privateKeyName));
					RSAPrivateKey rsa = (RSAPrivateKey) importPrivateKey.readObject();
					cipher.init(Cipher.UNWRAP_MODE, rsa);
					secretKey = (SecretKey) cipher.unwrap(sm.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
					System.out.println("Session Key successfully decrpyted.");
					int chunkSize = (int) sm.getChunkSize();
					int fileSize = (int) sm.getSize();
					int numOfChunks = (int) (Math.ceil((double) fileSize / (double) chunkSize));
					String finalMessage = "";
					byte[] decryptedChunk;
					for (int i = 0; i < numOfChunks; i++) {
						Chunk c = (Chunk) in.readObject();
						System.out.println("Chunk[" + c.getSeq() + "/" + numOfChunks + "]\treceived.");
						decryptedChunk = decryptChunk(c.getData(), secretKey);
						int checksum = getChecksum(decryptedChunk);
						if (checksum == c.getCrc()) {
							finalMessage += new String(decryptedChunk);
							AckMessage ack = new AckMessage((c.getSeq() + 1));
							out.writeObject(ack);
						} else {
							System.out.println("ERROR WITH FILE TRANSFER\nCLOSING PROGRAM.");
							System.exit(0);
						}
					}

					writeToFile(finalMessage);
					checkEnd(socket);
					out.close();
					os.close();
					is.close();
					in.close();

				} catch (Exception e) {
				}
			}
		}
	}

	public static void sendFile(File outputFile, int numOfChunks, Socket socket, int chunkSize, byte[] sessionKey)
			throws Exception {
		System.out.println("Starting transfer process...");
		StartMessage messageInfo = new StartMessage(outputFile.getName(), sessionKey, chunkSize);

		OutputStream os = socket.getOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(os);
		oos.writeObject(messageInfo);
		System.out.println("Acknowledgement sent...");

		InputStream is = socket.getInputStream();
		ObjectInputStream ois = new ObjectInputStream(is);
		AckMessage am = (AckMessage) ois.readObject();
		if (am.getSeq() == 0)
			System.out.println("Acknowledgement: Success\nSending File...");
		if (am.getSeq() == -1)
			System.out.println("Acknowledgement: Failed");
		byte[] readAllByte = Files.readAllBytes(outputFile.toPath());
		byte[] normalChunks = new byte[chunkSize];
		byte[] lastChunk = new byte[(int) outputFile.length() % chunkSize];
		byte[] encryptedChunk = null;
		int byteCounter = 0;
		int checksum = 0;
		Chunk c;
		for (int i = 1; i <= numOfChunks; i++) {
			int sequence = i;

			if (i == numOfChunks && lastChunk.length > 0) {
				for (int k = 0; k < ((int) outputFile.length() % chunkSize); k++) {
					lastChunk[k] = readAllByte[byteCounter];
					byteCounter++;
				}
				checksum = getChecksum(lastChunk);
				encryptedChunk = encryptChunk(lastChunk);
			} else {
				for (int j = 0; j < chunkSize; j++) {
					normalChunks[j] = readAllByte[byteCounter];
					byteCounter++;
				}
				checksum = getChecksum(normalChunks);
				encryptedChunk = encryptChunk(normalChunks);
			}
			c = new Chunk(sequence, encryptedChunk, checksum);
			oos.writeObject(c);
			System.out.println("Chunk[" + c.getSeq() + "/" + numOfChunks + "]\tsent.");
			AckMessage ack = (AckMessage) ois.readObject();

		}
	}

	public static void checkEnd(Socket socket) {
		try {
			InputStream is = socket.getInputStream();
			ObjectInputStream ois = new ObjectInputStream(is);
			StopMessage stop = new StopMessage("test.txt");
			System.exit(0);
		} catch (Exception e) {
		}
	}

	public static byte[] encryptChunk(byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encryptedChunk = cipher.doFinal(data);
		return encryptedChunk;
	}

	public static byte[] decryptChunk(byte[] data, Key key) throws Exception {
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decryptedChunk = c.doFinal(data);
		return decryptedChunk;
	}

	public static byte[] createSessionKey(String publicKeyName) throws Exception {
		//Creates an AES session key at 128bit strength
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream(publicKeyName));
		RSAPublicKey publicKey = (RSAPublicKey) ois.readObject();
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		secretKey = keyGen.generateKey();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.WRAP_MODE, publicKey);
		byte[] sKey = cipher.wrap(secretKey);
		return sKey;

	}

	public static int getChecksum(byte[] packet) {
		int length = packet.length;
		int i = 0;
		long total = 0;
		int sum = 0;
		while (length > 1) {
			sum = sum + ((packet[i] << 8 & 0xFF00) | ((packet[i + 1]) & 0x00FF));
			i = i + 2;
			length = length - 2;
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum++;
			}
		}

		if (length > 0) {
			sum += packet[i] << 8 & 0xFF00;
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum++;
			}
		}
		return sum;
	}

	public static void writeToFile(String msg) throws IOException {

		BufferedWriter out = new BufferedWriter(new FileWriter("output.txt"));
		out.write(msg);
		out.close();

	}

}