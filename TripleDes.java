package mainPackage;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class TripleDes {
	
	static Scanner sc = new Scanner(System.in);

	public static void main(String[] args){
		
		try {
			// This is where we'll read the key from or write it to
			File keyfile = new File(args[1]);

		    // Going through the arguments to find out what to do
			if (args[0].equals("-g")) { // Generate a key

		        SecretKey key = generateKey();
		        writeKey(key, keyfile);
		        	
		        System.out.println("Secret key written to " + args[1] 
		        		+ " . Protect that file carefully!");
		        
		      } else if (args[0].equals("-e")) {
		    	  
		    	  SecretKey key = readKey(keyfile);
		    	  
		    	  System.out.print("Name of the image file you want to "
		    	  		+ "encrypt: ");
		    	  String in = sc.nextLine();
		    	  System.out.print("Name of the output file of the encrypted "
		    	  		+ "image: ");
		    	  String out = sc.nextLine();
		    	  
		    	  encrypt(key, in, out);
		    	  
		      } else if(args[0].equals("-d")) {
		    	  
		    	  SecretKey key = readKey(keyfile);
		    	  
		    	  System.out.print("Name of the image file you want to "
		    	  		+ "decrypt: ");
		    	  String in = sc.nextLine();
		    	  System.out.print("Name of the output file of the decrypted "
		    	  		+ "image: ");
		    	  String out = sc.nextLine();
		    	  
		    	  decrypt(key, in, out);
		      }
			
		} catch (Exception e){
			System.err.println(e);
			System.err.println("Usage: java " + TripleDes.class.getName() 
					+ " -d|-e|-g| <keyfile>");
		}
		
		sc.close();
	}
	
	  /* Generate a secret TripleDES encryption/decryption key */
	  public static SecretKey generateKey() throws NoSuchAlgorithmException {

		// Get a key generator for Triple DES (a.k.a DESede)
	    KeyGenerator keygen = KeyGenerator.getInstance("DESede");
	    
	    // Use it to generate a key
	    return keygen.generateKey();
	    
	  }

	  /* Save the specified TripleDES SecretKey to the specified file */
	  public static void writeKey(SecretKey key, File keyfile) throws 
	  IOException, NoSuchAlgorithmException, InvalidKeySpecException {
	    
		// Convert the secret key to an array of bytes like this
	    SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
	    
	    FileOutputStream out = new FileOutputStream(keyfile);
	    DESedeKeySpec keyspec = (DESedeKeySpec) keyfactory.getKeySpec(key, 
	    		DESedeKeySpec.class);
	    byte[] rawkey = keyspec.getKey();
	    
	    // Write the raw key to the file
	    out.write(rawkey);
	    out.close();
	  
	  }
	  
	  public static SecretKey readKey(File keyfile) throws IOException, 
	  InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		  
		  // Reads the raw bytes from the key file
		  // You might be able to only use FileInputStream
		  DataInputStream in = new DataInputStream
				  (new FileInputStream(keyfile));
		  byte[] rawkey = new byte[(int) keyfile.length()]; 
		  in.readFully(rawkey);
		  in.close();
		  
		  // Converts it to the secret key
		  DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
		  SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
		  SecretKey key = keyfactory.generateSecret(keyspec);
		  return key;
		  
	  }
	  
	  
	  public static void encrypt(SecretKey key, String in, String out) throws 
	  IOException {
		    
		  // Converting the original image to a byte array
		  File inputFile = new File(in);
		  byte[] fileContent = Files.readAllBytes(inputFile.toPath());
		  
		  byte[] encrypted = null;
		  // Create and initialize the encryption engine
		  try {
			  Cipher cipher = Cipher.getInstance("DESede");
			  cipher.init(Cipher.ENCRYPT_MODE, key);
			  encrypted = cipher.doFinal(fileContent);
		  
		  } catch (Exception e) {
			  e.printStackTrace();
		  }
		  
		  saveFile(encrypted, out);
		  System.out.println("Encryption completed!");
	  }
	  
	  public static void decrypt(SecretKey key, String in, String out) throws 
	  IOException {
		  
		  // Converting the original image to a byte array
		  File inputFile = new File(in);
		  byte[] encryptedContent = Files.readAllBytes(inputFile.toPath());
		  
		  byte[] decrypted = null;
		  // Create and initialize the decryption engine
		  try {
			  Cipher cipher = Cipher.getInstance("DESede");
			  cipher.init(Cipher.DECRYPT_MODE, key);
			  decrypted = cipher.doFinal(encryptedContent);
			  
		  } 
			  catch (BadPaddingException bpe) {
			
			  System.out.println("Wrong key provided!");
			  return;
			  
		  } catch (Exception e) {
			  
			  e.printStackTrace();
		  }
		  
		  saveFile(decrypted, out);
		  System.out.println("Decryption completed!");
	  }
		  
		    
	  public static void saveFile(byte[] bytes, String output) throws 
	  IOException {
		  
		  FileOutputStream fos = new FileOutputStream(output);
		  fos.write(bytes);
		  fos.close();
		  
	  }
}
