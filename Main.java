import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

/*

AUTHORS: BEN KURZION & ROHITH ESHWARWAK
CASE ID: bxk389, rxe136

PROJECT: CSDS 344 PASSWORD MANAGER

 */

public class PasswordManager {
    public static void main(String[] args) {

        /**
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String base64Salt = Base64.getEncoder().encodeToString(salt);
        String knownData = "Hello";
        String passWord = "Desk";

        byte[] h = hashPassword(salt, passWord);
        String token = encrypt(h, knownData);

        System.out.println(decrypt(h, token));
         */




        // Check if password file exists or not

        Scanner scanner = new Scanner(System.in);
        String userEnteredPassword = "";

        // check for a password file
        File file = getPasswordFile();
        boolean noFile = false;

        try {
            noFile = file.createNewFile();
            System.out.println(noFile);
        }
        catch (IOException e) {
           System.out.println("Error with file checking");
        }

        if (!noFile){
            boolean correctPassword = false;
            System.out.println("Please enter the passcode to access your passwords:");
            userEnteredPassword = scanner.nextLine();
            while (!correctPassword){

                //String userEnteredPassword = scanner.nextLine();
                if (verifyPassword(userEnteredPassword, file, "hello")){
                    correctPassword = true;
                }else{
                    System.out.println("Wrong password entered");
                    System.out.println("Please enter correct password");
                    userEnteredPassword = scanner.nextLine();
                }
            }


        }else{
            // No password file
            System.out.println("No password file detected. Creating a new password file.");
            System.out.println("Please enter a passcode to access your passwords:");
            userEnteredPassword = scanner.nextLine();
            /**
            try{
                if (file.createNewFile()){
                    System.out.println("No password file detected. Creating a new password file.");
                }
            }catch (Exception e){
                System.out.println("Error in creating a file");
            }
             */

            // make the salt

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            String base64Salt = Base64.getEncoder().encodeToString(salt);

            // DO SOMETHING WITH THE PASSWORD. HASH OR ENCRYPT? NOT CLEAR. ASK BRIAN

            String encryptedToken = encrypt(hashPassword(salt, userEnteredPassword),"hello");

            //String base64Token = Base64.getEncoder().encodeToString(encryptedToken.getBytes());
            try {
                addSaltAndToken(base64Salt, encryptedToken);
            }catch (Exception e){
                System.out.println("Cannot write to file");
            }


        }
        // The main loop

        while (true){
            System.out.println("a : Add password");
            System.out.println("r : Read password");
            System.out.println("q : Quit");
            System.out.println("Enter choice:");
            String userChoice = scanner.nextLine();
            if (userChoice.equals("a")){
                // add a password
                System.out.println("Enter a label for the password:");
                String label = scanner.nextLine();
                System.out.println("Enter a password to store:");
                String password = scanner.nextLine();
                addPassword(label, file, password);


            }else if (userChoice.equals("r")){
                // read a password
                System.out.println("Enter a label for the password:");
                String label = scanner.nextLine();
                // check that there exists a password associated with this label
                // if it exits then print the password, else complain about bad label
            }else if (userChoice.equals("q")){
                // Quit
                System.out.println("Quitting");
                System.exit(0);
            }else{
                System.out.println("Not a valid option. Please try again");
            }
        }

    }


    private static boolean verifyPassword(String userEnteredPassword, File file, String knownData) {
        // Hash the salt + password and compare it to the hash stored in the secrets file
        String[] saltAndToken = getSaltAndToken();
        assert saltAndToken != null;
        String decryptedToken = decrypt(hashPassword(Base64.getDecoder().decode(saltAndToken[0]), userEnteredPassword), saltAndToken[1]);
        if (decryptedToken == null)
             return false;
        return decryptedToken.equals(knownData);
    }

    private static byte[] hashPassword(byte[] salt, String key) {
        try {
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 600000, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey sharedKey = factory.generateSecret(spec);
            return sharedKey.getEncoded();
        }catch (Exception e){
            System.out.println("Issues generating encryption key");
        }
        return null;

    }

    private static String encrypt(byte[] hash, String knownData) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(hash, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(knownData.getBytes());
            String messageString = new String(Base64.getEncoder().encode(encryptedData));
            return messageString;

        }
        catch (Exception e) {
            System.out.println("There was an exception during encryption");
        }
        return null;
    }

    private static String decrypt(byte[] hash, String encryptedToken) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(hash, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte [] decoded = Base64.getDecoder().decode(encryptedToken);
            byte [] decrypted = cipher.doFinal(decoded);
            return new String(decrypted);
        }catch (Exception e){
            //System.out.println("Issues decrypting password");
            //e.printStackTrace();
        }
        return null;

    }

    private static File getPasswordFile() {
        // Returns whether there exists a file with all of the  password manager information
            //System.out.println("No password file detected. Creating a new password file.");
            String currentPath = System.getProperty("user.dir");
            String fileName = "secrets.txt";
            return new File(currentPath, fileName);
    }

    private static void addSaltAndToken(String salt, String encryptedToken) {
        try {
            FileWriter fw = new FileWriter("secrets.txt", true);
            //BufferedWriter writer give better performance
            BufferedWriter bw = new BufferedWriter(fw);
            fw.write(salt+':'+encryptedToken);
            bw.close();

        }
        catch(IOException e) {
            System.out.println("There was an issue writing to file");
        }
    }

    private static String[] getSaltAndToken() {
        try {
            FileReader fr = new FileReader("secrets.txt");
            BufferedReader br = new BufferedReader(fr);
            String[] saltAndToken = br.readLine().split(":");
            String base64Salt = saltAndToken[0];
            String base64Password = saltAndToken[1];
            String[] vals = {base64Salt, base64Password};
            return vals;
        }
        catch(IOException e) {
            System.out.println("Error reading file");
        }
        return null;
    }

    private static void deleteLine(String label, String filePath, String newPassword) {


        Path path = Paths.get(filePath);
        boolean updated = false;
        String newLine = "";
        try {
            List<String> lines = Files.readAllLines(path);
            List<String> updatedLines = new ArrayList<>();
            for (String line: lines) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2 && parts[0].equals(label) && !updated) {
                    System.out.println("Updating");
                    updated = true;
                    newLine = label + ":" + newPassword;

                }
                else {
                    newLine = line;
                }
                updatedLines.add(newLine);
            }
            Files.write(path, updatedLines);
        } catch (IOException e) {
            System.err.println("Error processing file: " + e.getMessage());
        }

    }


    private static void addPassword(String label, File file, String password) {
        try {
            FileReader fr = new FileReader(file.getName());
            BufferedReader br = new BufferedReader(fr);
            FileWriter fw = new FileWriter(file.getName(), true);
            BufferedWriter bw = new BufferedWriter(fw);
            String key = null;
            String value = null;
            String[] keyValPair = null;
            String line = br.readLine();
            int lineNumber = 1;

            while(line!= null) {
                keyValPair = line.split(":");
                key = keyValPair[0];
                if (key.equals(label) && lineNumber > 1) {

                    // The password will have to be encrypted. Here 'password' is assumed to be encrypted

                    deleteLine(label, file.getPath(), password);
                }
                line = br.readLine();
                lineNumber++;
            }
            bw.write(label+":"+password);
            bw.newLine();
            br.close();
            bw.close();

        }
        catch (IOException e) {
            System.out.println("Error reading file");
        }
    }

}
