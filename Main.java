import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

/*

AUTHORS: BEN KURZION & ROHITH ESHWARWAK
CASE ID: bxk389, rxe136

PROJECT: CSDS 344 PASSWORD MANAGER

 */

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // check for a password file
        File file = getPasswordFile();
        if (file.isFile()){
            boolean correctPassword = false;
            while (!correctPassword){
                System.out.println("Please enter the passcode to access your passwords:");
                String userEnteredPassword = scanner.nextLine();
                if (verifyPassword(userEnteredPassword)){
                    correctPassword = true;
                }else{
                    System.out.println("Wrong password entered");
                }
            }
        }else{
            // No password file
            System.out.println("Please enter a passcode to access your passwords:");
            String userEnteredPassword = scanner.nextLine();
            try{
                if (file.createNewFile()){
                    System.out.println("No password file detected. Creating a new password file.");
                }
            }catch (Exception e){
                System.out.println("Error in creating a file");
            }
            // make the salt
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            try {
                KeySpec spec = new PBEKeySpec(userEnteredPassword.toCharArray(), salt, 600000, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey sharedKey = factory.generateSecret(spec);
                byte[] encoded = sharedKey.getEncoded();
            } catch (Exception e) {
                System.out.println("Error in encoding ");
            }

            String base64Salt = Base64.getEncoder().encodeToString(salt);


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





    private static boolean verifyPassword(String userEnteredPassword){
        // Hash the salt + password and compare it to the hash stored in the secrets file
        String storedHash = "";
        String userHash = "";

        return storedHash.equals(userHash);
    }

    private static File getPasswordFile(){
        // Returns whether there exists a file with all of the password manager information
        String currentPath = System.getProperty("user.dir");
        String fileName = "secrets.txt";
        return new File(currentPath, fileName);
    }

    private static byte[] getSalt(){
        // Returns the salt used for all passwords
        // salt is stored in Base64
        return new byte[1];
    }
}