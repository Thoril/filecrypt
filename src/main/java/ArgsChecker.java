import org.apache.commons.cli.*;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Enumeration;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ArgsChecker {
    private int mode;
    private String[] input;
    private String output;
    private String password;

    public Boolean getInputZip() {
        return inputZip;
    }

    public void setInputZip(Boolean inputZip) {
        this.inputZip = inputZip;
    }

    private Boolean inputZip;

    public ArgsChecker(String[] args) {
        parsArgs(args);
    }

    public void parsArgs(String[] args){
        CommandLine commandLine = null;
        Option optionDec = Option.builder("d")
                .required(false)
                .hasArg(false)
                .desc("decrypt mode")
                .longOpt("dec")
                .build();
        Option optionEnc = Option.builder("e")
                .required(false)
                .hasArg(false)
                .desc("encrypt mode")
                .longOpt("enc")
                .build();
        Option optionInput = Option.builder("i")
                .required(true)
                .hasArgs()
                .desc("input file")
                .longOpt("input")
                .build();
        Option optionOutput = Option.builder("o")
                .required(true)
                .hasArg(true)
                .desc("output file")
                .longOpt("output")
                .build();
        Option optionPassword = Option.builder("p")
                .required(true)
                .hasArg(true)
                .desc("password")
                .longOpt("pass")
                .build();

        Options options = new Options();
        CommandLineParser parser = new DefaultParser();
        options.addOption(optionEnc);
        options.addOption(optionDec);
        options.addOption(optionInput);
        options.addOption(optionOutput);
        options.addOption(optionPassword);

        try
        {
            commandLine = parser.parse(options, args);
        }
        catch (ParseException exception)
        {
            System.out.print("Parse error: ");
            System.out.println(exception.getMessage());
            System.exit(1);
        }

        if (commandLine.hasOption("d"))
        {
            this.mode = 2;
        }
        else if (commandLine.hasOption("e"))
        {
            this.mode = 1;
        }
        if (commandLine.hasOption("i"))
        {
            this.setInput(commandLine.getOptionValues("input"));
        }
        if (commandLine.hasOption("o"))
        {
            this.setOutput(commandLine.getOptionValue("output"));
        }
        if (commandLine.hasOption("p")){
            this.setPassword(commandLine.getOptionValue("pass"));
        }
    }

    public int getMode() {
        return mode;
    }


    public String[] getInput() {
        return input;
    }

    private void setInput(String[] input) {

        if (FilenameUtils.getExtension(input[0]).equals("zip") && input.length == 1) {
            this.inputZip = true;
        } else {
            this.inputZip = false;
            for (String in : input) {
                File f = new File(in);
                if (!f.isFile()) {
                    System.out.println("Fichier non valide");
                    System.exit(1);
                }
            }
        }
        this.input = input;

    }

    public String getOutput() {
        return output;
    }

    private void setOutput(String output) {
        File f = new File(output);
        if(f.exists())
        {
            System.out.print("Le fichier existe déja voulez-vous l'écraser (yes/no) : ");
            Scanner sc = new Scanner(System.in);
            String ans = sc.next();
            if(ans.equals("yes") | ans.equals("y")){
                this.output = output;
            }else{
                System.exit(1);
            }
        }else {
            this.output = output;
        }
    }

    private void setPassword(String password){

        if(password.matches("[a-zA-Z0-9]+")){
            if(password.length() <22){
                //62^x = 2^128 => x = 21,4
                System.out.println("Taille du mot de passe insufisante (Mini 22 caracteères");
                System.exit(1);
            }else{
                this.password = password;
            }
        }else{
            System.out.println("Erreur le mot de passe doit contenir uniquement des lettres et des chiffres");
            System.exit(1);
        }
    }

    public SecretKey getKey(String name){
        byte[] salt ={0x40,0x10,0x30,0x50,0x20,0x10,0x70};
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            String str = this.password + name;
            KeySpec spec = new PBEKeySpec(str.toCharArray(), salt, 1000, 128);
            return factory.generateSecret(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecretKey getKey() {
        byte[] salt ={0x40,0x10,0x30,0x50,0x20,0x10,0x70};
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(this.password.toCharArray(), salt, 1000, 128);
            return factory.generateSecret(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public  Boolean checkMac(){
        if(!this.inputZip){
            return false;
        }else{
            try {
                byte[] mac = null;
                ByteArrayOutputStream allfile = new ByteArrayOutputStream();
                 ZipFile zipFile = new ZipFile(this.input[0]);
                Enumeration<? extends ZipEntry> entries = zipFile.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (entry.getName().equals("mac")) {
                        InputStream streamIn = zipFile.getInputStream(entry);
                        mac = IOUtils.toByteArray(streamIn);
                    } else {
                        InputStream streamIn = zipFile.getInputStream(entry);
                        allfile.write(IOUtils.toByteArray(streamIn));
                    }
                }
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] messageDigest = md.digest(allfile.toByteArray());
                if(messageDigest == mac) {
                    System.out.println("Les fichiers sont valides");
                }else{
                    System.out.println("Erreur: Les fichiers ont été modifié");
                    return false;
                }

            } catch (IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return false;
    }
}
