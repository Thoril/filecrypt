import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class Main {

    static public void main(String[] args) {
        ArgsChecker ac = new ArgsChecker(args);
        ZipOutputStream out = null;
        ByteArrayOutputStream allfile = new ByteArrayOutputStream();
        //On verifie si on a une liste de fichier ou un seul fichier
        if (ac.getInput().length != 1) {
            //si on a qu'un seul fichier la sortie doit etre un zip
            File f = new File(ac.getOutput());
            if (!FilenameUtils.getExtension(ac.getOutput()).equals("zip")) {
                System.out.println("Erreur : le dossier de sortie doit etre un .zip");
                System.exit(1);
            }
            try {
                //si on a un zip on init notre output stream
                out = new ZipOutputStream(new FileOutputStream(f));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        try {
            //pour chaque fichier dans notre input
            for (String file : ac.getInput()) {
                    byte[] data = Files.readAllBytes(Paths.get(file));
                    allfile.write(data);
                    byte[] dataOut = null;
                    CipherWrapper cw = new CipherWrapper();
                    //Cas ou l'on n'a qu'un seul fichier en entré et ce n'est pas un zip
                    if (ac.getMode() == 1 && !ac.getInputZip()) {
                        if (ac.getInput().length == 1)
                            dataOut = cw.encrypt(data, ac.getKey());
                        else
                            dataOut = cw.encrypt(data, ac.getKey(new File(file).getName()));
                    } else if (ac.getMode() == 2 && !ac.getInputZip()) {
                        if (ac.getInput().length == 1)
                            dataOut = cw.decrypt(data, ac.getKey());
                        else
                            dataOut = cw.decrypt(data, ac.getKey(new File(file).getName()));
                    }
                    //Cas ou l'on a un zip en entrer et on doit déchiffer son contenu
                    if (ac.getInputZip() && ac.getMode() == 2) {
                        //ac.checkMac();
                        ZipFile zipFile = new ZipFile(ac.getInput()[0]);
                        Enumeration<? extends ZipEntry> entries = zipFile.entries();
                        while (entries.hasMoreElements()) {
                            ZipEntry entry = entries.nextElement();
                            if(entry.getName().equals("mac")){
                                //On ne déchiffre pas le mac file
                            }else {
                                InputStream streamIn = zipFile.getInputStream(entry);
                                dataOut = cw.decrypt(IOUtils.toByteArray(streamIn), ac.getKey(entry.getName()));
                                File newFolder = new File(ac.getOutput());
                                newFolder.mkdir();
                                try (FileOutputStream stream1 = new FileOutputStream(ac.getOutput() + "\\" + entry.getName())) {
                                    if (dataOut != null) {
                                        stream1.write(dataOut);
                                    } else {
                                        System.out.println("Erreur ecriture lors du chiffrement");
                                        System.exit(1);
                                    }
                                }
                            }
                        }
                    }
                    //Cas ou l'on doit ecrire un fichier en sortie
                    if (ac.getInput().length == 1 && !ac.getInputZip()) {
                        try (FileOutputStream stream2 = new FileOutputStream(ac.getOutput())) {
                            if (dataOut != null) {
                                stream2.write(dataOut);
                            } else {
                                System.out.println("Erreur ecriture lors du chiffrement");
                                System.exit(1);
                            }
                        }
                        //Cas ou l'on doit ecrire la sortie dans un zip
                    } else if (!ac.getInputZip()) {
                        ZipEntry entry = new ZipEntry(new File(file).getName());
                        out.putNextEntry(entry);
                        out.write(dataOut, 0, dataOut.length);
                        out.closeEntry();
                    }
                }

        } catch (IOException e) {
            e.printStackTrace();
        }
        if (ac.getInput().length != 1) {
            try {
                // Static getInstance method is called with hashing SHA
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] messageDigest = md.digest(allfile.toByteArray());
                ZipEntry entry = new ZipEntry("mac");
                out.putNextEntry(entry);
                out.write(messageDigest, 0, messageDigest.length);
                out.closeEntry();
            }
            // For specifying wrong message digest algorithms
            catch (NoSuchAlgorithmException | IOException e) {
                e.printStackTrace();
            }

            try {
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
