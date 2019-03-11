import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;


public class CipherWrapper {

    private byte[] blockPlain;
    private byte[] blockTmp;
    private byte[] blockCipher ;
    private int indice;

    public byte[] encrypt( byte[] data, Key key){
        if(data.length <16){
            System.out.println("Fichier trop petit");
            System.exit(1);
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"));
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            blockCipher = new byte[16];
            for(indice=0; indice < (data.length/16)-1; indice++) {
                blockPlain = Arrays.copyOfRange(data,indice*16,(indice+1)*16);
                if(indice == 0){
                    blockTmp = blockPlain;
                }else{
                    blockTmp = xorTwoBlock(blockPlain,blockCipher);
                }
                blockCipher = cipher.doFinal(blockTmp);
                result.write(blockCipher);
            }
            //-----------------Cipher Text Stealing ------------------------------------
            blockPlain = Arrays.copyOfRange(data,indice*16,(indice+1)*16);
            blockTmp = xorTwoBlock(blockPlain,blockCipher);
            byte[] lastFullBlock = cipher.doFinal(blockTmp);
            //Calcul de la longueur du dernier bloque
            int length = data.length%16;
            //Copie des derniers bits de data
            blockPlain = new byte[16];
            //Rcupere les derniers bytes et copie de ces derniers
            byte[] lastdata =  Arrays.copyOfRange(data, (indice+1)*16, data.length);
            for (int j =0; j<16;j++) {
                if(j<length)
                    blockPlain[j] = lastdata[j];
                else
                    blockPlain[j] =0x0;
            }
            //Xor avec le dernier bloque
            blockTmp = xorTwoBlock(blockPlain,lastFullBlock);
            //On chiffre l'avant dernier bloque
            blockCipher = cipher.doFinal(blockTmp);
            //Copie de l'avant dernier bloque
            result.write(blockCipher);
            //Copie du dernier bloque
            result.write(lastFullBlock,0,length);
            return result.toByteArray();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    public byte[] decrypt(byte[] data, Key key){
        if(data.length <16){
            System.out.println("Fichier trop petit");
            System.exit(1);
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"));
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] previousBlockCipher = new byte[16];

            for(indice=0; indice<(data.length/16)-1; indice++) {
                blockCipher = Arrays.copyOfRange(data,indice*16,(indice+1)*16);
                blockTmp = cipher.doFinal(blockCipher);
                if(indice == 0){
                    blockPlain = blockTmp;
                }else {
                    blockPlain = xorTwoBlock(blockTmp,previousBlockCipher);
                }
                previousBlockCipher = blockCipher;
                result.write(blockPlain);
            }
            //-------------------Cipher Text Stealing--------------------------------------
            byte[] penultimateCipher = previousBlockCipher;
            blockCipher =  Arrays.copyOfRange(data,indice*16,(indice+1)*16);
            blockTmp = cipher.doFinal(blockCipher);
            byte[] lastBlock = new byte[16];
            byte[] lastBlockTemp;
            //Calcul de la longueur du dernier bloque
            int length = data.length%16;
            //On recupere les derniers bits de data
            lastBlockTemp = Arrays.copyOfRange(data,(indice+1)*16,data.length);
            for (int j=0;j<16;j++){
                if (j<length)
                    lastBlock[j] =lastBlockTemp[j];
                else
                    lastBlock[j] =blockTmp[j];
            }
            //On complete lastBlock avec les bits du messages précédent
            lastBlockTemp = cipher.doFinal(lastBlock);
            //Xor du dernier bloque
            blockPlain = xorTwoBlock(penultimateCipher, lastBlockTemp);
            //Copie de l'avant dernier bloque
            result.write(blockPlain);
            blockPlain=xorTwoBlock(blockTmp,lastBlock);
            //Copie du dernier bloque
            result.write(blockPlain,0,length);
            return result.toByteArray();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    private byte[] xorTwoBlock(byte[] b1, byte[] b2){
        byte[] br = new byte[16];
        for (int j = 0; j < 16; j++)
            br[j] = (byte) (b1[j] ^ b2[j]);
        return br;
    }
}
