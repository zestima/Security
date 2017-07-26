package si;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;
import java.nio.file.Path;
import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Encoder;

public class SI {

    public static void createDatabase() {
        Connection c = null;
        try {
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");
        } catch (Exception e) {
            System.err.println(e.getClass().getName() + ": " + e.getMessage());
            System.exit(0);
        }
        try {
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");

            Statement stmt = c.createStatement();
            String sql = "CREATE TABLE IF NOT EXISTS OBLIVION" + "(HASHKEY                       CHAR(1024)  NOT NULL, "
                    + " HASHFUN                       CHAR(1024)  NOT NULL, "
                    + " HMAC                          CHAR(1024)  NOT NULL, "
                    + " SALT                          CHAR(1024)  NOT NULL, "
                    + " CIFRA                         CHAR(1024)  NOT NULL, "
                    + " TENTATIVAS                    INT         NOT NULL, "
                    + " TAMANHO                       INT         NOT NULL, "
                    + " PK                            CHAR(1024)  NOT NULL, "
                    + " SIGNED                        CHAR(1024)  NOT NULL, "
                    + " FILENAME                      CHAR(50) NOT NULL    )";
            stmt.executeUpdate(sql);
            stmt.close();
            c.close();
        } catch (Exception e) {
            System.err.println(e.getClass().getName() + ": " + e.getMessage());
            System.exit(0);
        }
    }

    public static void encrypt(InputStream in, OutputStream out, Key k, String cifra)
            throws Exception, InvalidKeyException {

        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[16];
        r.nextBytes(iv);
        out.write(iv);
        out.flush();
        Cipher cipher = Cipher.getInstance(cifra); //AES/CBC/PKCS5Padding
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, k, ivSpec);
        out = new CipherOutputStream(out, cipher);
        byte[] buf = new byte[1024];
        int numRead = 0;
        while ((numRead = in.read(buf)) >= 0) {
            out.write(buf, 0, numRead);
        }
        out.close();
    }

    public static void decrypt(InputStream in, OutputStream out, Key password, String cifra)
            throws Exception, InvalidKeyException {

        byte[] iv = new byte[16];
        in.read(iv);
        Cipher cipher = Cipher.getInstance(cifra); //AES/CBC/PKCS5Padding
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, password, ivSpec);

        in = new CipherInputStream(in, cipher);
        byte[] buf = new byte[1024];
        int numRead = 0;
        while ((numRead = in.read(buf)) >= 0) {
            out.write(buf, 0, numRead);
        }
        out.close();
    }

    public static void copy(int mode, String inputFile, String outputFile, Key password, String cifra)
            throws Exception {

        BufferedInputStream is = new BufferedInputStream(new FileInputStream(inputFile));
        BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(outputFile));
        if (mode == Cipher.ENCRYPT_MODE) {
            encrypt(is, os, password, cifra);
        } else if (mode == Cipher.DECRYPT_MODE) {
            decrypt(is, os, password, cifra);
        } else {
            throw new Exception("unknown mode");
        }
        is.close();
        os.close();
    }

    public static String getHex(byte[] badigest) {
        String sReturn = "";

        for (final byte b : badigest) {
            int iPrimeiroHex = (b >> 4) & 0xf;
            switch (iPrimeiroHex) {
            case 0:
                sReturn = sReturn + "0";
                break;
            case 1:
                sReturn = sReturn + "1";
                break;
            case 2:
                sReturn = sReturn + "2";
                break;
            case 3:
                sReturn = sReturn + "3";
                break;
            case 4:
                sReturn = sReturn + "4";
                break;
            case 5:
                sReturn = sReturn + "5";
                break;
            case 6:
                sReturn = sReturn + "6";
                break;
            case 7:
                sReturn = sReturn + "7";
                break;
            case 8:
                sReturn = sReturn + "8";
                break;
            case 9:
                sReturn = sReturn + "9";
                break;
            case 10:
                sReturn = sReturn + "a";
                break;
            case 11:
                sReturn = sReturn + "b";
                break;
            case 12:
                sReturn = sReturn + "c";
                break;
            case 13:
                sReturn = sReturn + "d";
                break;
            case 14:
                sReturn = sReturn + "e";
                break;
            case 15:
                sReturn = sReturn + "f";
                break;
            }
            int iSegundoHex = b & 0x0F;
            switch (iSegundoHex) {
            case 0:
                sReturn = sReturn + "0";
                break;
            case 1:
                sReturn = sReturn + "1";
                break;
            case 2:
                sReturn = sReturn + "2";
                break;
            case 3:
                sReturn = sReturn + "3";
                break;
            case 4:
                sReturn = sReturn + "4";
                break;
            case 5:
                sReturn = sReturn + "5";
                break;
            case 6:
                sReturn = sReturn + "6";
                break;
            case 7:
                sReturn = sReturn + "7";
                break;
            case 8:
                sReturn = sReturn + "8";
                break;
            case 9:
                sReturn = sReturn + "9";
                break;
            case 10:
                sReturn = sReturn + "a";
                break;
            case 11:
                sReturn = sReturn + "b";
                break;
            case 12:
                sReturn = sReturn + "c";
                break;
            case 13:
                sReturn = sReturn + "d";
                break;
            case 14:
                sReturn = sReturn + "e";
                break;
            case 15:
                sReturn = sReturn + "f";
                break;
            }
        }

        return sReturn;
    }

    public static String Hash(String data, String hash)
            throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        MessageDigest md = MessageDigest.getInstance(hash);

        FileInputStream fis = new FileInputStream(data);

        byte[] buff = new byte[1];

        while ((fis.read(buff)) > 0) {
            md.update((byte) buff[0]);
        }
        byte[] mdbytes = md.digest();
        return getHex(mdbytes);
    }

    public static String Hmac256(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        FileInputStream fis = new FileInputStream(data);
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        mac.init(secret_key);

        byte[] buff = new byte[1];
        while ((fis.read(buff)) > 0) {
            mac.update((byte) buff[0]);
        }
        byte[] macbytes = mac.doFinal();
        return getHex(macbytes);
        //return getHex(buff);
    }

    public static void watchDirectoryPath(Path path) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {

        try {
            Boolean isFolder = (Boolean) Files.getAttribute(path, "basic:isDirectory", NOFOLLOW_LINKS);
            if (!isFolder) {
                throw new IllegalArgumentException("Path: " + path + " is not a folder");
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }

        System.out.println("Watching path: " + path);
        System.out.println("Arrasta o ficheiro para a pasta");
        FileSystem fs = path.getFileSystem();

        try (WatchService service = fs.newWatchService()) {

            path.register(service, ENTRY_CREATE);

            WatchKey key = service.take();

            WatchEvent.Kind<?> kind = null;
            for (WatchEvent<?> watchEvent : key.pollEvents()) {
                kind = watchEvent.kind();
                if (OVERFLOW == kind) {
                    continue; // loop
                } else if (ENTRY_CREATE == kind) {
                    // Novo ficheiro
                    Path newPath = ((WatchEvent<Path>) watchEvent).context();
                    System.out.println("New path created : " + newPath);
                    Scanner input = new Scanner(System.in);

                    //Calcular Hash
                    String hashfun = "";
                    while (hashfun.equals("")) {
                        System.out.println("Introduz a função de Hash");
                        hashfun = input.nextLine();
                        try {
                            MessageDigest md = MessageDigest.getInstance(hashfun);
                        } catch (Exception e) {
                            System.out.println("Função de Hash não existe");
                            hashfun = "";
                        }
                    }
                    String hash = Hash(path.toString() + "/" + newPath.toString(), hashfun);

                    //Calcular Hmac
                    String macs = Hmac256(hash, path.toString() + "/" + newPath.toString());

                    //grep securerandom.source /usr/lib/jvm/java-8-oracle/jre/lib/security/java.security 
                    //Verificar se cifra é válida
                    String cifra = "";
                    while (cifra.equals("")) {
                        System.out.println("Introduz a cifra");
                        cifra = input.nextLine();
                        try {
                            Cipher cipher = Cipher.getInstance(cifra);
                        } catch (Exception e) {
                            System.out.println("Cifra não existe");
                            cifra = "";
                        }
                    }
                    //grep securerandom.source /usr/lib/jvm/java-8-oracle/jre/lib/security/java.security 
                    //Obter pin gerado aleatoriamente do melhor lixo /dev/random
                    SecureRandom random = SecureRandom.getInstanceStrong();
                    String chave = "";
                    for (int i = 0; i < 4; i++) {

                        chave = chave + String.valueOf(random.nextInt(9));

                    }
                    //Pin para motivos de teste
                    //System.out.println("Pin=" + chave);

                    //Obter o salt gerado aleatoriamente mais uma vez do grandioso /dev/random
                    byte[] salt = new byte[64];
                    random.nextBytes(salt);

                    //Verificar se o tamanho de chave é válido
                    Key k = null;
                    int tamanho = 0;
                    while (k == null) {
                        System.out.println("Introduz o comprimento da chave");
                        tamanho = input.nextInt();
                        try {
                            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                            KeySpec ks = new PBEKeySpec(salt.toString().toCharArray(), chave.getBytes(), 65536,
                                    tamanho);
                            SecretKey s = f.generateSecret(ks);
                            k = new SecretKeySpec(s.getEncoded(), "AES");
                        } catch (Exception e) {
                            System.out.println("Tamanho da chave tem de ser 128 ou 256");
                            continue;
                        }
                    }

                    //Gerar par de chaves RSA do /dev/random
                    SecureRandom sr = new SecureRandom();
                    BASE64Encoder b64 = new BASE64Encoder();
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    //tamanho das chaves e source
                    kpg.initialize(2048, sr);
                    KeyPair kp = kpg.generateKeyPair();
                    PrivateKey sk = kp.getPrivate();
                    PublicKey pk = kp.getPublic();

                    //Calcular Assinatura Digital
                    FileInputStream fis = new FileInputStream(path.toString() + "/" + newPath.toString());
                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign(sk);
                    byte[] buffer = new byte[1];
                    while ((fis.read(buffer)) > 0) {
                        sig.update(buffer);
                    }
                    byte[] sign = sig.sign();

                    //Converter assinatura e chave pública para Base64 para inserir na Base de Dados                        
                    String signed = b64.encode(sign);
                    String PublicKey = b64.encode(pk.getEncoded());

                    //Cifrar ficheiro
                    File temp = new File(newPath.toString());
                    copy(Cipher.ENCRYPT_MODE, path.toString() + "/" + newPath.toString(), temp.toString(), k, cifra);
                    FileChannel src = new FileInputStream(temp.toString()).getChannel();
                    FileChannel dest = new FileOutputStream(path.toString() + "/" + newPath.toString()).getChannel();
                    dest.transferFrom(src, 0, src.size());
                    temp.delete();
                    System.out.println("Ficheiro Cifrado com Sucesso!");

                    //Inserir na base de dados
                    try {
                        Class.forName("org.sqlite.JDBC");
                        Connection c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");
                        c.setAutoCommit(false);

                        Statement stmt = c.createStatement();
                        String sql = "INSERT INTO OBLIVION (HASHKEY,HASHFUN,HMAC,SALT,CIFRA,TENTATIVAS,TAMANHO,PK,SIGNED,FILENAME) "
                                + "VALUES ('" + hash + "', '" + hashfun + "', '" + macs + "', '" + salt + "', '" + cifra
                                + "','0','" + tamanho + "'," + "'" + PublicKey + "'," + "'" + signed + "','"
                                + newPath.toString() + "')";
                        stmt.executeUpdate(sql);

                        stmt.close();
                        c.commit();
                        c.close();
                    } catch (Exception e) {
                        System.err.println(e.getClass().getName() + ": " + e.getMessage());
                        System.exit(0);
                    }
                }
            }

        } catch (IOException ioe) {
            ioe.printStackTrace();
        } catch (InterruptedException ie) {
            ie.printStackTrace();
        }

    }

    public static void main(String args[]) throws NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, Exception {
        //Criar base de dados se não existir
        createDatabase();

        //Criar Diretoria se não existir
        File theDir = new File("FALL-INTO-OBLIVION");
        if (!theDir.exists()) {
            System.out.println("creating directory: FALL-INTO-OBLIVION");
            boolean result = false;
            try {
                theDir.mkdir();
                result = true;
            } catch (SecurityException se) {
                //handle it
            }
            if (result) {
                System.out.println("DIR created");
            }
        }
        Scanner input = new Scanner(System.in);

        while (true) {
            System.out.println("Introduz um comando !\nhelp caso não saibas o que fazer\n ");
            String read = input.nextLine();

            if (read.equals("cifrar")) {
                watchDirectoryPath(theDir.toPath());
            } else if (read.equals("decifrar")) {

                //Verificar se ficheiro existe
                System.out.println("Introduz o nome do ficheiro que queres decifrar");
                String ficheiro = input.nextLine();
                File check = new File(theDir.toString() + "/" + ficheiro);
                if (!check.exists()) {
                    System.out.println("Ficheiro não existe");
                    continue;
                }
                String hashfun = null;
                String hash = null;
                String hmac = null;
                String salt = null;
                String cifra = null;
                int tamanho = 0;
                int tentativas;
                String key = null;
                String signed = null;

                //Obter informação da base de dados corresponde ao ficheiro que queremos decifrar
                try {
                    Class.forName("org.sqlite.JDBC");
                    Connection c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");
                    c.setAutoCommit(false);

                    Statement stmt = c.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT * FROM OBLIVION where FILENAME='" + ficheiro + "';");
                    while (rs.next()) {
                        hashfun = rs.getString("HASHFUN");
                        hash = rs.getString("HASHKEY");
                        hmac = rs.getString("HMAC");
                        salt = rs.getString("SALT");
                        cifra = rs.getString("CIFRA");
                        tamanho = rs.getInt("TAMANHO");
                        tentativas = rs.getInt("TENTATIVAS");
                        key = rs.getString("PK");
                        signed = rs.getString("SIGNED");

                    }
                    rs.close();
                    stmt.close();
                    c.close();
                } catch (Exception e) {
                    System.err.println(e.getClass().getName() + ": " + e.getMessage());
                    System.exit(0);
                }
                String pin;
                File temp = null;

                //Tentar decifrar ficheiro se sucesso decifrar senão diminui as tentativas possíveis
                try {
                    System.out.println("Introduz o pin");
                    pin = input.nextLine();
                    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    KeySpec ks = new PBEKeySpec(salt.toCharArray(), pin.getBytes(), 65536, tamanho);
                    SecretKey s = f.generateSecret(ks);
                    Key k = new SecretKeySpec(s.getEncoded(), "AES");
                    temp = new File(ficheiro);
                    temp.createNewFile();
                    copy(Cipher.DECRYPT_MODE, theDir.toString() + "/" + ficheiro, temp.toString(), k, cifra);
                } catch (Exception e) {
                    temp.delete();
                    System.out.println("Pin errado");
                    int verifica = 0;

                    //Obter tentativas restantes
                    try {
                        Class.forName("org.sqlite.JDBC");
                        Connection c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");
                        c.setAutoCommit(false);
                        Statement stmt = c.createStatement();
                        ResultSet rs = stmt.executeQuery("SELECT * FROM OBLIVION where FILENAME='" + ficheiro + "';");
                        while (rs.next()) {
                            verifica = rs.getInt("TENTATIVAS");
                        }
                        rs.close();
                        stmt.close();
                        c.close();
                    } catch (Exception ex) {
                        System.err.println(ex.getClass().getName() + ": " + ex.getMessage());
                        System.exit(0);
                    }

                    //Atualizar tentativas restantes
                    int v = 2 - verifica;
                    if (v > 0) {
                        System.out.println("Tens mais " + v + " tentativas");
                        try {
                            Class.forName("org.sqlite.JDBC");
                            Connection c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");
                            c.setAutoCommit(false);

                            Statement stmt = c.createStatement();
                            String sql = "UPDATE OBLIVION set TENTATIVAS = " + (verifica + 1) + " where FILENAME='"
                                    + ficheiro + "';";
                            stmt.executeUpdate(sql);
                            c.commit();

                            stmt.close();
                            c.close();
                        } catch (Exception ex) {
                            System.err.println(ex.getClass().getName() + ": " + ex.getMessage());
                            System.exit(0);
                        }
                    } else {

                        //Apagar o ficheiro e o que lhe corresponde na base de dados quando acabarem as tentativas
                        System.out.println("Ficheiro apagado devido ás tentativas de acesso!");
                        temp = new File(theDir.toString() + "/" + ficheiro);
                        temp.delete();
                        try {
                            Class.forName("org.sqlite.JDBC");
                            Connection c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");
                            c.setAutoCommit(false);

                            Statement stmt = c.createStatement();
                            String sql = "DELETE from OBLIVION where FILENAME='" + ficheiro + "';";
                            stmt.executeUpdate(sql);
                            c.commit();

                            stmt.close();
                            c.close();
                        } catch (Exception ex) {
                            System.err.println(ex.getClass().getName() + ": " + ex.getMessage());
                            System.exit(0);
                        }
                    }
                    continue;
                }

                //Se tudo correr bem verificar se o ficheiro não foi alterado
                temp = new File(theDir.toString() + "/" + ficheiro);
                temp.delete();
                System.out.println("Ficheiro decifrado com sucesso!");

                //Verificar Hash
                String hashv = Hash(ficheiro, hashfun);
                if (hash.equals(hashv)) {
                    System.out.println("Hash verifica!");
                } else {
                    System.out.println("Hash não verifica");
                }

                //Verifica Hmac
                String hmacv = Hmac256(hashv, ficheiro);
                if (hmac.equals(hmacv)) {
                    System.out.println("Hmac verifica!");
                } else {
                    System.out.println("Hmac não verifica");
                }

                //Converter novamente a assinatura e public key de base64 para byte []
                byte[] p = Base64.decode(key);
                byte[] signv = Base64.decode(signed);

                //Usar certificado digital para gerar a chave a partir dos seus bytes
                X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(p);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pk = kf.generatePublic(X509publicKey);

                //Ler o ficheiro e verificar assinatura
                FileInputStream fis = new FileInputStream(ficheiro);
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(pk);
                byte[] buffer = new byte[1];
                while ((fis.read(buffer)) > 0) {
                    sig.update(buffer);
                }
                if (sig.verify(signv)) {
                    System.out.println("Assinatura Digital Verifica");
                } else {
                    System.out.println("Assinatura Digital Não verifica");
                }

                //Apagar tudo o que corresponde ao ficheiro decifrado
                try {
                    Class.forName("org.sqlite.JDBC");
                    Connection c = DriverManager.getConnection("jdbc:sqlite:OBLIVION.db");
                    c.setAutoCommit(false);

                    Statement stmt = c.createStatement();
                    String sql = "DELETE from OBLIVION where FILENAME='" + ficheiro + "';";
                    stmt.executeUpdate(sql);
                    c.commit();
                    stmt.close();
                    c.close();
                } catch (Exception e) {
                    System.err.println(e.getClass().getName() + ": " + e.getMessage());
                    System.exit(0);
                }
            } else {
                System.out.println(
                        "Help\nComandos:\n    cifrar\n    decifrar\nRecomendações: \n    Usar como função de Hash SHA-256 ou SHA-512\n    Usar como função de cifra AES/CBC/PKCS5Padding\n    Usar como tamanho de chave 128 ou 256");
            }

        }
    }
}
