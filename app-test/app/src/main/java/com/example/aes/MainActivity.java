/* Author: Luca Piccolboni (piccolboni@cs.columbia.edu) */

package com.example.aes;

import java.io.*;

import java.util.*;

import javax.crypto.*;
import java.security.*;

import java.nio.*;
import java.nio.file.*;
import java.nio.channels.*;
import java.nio.charset.*;

import android.content.*;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static int KEY_SIZE = 256;
    private static String alg = "AES/ECB/PKCS5Padding";

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        String ciphertext, plaintext;
        FileOutputStream stream = null;
        String testString = "The quick brown fox jumps over the lazy dog";

        try {

            stream = openFileOutput("aes.log",
                           Context.MODE_PRIVATE |
                           Context.MODE_APPEND);

            Cipher cipher = Cipher.getInstance(alg);

            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(KEY_SIZE); SecretKey key = keygen.generateKey();

            // Encryption
            cipher.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = Base64.getEncoder().encodeToString(cipher.doFinal(
                    testString.getBytes(StandardCharsets.UTF_8)));

            // Decryption
            cipher.init(Cipher.DECRYPT_MODE, key);
            plaintext = new String(cipher.doFinal(Base64.getDecoder().decode(
                    ciphertext)));

            stream.write(("[decrypted: " + plaintext + "]\n").getBytes());
            stream.close();

        } catch (Exception e) {

            try { stream.write(("Exception:" +
                    e.getMessage() + "\n").getBytes()); }
            catch (Exception e2) {}

        }

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}
