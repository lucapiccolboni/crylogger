/* CRYLOGGER: Author: Luca Piccolboni (piccolboni@cs.columbia.edu) */

package java.security;

import java.io.File;
import java.io.FileOutputStream;

/**
 * Class to log cryptographic uses and misues =).
 */
public class CRYLogger {

    private static FileOutputStream stream;

    /**
     *  Write the specified string in the log file.
     *
     *  @param string the string to be written.
     */
    synchronized static public void write(String string) {

        try {

            if (stream == null) {

                String filePath = System.getProperty("java.io.tmpdir");
                String fileName = filePath + "/application.cryptolog";
                String startMsg = "[CRYLOGGER] start logging here\n";
                stream = new FileOutputStream(fileName, true);
                stream.write(startMsg.getBytes());
            }

            stream.write(string.getBytes());

        } catch (Exception e) {

            e.printStackTrace();
        }
    }

    /**
     *  Write the specified string and the byte array in the log file.
     *
     *  @param string the string to be written.
     *  @param array the byte array to be written.
     */
    synchronized static public void write(String string, byte[] array) {

        try {

            if (stream == null) {

                String filePath = System.getProperty("java.io.tmpdir");
                String fileName = filePath + "/application.cryptolog";
                String startMsg = "[CRYLogger] start logging here\n";
                stream = new FileOutputStream(fileName, true);
                stream.write(startMsg.getBytes());
            }

            stream.write(string.getBytes());

            if (array != null)
            {
                for (byte b: array)
                    stream.write((String.format("%02x", b)).getBytes());
                stream.write("\n".getBytes());
            }
            else
            {
                stream.write("null\n".getBytes());
            }

        } catch (Exception e) {

            e.printStackTrace();
        }
    }
}
