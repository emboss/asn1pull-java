/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.jruby.ext.crypto.asn1.resources;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author martin
 */
public class Resources {
    
    public static InputStream certificate() {
        return Resources.class.getResourceAsStream("certificate.cer");
    }
    
    public static byte[] read(InputStream in) {
        try {
            byte[] buf = new byte[8192];
            int read;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            while ((read = in.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }

            return baos.toByteArray();
        }
        catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        finally {
            try {
                in.close();
            }
            catch (IOException ex) {
                //silent
            }
        }
    }
    
}
