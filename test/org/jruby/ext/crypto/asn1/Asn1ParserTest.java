/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.jruby.ext.crypto.asn1;

import java.io.ByteArrayOutputStream;
import org.jruby.ext.crypto.asn1.resources.Resources;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author martin
 */
public class Asn1ParserTest {
    
    public Asn1ParserTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }
    
    @Test
    public void parseConstructed() {
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        Asn1 asn = p.parse(Resources.certificate());
        assertNotNull(asn);
        assertTrue(asn instanceof Constructed);
        Constructed cons = (Constructed)asn;
        List<Asn1> contents = cons.getValue();
        assertNotNull(contents);
        assertTrue(contents.size() > 0);
    }
    
    @Test
    public void parseEncodeEquality() {
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        Asn1 asn = p.parse(Resources.certificate());
        byte[] raw = Resources.read(Resources.certificate());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(asn, baos);
        assertArrayEquals(raw, baos.toByteArray());
    }

}
