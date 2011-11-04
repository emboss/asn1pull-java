/***** BEGIN LICENSE BLOCK *****
* Version: CPL 1.0/GPL 2.0/LGPL 2.1
*
* The contents of this file are subject to the Common Public
* License Version 1.0 (the "License"); you may not use this file
* except in compliance with the License. You may obtain a copy of
* the License at http://www.eclipse.org/legal/cpl-v10.html
*
* Software distributed under the License is distributed on an "AS
* IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
* implied. See the License for the specific language governing
* rights and limitations under the License.
*
* Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
*
* Alternatively, the contents of this file may be used under the terms of
* either of the GNU General Public License Version 2 or later (the "GPL"),
* or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
* in which case the provisions of the GPL or the LGPL are applicable instead
* of those above. If you wish to allow use of your version of this file only
* under the terms of either the GPL or the LGPL, and not to allow others to
* use your version of this file under the terms of the CPL, indicate your
* decision by deleting the provisions above and replace them with the notice
* and other provisions required by the GPL or the LGPL. If you do not delete
* the provisions above, a recipient may use your version of this file under
* the terms of any one of the CPL, the GPL or the LGPL.
 */
package org.jruby.ext.krypt.asn1;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.jruby.ext.krypt.asn1.encode.Asn1Serializer;
import org.jruby.ext.krypt.asn1.parser.Asn1Parser;
import org.jruby.ext.krypt.asn1.resources.Resources;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.jruby.ext.krypt.asn1.Utils.*;
/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Asn1ParserTest {
    
    @Test
    public void parseConstructed() throws Exception {
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = Resources.certificate();

        try {
            Asn1 asn = p.parse(in);
            assertNotNull(asn);
            assertTrue(asn instanceof Constructed);
            Constructed cons = (Constructed)asn;
            Iterable<Asn1> contents = cons.getContent();
            assertNotNull(contents);
            assertTrue(contents.iterator().hasNext());
        }
        finally {
            in.close();
        }
    }
    
    @Test
    public void parseEncodeEquality() throws Exception {
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = Resources.certificate();

        try {
            byte[] raw = Resources.read(Resources.certificate());
            Asn1 asn = p.parse(new ByteArrayInputStream(raw));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Asn1Serializer.serialize(asn, baos);
            assertArrayEquals(raw, baos.toByteArray());
        }
        finally {
            in.close();
        }
    }
    
    @Test
    public void primitiveParse() {
        byte[] raw = bytesOf(0x02,0x02,0x01,0x00);
        
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = new ByteArrayInputStream(raw);
        
        Asn1 asn1 = p.parse(in);
        Header h = asn1.getHeader();
        assertEquals(Tags.INTEGER, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(2, h.getLength());
        assertEquals(2, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(asn1, baos);
        byte[] result = baos.toByteArray();
        
        assertArrayEquals(raw, result);
    }
    
    @Test
    public void constructedEncode() {
        byte[] raw = bytesOf(0x30,0x06,0x04,0x01,0x01,0x04,0x01,0x02);
        
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = new ByteArrayInputStream(raw);
        
        Asn1 asn1 = p.parse(in);
        Header h = asn1.getHeader();
        assertEquals(Tags.SEQUENCE, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertTrue(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(6, h.getLength());
        assertEquals(2, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(asn1, baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(raw, result);
    }
    
    @Test
    public void complexLength() throws IOException{
        byte[] raw = bytesOf(0x04,0x82,0x03,0xe8);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(raw);
        baos.write(byteTimes(0x00, 1000));
        raw = baos.toByteArray();
        
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = new ByteArrayInputStream(raw);
        
        Asn1 asn1 = p.parse(in);
        Header h = asn1.getHeader();
        assertEquals(Tags.OCTET_STRING, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(1000, h.getLength());
        assertEquals(4, h.getHeaderLength());
        
        baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(asn1, baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(raw, result);
    }
    
    @Test
    public void complexTagSingleOctet() throws IOException {
        byte[] raw = bytesOf(0xdf,0x2a,0x01);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(raw);
        baos.write(bytesOf(0x00));
        raw = baos.toByteArray();
        
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = new ByteArrayInputStream(raw);
        
        Asn1 asn1 = p.parse(in);
        Header h = asn1.getHeader();
        assertEquals(42, h.getTag());
        assertEquals(TagClass.PRIVATE, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(1, h.getLength());
        assertEquals(3, h.getHeaderLength());
        
        baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(asn1, baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(raw, result);
    }
    
    @Test
    public void complexTagTwoOctets() throws IOException {
        byte[] raw = bytesOf(0x5f,0x82,0x2c,0x01);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(raw);
        baos.write(bytesOf(0x00));
        raw = baos.toByteArray();
        
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = new ByteArrayInputStream(raw);
        
        Asn1 asn1 = p.parse(in);
        Header h = asn1.getHeader();
        assertEquals(300, h.getTag());
        assertEquals(TagClass.APPLICATION, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(1, h.getLength());
        assertEquals(4, h.getHeaderLength());
        
        baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(asn1, baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(raw, result);
    }
    
    @Test
    public void infiniteLengthParsing() throws IOException {
        byte[] raw = bytesOf(0x24,0x80,0x04,0x01,0x01,0x04,0x01,0x02,0x00,0x00);
        
        Asn1Parser p = new Asn1Parser(new ParserFactory());
        InputStream in = new ByteArrayInputStream(raw);
        Asn1 asn1 = p.parse(in);
        Header h = asn1.getHeader();
        assertEquals(Tags.OCTET_STRING, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertTrue(h.isConstructed());
        assertTrue(h.isInfiniteLength());
        assertEquals(-1, h.getLength());
        assertEquals(2, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(asn1, baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(raw, result);
    }

}
