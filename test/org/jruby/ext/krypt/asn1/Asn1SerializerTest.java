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

import org.jruby.ext.krypt.asn1.encode.InfiniteLengthBitString;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import org.jruby.ext.krypt.asn1.encode.Asn1Serializer;
import org.jruby.ext.krypt.asn1.encode.InfiniteLengthOctetString;
import org.jruby.ext.krypt.asn1.encode.InfiniteLengthStreamingValue;
import org.jruby.ext.krypt.asn1.encode.InfiniteLengthListValue;
import org.jruby.ext.krypt.asn1.encode.PrimitiveValue;
import org.jruby.ext.krypt.asn1.encode.Sequence;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.jruby.ext.krypt.asn1.Utils.*;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Asn1SerializerTest {
    
    public Asn1SerializerTest() {
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
    public void primitiveEncode()  {
        PrimitiveValue val = new PrimitiveValue(Tags.INTEGER, bytesOf(0x01,0x00));
        Header h = val.getHeader();
        assertEquals(Tags.INTEGER, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(2, h.getLength());
        assertEquals(2, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(val, baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0x02,0x02,0x01,0x00);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void constructedEncode() {
        List<Asn1> content = new ArrayList<Asn1>(){{
           add(new PrimitiveValue(Tags.OCTET_STRING, bytesOf(0x01)));
           add(new PrimitiveValue(Tags.OCTET_STRING, bytesOf(0x02)));
        }};
        Sequence seq = new Sequence(content);
        
        Header h = seq.getHeader();
        assertEquals(Tags.SEQUENCE, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertTrue(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(6, h.getLength());
        assertEquals(2, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(seq, baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0x30,0x06,0x04,0x01,0x01,0x04,0x01,0x02);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void complexLength() {
        PrimitiveValue val = new PrimitiveValue(Tags.OCTET_STRING, byteTimes(0x00, 1000));
        Header h = val.getHeader();
        assertEquals(Tags.OCTET_STRING, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(1000, h.getLength());
        assertEquals(4, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        h.encodeTo(baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0x04,0x82,0x03,0xe8);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void complexLengthThreshold() {
        for (int i=0; i < 128; i++) {
            PrimitiveValue val = new PrimitiveValue(Tags.OCTET_STRING, byteTimes(0x00, i));
            Header h = val.getHeader();
            assertEquals(Tags.OCTET_STRING, h.getTag());
            assertEquals(TagClass.UNIVERSAL, h.getTagClass());
            assertFalse(h.isConstructed());
            assertFalse(h.isInfiniteLength());
            assertEquals(i, h.getLength());
            assertEquals(2, h.getHeaderLength());
        }
        PrimitiveValue val = new PrimitiveValue(Tags.OCTET_STRING, byteTimes(0x00, 128));
        Header h = val.getHeader();
        assertEquals(Tags.OCTET_STRING, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(128, h.getLength());
        assertEquals(3, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        h.encodeTo(baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0x04,0x81,0x80);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void complexTagSingleOctet() {
        PrimitiveValue val = new PrimitiveValue(42, TagClass.PRIVATE, bytesOf(0x00));
        Header h = val.getHeader();
        assertEquals(42, h.getTag());
        assertEquals(TagClass.PRIVATE, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(1, h.getLength());
        assertEquals(3, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        h.encodeTo(baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0xdf,0x2a,0x01);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void complexTagTwoOctets() {
        PrimitiveValue val = new PrimitiveValue(300, TagClass.APPLICATION, bytesOf(0x00));
        Header h = val.getHeader();
        assertEquals(300, h.getTag());
        assertEquals(TagClass.APPLICATION, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(1, h.getLength());
        assertEquals(4, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        h.encodeTo(baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0x5f,0x82,0x2c,0x01);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void complexTagThreshold() {
        for (int i=0; i <= 30; i++) {
            PrimitiveValue val = new PrimitiveValue(i, bytesOf(0x00));
            Header h = val.getHeader();
            assertEquals(i, h.getTag());
            assertEquals(TagClass.UNIVERSAL, h.getTagClass());
            assertFalse(h.isConstructed());
            assertFalse(h.isInfiniteLength());
            assertEquals(1, h.getLength());
            assertEquals(2, h.getHeaderLength());
        }
        PrimitiveValue val = new PrimitiveValue(31, TagClass.APPLICATION, bytesOf(0x00));
        Header h = val.getHeader();
        assertEquals(31, h.getTag());
        assertEquals(TagClass.APPLICATION, h.getTagClass());
        assertFalse(h.isConstructed());
        assertFalse(h.isInfiniteLength());
        assertEquals(1, h.getLength());
        assertEquals(3, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        h.encodeTo(baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0x5f,0x1f,0x01);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void infiniteLengthEncode() {
        List<Asn1> content = new ArrayList<Asn1>(){{
           add(new PrimitiveValue(Tags.OCTET_STRING, bytesOf(0x01)));
           add(new PrimitiveValue(Tags.OCTET_STRING, bytesOf(0x02)));
           add(new PrimitiveValue(Tags.END_OF_CONTENTS, null));
        }};
        InfiniteLengthListValue val = new InfiniteLengthListValue(Tags.OCTET_STRING, content);
        
        Header h = val.getHeader();
        assertEquals(Tags.OCTET_STRING, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertTrue(h.isConstructed());
        assertTrue(h.isInfiniteLength());
        assertEquals(-1, h.getLength());
        assertEquals(2, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(val, baos);
        byte[] result = baos.toByteArray();
        byte[] expected = bytesOf(0x24,0x80,0x04,0x01,0x01,0x04,0x01,0x02,0x00,0x00);
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void streamingOctetStringDefaultChunkSize() throws Exception {
        streamingDefaultChunkSize(InfiniteLengthOctetString.class, Tags.OCTET_STRING);
    }
    
    @Test
    public void streamingBitStringDefaultChunkSize() throws Exception {
        streamingDefaultChunkSize(InfiniteLengthBitString.class, Tags.BIT_STRING);
    }
    
    @Test
    public void streamingOctetStringExplicitChunkSize() throws Exception {
        streamingExplicitChunkSize(InfiniteLengthOctetString.class, Tags.OCTET_STRING, 42);
    }
    
    @Test
    public void streamingBitStringExplicitChunkSize() throws Exception {
        streamingExplicitChunkSize(InfiniteLengthBitString.class, Tags.BIT_STRING, 42);
    }
    
    private void streamingDefaultChunkSize(Class<? extends InfiniteLengthStreamingValue> clazz, int tag) throws Exception {
        byte[] value = byteTimes(0x01, InfiniteLengthStreamingValue.DEFAULT_CHUNK_SIZE * 2 + 1);
        
        InfiniteLengthStreamingValue val = clazz.getConstructor(InputStream.class)
                                                .newInstance(new ByteArrayInputStream(value));
        
        streamingChunked(val, tag, InfiniteLengthStreamingValue.DEFAULT_CHUNK_SIZE, bytesOf(0x82,0x20,0x00));
    }
    
    private void streamingExplicitChunkSize(Class<? extends InfiniteLengthStreamingValue> clazz, int tag, int chunkSize) throws Exception {
        byte[] value = byteTimes(0x01, chunkSize * 2 + 1);
        
        InfiniteLengthStreamingValue val = clazz.getConstructor(InputStream.class, int.class)
                                                .newInstance(new ByteArrayInputStream(value), chunkSize);
        
        streamingChunked(val, tag, chunkSize, bytesOf(0x2a));
    }
    
    private void streamingChunked(InfiniteLengthStreamingValue val, int tag, int chunkSize, byte[] lengthEncoding) throws Exception {
        Header h = val.getHeader();
        assertEquals(tag, h.getTag());
        assertEquals(TagClass.UNIVERSAL, h.getTagClass());
        assertTrue(h.isConstructed());
        assertTrue(h.isInfiniteLength());
        assertEquals(-1, h.getLength());
        assertEquals(2, h.getHeaderLength());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Asn1Serializer.serialize(val, baos);
        byte[] result = baos.toByteArray();
        
        baos = new ByteArrayOutputStream();
        baos.write(bytesOf(tag | 0x20,0x80));
        
        for(int i=0; i<2; i++) {
          baos.write(bytesOf(tag));
          baos.write(lengthEncoding);
          baos.write(byteTimes(0x01, chunkSize));
        }
        
        baos.write(bytesOf(tag,0x01,0x01,0x00,0x00));
        assertArrayEquals(baos.toByteArray(), result);
    }
}
