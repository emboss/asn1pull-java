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
package org.jruby.ext.krypt.asn1.parser;

import org.jruby.ext.krypt.asn1.Encodable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.jruby.ext.krypt.asn1.Header;
import org.jruby.ext.krypt.asn1.ParseException;
import org.jruby.ext.krypt.asn1.Parser;
import org.jruby.ext.krypt.asn1.ParsedHeader;
import org.jruby.ext.krypt.asn1.TagClass;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class PullHeaderParser implements Parser {

    private static final int LONG_BYTE_LEN = Long.SIZE / 8;
    
    private final InputStream in;

    public PullHeaderParser(InputStream in) {
        if (in == null) throw new NullPointerException();
        this.in = in;
    }
    
    @Override
    public ParsedHeader next() {
        int read = nextInt();
        if (read == -1) 
            return null;
        byte b = (byte)read;
        //TODO: Implement this properly
        final Tag tag = parseTag(b);
	final Length length = parseLength();
        final Encodable enc = new Encodable() {
            public void encodeTo(OutputStream out) {
                tag.encodeTo(out);
                length.encodeTo(out);
            }
        };

        return new ParsedHeader() {

            @Override
            public void skipValue() {
                getValue();
            }

            @Override
            public byte[] getValue() {
                //TODO: Make this work for OCTET_STRING etc.
                if (length.isInfiniteLength())
                    throw new IllegalStateException("Not supported when current header is infinite length.");
                return readBytes(length.getLength());
            }

            @Override
            public InputStream getValueStream() {
                //TODO: Make this work for OCTET_STRING etc.
                if (length.isInfiniteLength())
                    throw new IllegalStateException("Not supported when current header is infinite length.");
                return new ByteArrayInputStream(readBytes(length.getLength()));
            }

            @Override
            public int getTag() {
                return tag.getTag();
            }

            @Override
            public TagClass getTagClass() {
                return tag.getTagClass();
            }

            @Override
            public boolean isConstructed() {
                return tag.isConstructed();
            }

            @Override
            public boolean isInfiniteLength() {
                return length.isInfiniteLength();
            }

            @Override
            public long getLength() {
                return length.getLength();
            }

            @Override
            public int getHeaderLength() {
                return tag.getEncodingLength() + length.getEncodingLength();
            }

            @Override
            public void encodeTo(OutputStream out) {
                enc.encodeTo(out);
            }

            public Encodable getEncodable() {
                return enc;
            }
            
        };
    }
    
    private byte nextByte() {
        int read = nextInt();
        if (read == -1) 
            throw new ParseException("EOF reached.");
        return (byte)read;
    }
    
    private int nextInt() {
        try {
            return in.read();
        }
        catch (IOException ex) {
            throw new ParseException(ex);
        }
    }
    
    private static boolean matchMask(byte test, byte mask) {
        return ((byte)(test & mask)) == mask;
    }
    
    private byte[] readBytes(long length) {
        
        byte[] buf = new byte[8192];
        int read = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        long total = 0;
        
        while (total != length) {
            try {
                //TODO: Hack - treat long correctly
                read = in.read(buf, 0, (int)(length - total));
                if (read == -1)
                    throw new ParseException("EOF reached while parsing value");
                total += read;
                baos.write(buf, 0, read);
            }
            catch (IOException ex) {
                throw new ParseException(ex);
            }
        }
        
        return baos.toByteArray();
    }
    
    private Tag parseTag(byte b) {
        if (matchMask(b, Header.COMPLEX_TAG_MASK))
            return parseComplexTag(b);
        else
            return parsePrimitiveTag(b);
    }
    
    private Tag parsePrimitiveTag(byte b) {
        int tag = b & Header.COMPLEX_TAG_MASK;
        boolean isConstructed = matchMask(b, Header.CONSTRUCTED_MASK);
        TagClass tc = TagClass.of((byte)(b & TagClass.PRIVATE.getMask()));
        return new Tag(tag, tc, isConstructed, new byte[] { b });
    }
    
    private Tag parseComplexTag(byte b) {
        throw new UnsupportedOperationException();
    }
    
    private Length parseLength() {
	byte b = nextByte();
	
        if (b == Header.INFINITE_LENGTH_MASK)
            return new Length(-1, true, new byte[] { b });
        else if (matchMask(b, Header.INFINITE_LENGTH_MASK))
            return parseComplexDefiniteLength(b);
        else
            return new Length(b & 0xff, false, new byte[] { b });
    }
    
    private Length parseComplexDefiniteLength(byte b) {
        long len = 0;
        int numOctets = b & 0x7f;
        
        if (numOctets > LONG_BYTE_LEN)
            throw new ParseException("Definite value length too long.");
        
        byte[] encoding = new byte[numOctets+1];
        encoding[0] = b;
        int off = 1;
        
        for (int i=numOctets; i > 0; i--) {
            b = nextByte();
            len <<= 8;
            len |= (b & 0xff);
            encoding[off++] = b;
        }
        
        return new Length(len, false, encoding);
    }
}
