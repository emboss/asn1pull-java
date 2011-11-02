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

import java.io.IOException;
import java.io.OutputStream;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public abstract class GenericAsn1 implements Asn1 {
    
    private Tag tag;
    private Length length;
    
    private Header h;
    
    public GenericAsn1(Tag tag, Length length) {
        this.tag = tag;
        this.length = length;
    }
    
    protected void update(Tag tag, Length length) {
        this.tag = tag;
        this.length = length;
        this.h = null;
    }

    @Override
    public Header getHeader() {
        if (h == null) {
            h = headerFor(tag, length);
        }
        return h;
    }
    
    public static Header headerFor(Tag tag, Length length) {
        final int ftag = tag.getTag();
        final TagClass ftc = tag.getTagClass();
        final boolean fcons = tag.isConstructed();
        final boolean finf = length.isInfiniteLength();
        final int flen = length.getLength();
        final byte[] ftenc = tag.getEncoding();
        final byte [] flenc = length.getEncoding();
        final int fhlen = ftenc.length + flenc.length;

        return new Header() {

            @Override
            public int getTag() {
                return ftag;
            }

            @Override
            public TagClass getTagClass() {
                return ftc;
            }

            @Override
            public boolean isConstructed() {
                return fcons;
            }

            @Override
            public boolean isInfiniteLength() {
                return finf;
            }

            @Override
            public int getLength() {
                return flen;
            }

            @Override
            public int getHeaderLength() {
                return fhlen;
            }

            @Override
            public void encodeTo(OutputStream out) {
                try {
                    out.write(ftenc);
                    out.write(flenc);
                }
                catch (IOException ex) {
                    throw new SerializationException(ex);
                }
            }
        };
    }

    public static class Tag {
        
        private final int tag;
        private final TagClass tc;
        private boolean isConstructed;
        private byte[] encoding;

        public Tag(int tag, TagClass tc, boolean isConstructed) {
            this(tag, tc, isConstructed, null);
        }
        
        public Tag(int tag, TagClass tc, boolean isConstructed, byte[] encoding) {
            this.tag = tag;
            this.tc = tc;
            this.isConstructed = isConstructed;
            this.encoding = encoding;
        }

        public byte[] getEncoding() {
            if (encoding == null) {
                encoding = computeEncoding();
            }
            return encoding;
        }

        public boolean isConstructed() {
            return isConstructed;
        }

        public int getTag() {
            return tag;
        }

        public TagClass getTagClass() {
            return tc;
        }
        
        private byte[] computeEncoding() {
            if (tag < 31) {
                byte tagByte = isConstructed ? Header.CONSTRUCTED_MASK : (byte)0x00;
                tagByte |= tc.getMask();
                tagByte |= (byte)(tag & 0xff);
                return new byte[] { tagByte };
            }
            else {
                return computeComplexTag();
            }
        }
        
        private byte[] computeComplexTag() {
            byte tagByte = isConstructed ? Header.CONSTRUCTED_MASK : (byte)0x00;
            tagByte |= tc.getMask();
            tagByte |= Header.COMPLEX_TAG_MASK;
            
            int numShifts = determineNumberOfShifts(tag, 7);
            byte[] out = new byte[numShifts + 1];
            int tmpTag = tag;
            
            out[0] = tagByte;
            for(int i = numShifts; i > 0; i--) {
                tagByte = (byte)(tmpTag & 0x7f);
                if (i != numShifts)
                    tagByte |= Header.INFINITE_LENGTH_MASK;
                out[i] = tagByte;
                tmpTag >>= 7;
            }
            return out;
        }
    }
    
    public static class Length {
        
        private final boolean isInfiniteLength;
        private final int length;
        private byte[] encoding;

        public Length(int length, boolean isInfiniteLength) {
            this(length, isInfiniteLength, null);
        }
        
        public Length(int length, boolean isInfiniteLength, byte[] encoding) {
            this.isInfiniteLength = isInfiniteLength;
            this.length = length;
            this.encoding = encoding;
        }

        public byte[] getEncoding() {
            if (encoding == null) {
                encoding = computeEncoding();
            }
            return encoding;
        }

        public boolean isInfiniteLength() {
            return isInfiniteLength;
        }

        public int getLength() {
            return length;
        }
        
        private byte[] computeEncoding() {
            if (isInfiniteLength) {
                return new byte[] { Header.INFINITE_LENGTH_MASK };
            }
            else if (length <= 127) {
                return new byte[] { (byte)(length & 0xff) };
            }
            else {
                return computeComplexLength();
            }
        }
        
        private byte[] computeComplexLength() {
            int numShifts = determineNumberOfShifts(length, 8);
            int tmp = length;
            byte[] out = new byte[numShifts + 1];
            out[0] = (byte)(numShifts & 0xff);
            out[0] |= Header.INFINITE_LENGTH_MASK;
            
            for (int i=numShifts; i > 0; i--) {
                out[i] = (byte)(tmp & 0xff);
                tmp >>= 8;
            }
            
            return out;
        }
    }
    
    private static int determineNumberOfShifts(int value, int shiftBy) {
        int i, tmp = value;
        for (i = 0; tmp > 0; i++) {
            tmp >>= shiftBy;
        }
        return i;
    }
}
