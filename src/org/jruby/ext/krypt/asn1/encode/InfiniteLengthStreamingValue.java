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
package org.jruby.ext.krypt.asn1.encode;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.NoSuchElementException;
import org.jruby.ext.krypt.asn1.Asn1;
import org.jruby.ext.krypt.asn1.SerializationException;
import org.jruby.ext.krypt.asn1.Tags;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public abstract class InfiniteLengthStreamingValue extends AbstractConstructed<Iterable<Asn1>> {
    
    public static final int DEFAULT_CHUNK_SIZE = 8192;
    
    private InfiniteLengthStreamingValue(int tag, ChunkedStream stream) {
        super(tag, stream);
        setInfiniteLength(true);
    }
    
    public InfiniteLengthStreamingValue(InputStream source, int tag, int chunkSize) {
        this(tag, new ChunkedStream(tag, source, chunkSize));
    }
    
    public InfiniteLengthStreamingValue(InputStream source, int tag) {
        this(tag, new ChunkedStream(tag, source, DEFAULT_CHUNK_SIZE));
    }

    private static class ChunkedStream implements Iterable<Asn1> {
        
        private final int chunkSize;
        private final InputStream source;
        private final int tag;

        public ChunkedStream(int tag, InputStream source, int chunkSize) {
            if (source == null) throw new NullPointerException();
            if (chunkSize <= 0) throw new IllegalArgumentException("chunkSize must be > 0");
            this.tag = tag;
            this.source = source;
            this.chunkSize = chunkSize;
        }

        @Override
        public Iterator<Asn1> iterator() {
            return new Iterator<Asn1>() {

                private boolean eof = false;
                private final byte[] buf = new byte[chunkSize];
                
                @Override
                public boolean hasNext() {
                    return !eof;
                }

                @Override
                public Asn1 next() {
                    if (eof) throw new NoSuchElementException();
                    try {
                        int read = source.read(buf);
                        if (read == -1) {
                            eof = true;
                            return new PrimitiveValue(Tags.END_OF_CONTENTS, null);
                        }
                        else {
                            byte[] trimmed = trim(read, buf);
                            return new PrimitiveValue(tag, trimmed);
                        }
                    }
                    catch (IOException ex) {
                        throw new SerializationException(ex);
                    }
                }
                
                private byte[] trim(int length, byte[] buf) {
                    if (length == buf.length)
                        return buf.clone();
                    else {
                        byte[] copy = new byte[length];
                        System.arraycopy(buf, 0, copy, 0, length);
                        return copy;
                    }
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException("Not supported.");
                }
            };
        }
        
    }
    
}
