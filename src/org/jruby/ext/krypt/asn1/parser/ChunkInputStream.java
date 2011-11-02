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

import org.jruby.ext.krypt.asn1.ParseException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.jruby.ext.krypt.asn1.ParsedHeader;
import org.jruby.ext.krypt.asn1.Parser;
import org.jruby.ext.krypt.asn1.Tags;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
class ChunkInputStream extends FilterInputStream {

    private static enum State {
        NEW_HEADER,
        PROCESS_TAG,
        PROCESS_LENGTH,
        PROCESS_VALUE,
        DONE
    }
    
    private final Parser parser;
    
    private ParsedHeader currentHeader;
    private int headerOffset;
    private State state;
    
    ChunkInputStream(InputStream in, Parser parser) {
        super(in);
        if (parser == null) throw new NullPointerException();
        
        this.parser = parser;
        this.headerOffset = 0;
        this.state = State.NEW_HEADER;
    }

    @Override
    public int read() throws IOException {
        if (State.DONE == state)
            return -1;
        return readSingleByte();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (State.DONE == state)
            return -1;
        return readMultipleBytes(b, off, len);
    }
    
    private int readSingleByte() throws IOException {
        switch (state) {
            case NEW_HEADER: 
                readNewHeader(); //fallthrough
            case PROCESS_TAG:
                return readSingleHeaderByte(currentHeader.getParsedTag().getEncoding(),
                                            State.PROCESS_LENGTH);
            case PROCESS_LENGTH:
                int b = readSingleHeaderByte(currentHeader.getParsedLength().getEncoding(),
                                              State.PROCESS_VALUE);
                checkDone();
                return b;
            case PROCESS_VALUE:
                return readSingleValueByte();
            default:
                throw new UnsupportedOperationException(state.name());
        }
    }
    
    private void checkDone() {
        //if state is PROCESS_VALUE, this means that the tag bytes
        //have been consumed. As an EOC contains no value, we are
        //done
        if (currentHeader.getTag() == Tags.END_OF_CONTENTS &&
            state == State.PROCESS_VALUE) {
            state = State.DONE;
        }
    }
    
    private int readSingleHeaderByte(byte[] headerPart, State nextState) {
        byte ret = headerPart[headerOffset];
        headerOffset++;
        if (headerOffset == headerPart.length) {
            headerOffset = 0;
            state = nextState;
        }
        return (ret & 0xff);
    }
    
    private int readSingleValueByte() throws IOException {
        int b = currentHeader.getValueStream().read();
        if (b == -1) {
            state = State.NEW_HEADER;
            b = readSingleByte();
        }
        return b;
    }
    
    private int readMultipleBytes(byte[] b, int off, int len) throws IOException {
        int read, totalRead = 0;
        while (totalRead != len && state != State.DONE) {
            read = readMultipleBytesSingleElement(b, off, len);
            totalRead += read;
            off += read;
        }
        return totalRead;
    }
    
    private int readMultipleBytesSingleElement(byte[] b, int off, int len) throws IOException {
        int read = 0, totalRead = 0;
        
        switch (state) {
            case NEW_HEADER: 
                readNewHeader(); //fallthrough
            case PROCESS_TAG: {
                read = readHeaderBytes(currentHeader.getParsedTag().getEncoding(),
                                       State.PROCESS_LENGTH, b, off, len);
                totalRead += read;
                if (totalRead == len)
                    return totalRead;
                off += read;
            } //fallthrough
            case PROCESS_LENGTH: {
                read = readHeaderBytes(currentHeader.getParsedLength().getEncoding(),
                                           State.PROCESS_VALUE, b, off, len);
                totalRead += read;
                checkDone();
                if (totalRead == len || state == State.DONE)
                    return totalRead;
                off += read;
            } //fallthrough
            case PROCESS_VALUE:
                totalRead += readValueBytes(b, off, len);
                return totalRead;
            default:
                throw new UnsupportedOperationException(state.name());
        }
    }
    
    private int readHeaderBytes(byte[] headerPart, 
                                State nextState,
                                byte[] b,
                                int off,
                                int len) {
        int toRead;
        int available = headerPart.length - headerOffset;
        
        if (len < available) {
            headerOffset += len;
            toRead = len;
        }
        else {
            state = nextState;
            headerOffset = 0;
            toRead = available;
        }
        
        System.arraycopy(headerPart, headerOffset, b, off, toRead);
        return toRead;
    }
    
    private int readValueBytes(byte[] b, int off, int len) throws IOException {
        int read = currentHeader.getValueStream().read(b, off, len);
        if (read == -1) {
            state = State.NEW_HEADER;
            read = 0;
        }
        return read;
    }
    
    private void readNewHeader() {
        currentHeader = parser.next(in);
        if (currentHeader == null)
            throw new ParseException("Premature EOF detected.");
        state = State.PROCESS_TAG;
        headerOffset = 0;
    }

    @Override
    public void close() throws IOException {
        //do nothing
    }
   
}
