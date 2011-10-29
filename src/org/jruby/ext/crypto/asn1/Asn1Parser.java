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
package org.jruby.ext.crypto.asn1;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Asn1Parser {
    
    private final ParserFactory parserFactory;
    
    public Asn1Parser(ParserFactory parser) {
	if (parser == null) throw new NullPointerException();
	
        this.parserFactory = parser;
    }
    
    public Asn1 parse(InputStream in) {
	if (in == null) throw new NullPointerException();
	
        Parser hp = parserFactory.newHeaderParser(in);
        ParsedHeader h = hp.next();
        if (h == null)
            return null;
        return parse(hp, h);
    }
    
    private Asn1 parse(Parser hp, ParsedHeader h) {
        if (h.isConstructed())
            return parseConstructed(hp, h);
        else
            return parsePrimitive(h);
    }
    
    private Primitive parsePrimitive(ParsedHeader h) {
        return new Primitive(new HeaderImpl(h, h.getEncodable()), h.getValue());
    }
    
    private Constructed parseConstructed(Parser hp, ParsedHeader h) {
        if (h.isInfiniteLength())
            return parseInfiniteConstructed(hp, h);
	else
	    return parseDefiniteConstructed(hp, h);
    }

    private Constructed parseDefiniteConstructed(Parser hp, ParsedHeader h) {
	List<Asn1> contents = new ArrayList<Asn1>();
	long len = h.getLength(), curLen = 0;
        ParsedHeader nested;

        while (curLen != len) {
	    nested = hp.next();
            if (Long.MAX_VALUE - nested.getHeaderLength() - curLen < nested.getLength())
                throw new ParseException("Constructed sequence is too long.");
            curLen = curLen + nested.getHeaderLength() + nested.getLength();
            if (curLen > len)
                throw new ParseException("Malformed encoding. Single lengths of "+
                                         "constructed value do not add up to total value");
            contents.add(parse(hp, nested));
        }

        return new Constructed(new HeaderImpl(h, h.getEncodable()), contents);
    }

    private Constructed parseInfiniteConstructed(Parser hp, ParsedHeader h) {
        List<Asn1> contents = new ArrayList<Asn1>();
	boolean parsedEof = false;
        ParsedHeader nested;

        while (!parsedEof) {
	    nested = hp.next();
            contents.add(parse(hp, nested));
            if (nested.getTag() == Tags.END_OF_CONTENTS) {
                if (nested.getLength() != 0)
                    throw new ParseException("EOF tag with length > 0 found.");
                parsedEof = true;
            }
        }
        return new Constructed(new HeaderImpl(h, h.getEncodable()), contents);
    }
    
    private static class HeaderImpl implements Header {

        private final long length;
        private final int headerLength;
        private final int tag;
        private final TagClass tc;
        private final boolean isInfinite;
        private final boolean isConstructed;
        private final Encodable enc;

        public HeaderImpl(ParsedHeader h, Encodable enc) {
            this.length = h.getLength();
            this.headerLength = h.getHeaderLength();
            this.tag = h.getTag();
            this.tc = h.getTagClass();
            this.isInfinite = h.isInfiniteLength();
            this.isConstructed = h.isConstructed();
            this.enc = enc;
        }
        
        @Override
        public long getLength() {
            return length;
        }

        @Override
        public int getHeaderLength() {
            return headerLength;
        }

        @Override
        public int getTag() {
            return tag;
        }

        @Override
        public TagClass getTagClass() {
            return tc;
        }

        @Override
        public boolean isConstructed() {
            return isConstructed;
        }

        @Override
        public boolean isInfiniteLength() {
            return isInfinite;
        }

        @Override
        public void encodeTo(OutputStream out) {
            enc.encodeTo(out);
        }
        
    }
}
