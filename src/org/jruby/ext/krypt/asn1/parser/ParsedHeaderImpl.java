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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.jruby.ext.krypt.asn1.GenericAsn1.Length;
import org.jruby.ext.krypt.asn1.GenericAsn1.Tag;
import org.jruby.ext.krypt.asn1.ParsedHeader;
import org.jruby.ext.krypt.asn1.SerializationException;
import org.jruby.ext.krypt.asn1.TagClass;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
class ParsedHeaderImpl implements ParsedHeader {

    private final Tag tag;
    private final Length length;
    private final InputStream in;
    private final PullHeaderParser parser;
    
    private InputStream valueStream;

    ParsedHeaderImpl(Tag tag, 
                     Length length, 
                     InputStream in,
                     PullHeaderParser parser) {
        if (tag == null) throw new NullPointerException();
        if (length == null) throw new NullPointerException();
        if (in == null) throw new NullPointerException();
        if (parser == null) throw new NullPointerException();
        
	this.tag = tag;
	this.length = length;
	this.in = in;
        this.parser = parser;
   }

    @Override
    public void skipValue() {
	getValue();
    }

    @Override
    public byte[] getValue() {
	byte[] ret = consume(getValueStream());
        return ret.length == 0 ? null : ret;
    }

    @Override
    public InputStream getValueStream() {
        if (valueStream == null) {
            if (length.isInfiniteLength())
                valueStream = new ChunkInputStream(in, parser);
            else
                valueStream = new DefiniteInputStream(in, length.getLength());
        }
        return valueStream;
    }

    private byte[] consume(InputStream stream) {
        
        byte[] buf = new byte[8192];
        int read = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
            while ((read = stream.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }
        }
        catch (IOException ex) {
                throw new ParseException(ex);
        }
        
        return baos.toByteArray();
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
    public int getLength() {
	return length.getLength();
    }

    @Override
    public int getHeaderLength() {
	return tag.getEncoding().length + length.getEncoding().length;
    }

    @Override
    public void encodeTo(OutputStream out) {
	try {
            out.write(tag.getEncoding());
            out.write(length.getEncoding());
        }
        catch (IOException ex) {
            throw new SerializationException(ex);
        }
    }

    @Override
    public Length getParsedLength() {
        return length;
    }

    @Override
    public Tag getParsedTag() {
        return tag;
    }
}
