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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.jruby.ext.krypt.asn1.Encodable;
import org.jruby.ext.krypt.asn1.ParseException;
import org.jruby.ext.krypt.asn1.ParsedHeader;
import org.jruby.ext.krypt.asn1.TagClass;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
class ParsedHeaderImpl implements ParsedHeader {

    private final Tag tag;
    private final Length length;
    private final Encodable encodable;
    private final InputStream in;

    public ParsedHeaderImpl(Tag tag, Length length, InputStream in) {
	this.tag = tag;
	this.length = length;
	this.in = in;
	this.encodable = new Encodable() {
	    public void encodeTo(OutputStream out) {
		ParsedHeaderImpl.this.tag.encodeTo(out);
		ParsedHeaderImpl.this.length.encodeTo(out);
	    }
	};
    }

    @Override
    public void skipValue() {
	getValue();
    }

    @Override
    public byte[] getValue() {
	//TODO: Make this work for OCTET_STRING etc.
	if (length.isInfiniteLength())
	    throw new IllegalStateException("Not supported when current header is infinite length.");
	else
            return consume(getValueStream());
    }

    //TODO: Implement this properly
    @Override
    public InputStream getValueStream() {
	if (length.isInfiniteLength())
	    throw new IllegalStateException("Not supported when current header is infinite length.");
	else
            return new DefiniteInputStream(in, length.getLength());
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
    public Encodable getEncodable() {
	return encodable;
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
	return tag.getEncodingLength() + length.getEncodingLength();
    }

    @Override
    public void encodeTo(OutputStream out) {
	encodable.encodeTo(out);
    }

}
