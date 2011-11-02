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

import java.util.List;
import org.jruby.ext.krypt.asn1.Asn1;
import org.jruby.ext.krypt.asn1.Constructed;
import org.jruby.ext.krypt.asn1.GenericAsn1;
import org.jruby.ext.krypt.asn1.GenericAsn1.Length;
import org.jruby.ext.krypt.asn1.GenericAsn1.Tag;
import org.jruby.ext.krypt.asn1.Header;
import org.jruby.ext.krypt.asn1.TagClass;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
abstract class AbstractConstructed extends Constructed {
    
    private int tag;
    
    private boolean isInfiniteLength = false;
    private TagClass tc = TagClass.UNIVERSAL;
    
    private Header header;
    
    protected AbstractConstructed(int tag, List<Asn1> contents) {
        super(contents);
        this.tag = tag;
    }

    @Override
    public Header getHeader() {
        if (header == null) {
            header = computeHeader();
        }
        return header;
    }
        
    private Header computeHeader() {
        Length l = new Length(computeValueLength(), isInfiniteLength);
        Tag t = new Tag(tag, tc, true);
        return GenericAsn1.headerFor(t, l);
    }
    
    private int computeValueLength() {
        if (isInfiniteLength)
            return -1;
        
        int length = 0;
        
        for (Asn1 asn : getContent()) {
            Header h = asn.getHeader();
            if (h.isInfiniteLength()) {
                length = 0;
                isInfiniteLength = true;
                return -1;
            }
            length += h.getHeaderLength() + h.getLength();
        }
        return length;
    }
    
    public void add (Asn1 asn1) {
        getContent().add(asn1);
        this.header = null; //needs to be recomputed
    }
    
    public void setInfiniteLength(boolean infinite) {
        this.isInfiniteLength = infinite;
        this.header = null; //needs to be recomputed
    }
    
    public void setTag(int contextSpecific) {
        this.tag = contextSpecific;
        this.tc = TagClass.CONTEXT_SPECIFIC;
        this.header = null; //needs to be recomputed
    }
    
}
