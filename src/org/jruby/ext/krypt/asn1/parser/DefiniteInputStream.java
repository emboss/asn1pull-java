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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.jruby.ext.krypt.asn1.ParseException;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class DefiniteInputStream extends FilterInputStream {

    private int read = 0;
    private final int length;
    
    public DefiniteInputStream(InputStream in, int length) {
        super(in);
        if (length < 0) throw new IllegalArgumentException("Length must be positive");
        this.length = length;
    }

    @Override
    public int read() throws IOException {
        if (read == length)
            return -1;
        int b = super.read();
        read++;
        return b;
    }

    @Override
    public void close() throws IOException {
        //do nothing
    }
    
    

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (read == length)
            return -1;
        
        int toRead, actuallyRead;
        
        if (length - len < read)
            toRead = length - read;
        else
            toRead = len;
        
        actuallyRead = super.read(b, off, toRead);
        if (actuallyRead == -1)
            throw new ParseException("Premature end of value detected.");
        
        read += actuallyRead;
        return actuallyRead;
    }

}
