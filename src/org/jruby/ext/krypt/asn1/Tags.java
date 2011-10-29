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


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Tags {
    
    public static final byte END_OF_CONTENTS   = (byte)0x00;
    public static final byte BOOLEAN           = (byte)0x01;
    public static final byte INTEGER           = (byte)0x02;
    public static final byte BIT_STRING        = (byte)0x03;
    public static final byte OCTET_STRING      = (byte)0x04;
    public static final byte NULL              = (byte)0x05;
    public static final byte OBJECT_IDENTIFIER = (byte)0x06;
    
    public static final byte ENUMERATED        = (byte)0xa0;
    
    public static final byte UTF8_STRING       = (byte)0xc0;
    
    public static final byte SEQUENCE          = (byte)0x10;
    public static final byte SET               = (byte)0x11;
    public static final byte NUMERIC_STRING    = (byte)0x12;
    public static final byte PRINTABLE_STRING  = (byte)0x13;
    public static final byte T61_STRING        = (byte)0x14;
    public static final byte VIDEOTEX_STRING   = (byte)0x15;
    public static final byte IA5_STRING        = (byte)0x16;
    public static final byte UTC_TIME          = (byte)0x17;
    public static final byte GENERALIZED_TIME  = (byte)0x18;
    public static final byte GRAPHIC_STRING    = (byte)0x19;
    public static final byte ISO64_STRING      = (byte)0x1a;
    public static final byte GENERAL_STRING    = (byte)0x1b;
    public static final byte UNIVERSAL_STRING  = (byte)0x1c;
    
    public static final byte BMP_STRING        = (byte)0x1e;

}
