/*
 * Copyright (C) 2019 e-Contract.be BVBA.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.e_contract.shamir;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class Share implements ASN1Encodable {

    public static final int VERSION = 1;

    private Integer index;

    private byte[] share;

    public Share(Integer index, byte[] share) {
        this.index = index;
        this.share = share;
    }

    public static Share getInstance(Object obj) {
        if (null == obj || obj instanceof Share) {
            return (Share) obj;
        } else {
            return new Share(ASN1Sequence.getInstance(obj));
        }
    }

    private Share(ASN1Sequence sequence) {
        BigInteger version = ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue();
        if (!version.equals(BigInteger.valueOf(VERSION))) {
            throw new IllegalArgumentException("version mismatch");
        }
        BigInteger shareBigInt = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
        this.index = shareBigInt.intValue();
        this.share = ASN1OctetString.getInstance(sequence.getObjectAt(2)).getOctets();
    }

    public Integer getIndex() {
        return this.index;
    }

    public byte[] getShare() {
        return this.share;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(VERSION));
        vector.add(new ASN1Integer(this.index));
        vector.add(new DEROctetString(this.share));
        return new DERSequence(vector);
    }
}
