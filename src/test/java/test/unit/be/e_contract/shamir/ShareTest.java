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
package test.unit.be.e_contract.shamir;

import be.e_contract.shamir.Share;
import java.security.SecureRandom;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

public class ShareTest {

    @Test
    public void testCodec() throws Exception {
        byte[] shareData = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(shareData);
        Share share = new Share(1, shareData);

        byte[] encodedShare = share.toASN1Primitive().getEncoded();
        share = Share.getInstance(encodedShare);
        assertThat(share.getIndex()).isEqualTo(1);
        assertThat(share.getShare()).isEqualTo(shareData);
    }
}
