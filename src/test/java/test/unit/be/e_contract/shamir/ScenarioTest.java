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

import static org.assertj.core.api.Assertions.assertThat;

import be.e_contract.shamir.Scheme;
import be.e_contract.shamir.Share;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScenarioTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScenarioTest.class);

    @BeforeAll
    public static void beforeAll() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testScenario() throws Exception {
        byte[] message = "hello world".getBytes();

        // generate key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // encryption
        Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedMessage = encryptionCipher.doFinal(message);
        byte[] iv = encryptionCipher.getIV();

        // split secret
        byte[] secretKeyData = secretKey.getEncoded();
        SecureRandom random = new SecureRandom();
        Scheme scheme = new Scheme(random, 5, 3);
        Map<Integer, byte[]> sharePoints = scheme.split(secretKeyData);
        List<byte[]> shares = new LinkedList<>();
        for (Map.Entry<Integer, byte[]> sharePoint : sharePoints.entrySet()) {
            Share share = new Share(sharePoint.getKey(), sharePoint.getValue());
            shares.add(share.toASN1Primitive().getEncoded());
        }

        // recover secret
        sharePoints = new HashMap<>();
        for (int idx = 0; idx < 3; idx++) {
            Share share = Share.getInstance(shares.get(idx));
            sharePoints.put(share.getIndex(), share.getShare());
        }
        scheme = new Scheme(random, 5, 3);
        byte[] recoveredSecret = scheme.join(sharePoints);

        // decrypt
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(recoveredSecret, "AES");
        Cipher decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedMessage = decryptionCipher.doFinal(encryptedMessage);

        // verify
        assertThat(decryptedMessage).isEqualTo(message);
    }
}
