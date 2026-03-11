package com.seguranca.servidor.adapter.out;

import com.seguranca.servidor.application.port.out.DescriptografadorPort;
import com.seguranca.servidor.domain.model.MensagemCifrada;
import com.seguranca.servidor.domain.model.MensagemClara;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Adapter de saída — descriptografia híbrida RSA + AES-256-GCM.
 *
 * <p>Espera o payload no formato:
 * {@code wrappedKey[256] || iv[12] || aesCiphertext+tag[N]}
 *
 * <p>Fluxo:
 * <ol>
 *   <li>Desempacota (unwraps) a chave AES com RSA-OAEP usando a chave privada</li>
 *   <li>Decifra o ciphertext com AES/GCM/NoPadding — valida automaticamente a tag de autenticação</li>
 * </ol>
 *
 * <p>A validação da tag GCM garante integridade: qualquer adulteração no payload
 * lança {@link AEADBadTagException}, prevenindo ataques de manipulação de ciphertext.
 */
public class RsaDescriptografadorAdapter implements DescriptografadorPort {

    private static final int WRAPPED_KEY_LENGTH = 256; // bytes (RSA-2048)
    private static final int IV_LENGTH          = 12;  // bytes (GCM)
    private static final int GCM_TAG_BITS       = 128;

    private static final OAEPParameterSpec OAEP_SPEC = new OAEPParameterSpec(
            "SHA-256", "MGF1",
            new MGF1ParameterSpec("SHA-256"),
            PSource.PSpecified.DEFAULT
    );

    @Override
    public MensagemClara descriptografar(byte[] chavePrivadaBytes, MensagemCifrada mensagem) {
        try {
            byte[] payload = mensagem.conteudo();

            // 1. Desempacotar: wrappedKey[256] || iv[12] || aesCiphertext[N]
            byte[] wrappedKey     = new byte[WRAPPED_KEY_LENGTH];
            byte[] iv             = new byte[IV_LENGTH];
            byte[] aesCiphertext  = new byte[payload.length - WRAPPED_KEY_LENGTH - IV_LENGTH];

            System.arraycopy(payload, 0,                              wrappedKey,    0, WRAPPED_KEY_LENGTH);
            System.arraycopy(payload, WRAPPED_KEY_LENGTH,             iv,            0, IV_LENGTH);
            System.arraycopy(payload, WRAPPED_KEY_LENGTH + IV_LENGTH, aesCiphertext, 0, aesCiphertext.length);

            // 2. Reconstruir chave privada e desencapsular chave AES via RSA-OAEP
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey chavePrivada = kf.generatePrivate(new PKCS8EncodedKeySpec(chavePrivadaBytes));

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.UNWRAP_MODE, chavePrivada, OAEP_SPEC);
            SecretKey aesKey = (SecretKey) rsaCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

            // 3. Decifrar com AES-256-GCM (lança AEADBadTagException se payload adulterado)
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] textoBytes = aesCipher.doFinal(aesCiphertext);

            return new MensagemClara(new String(textoBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Falha ao descriptografar a mensagem recebida", e);
        }
    }
}
