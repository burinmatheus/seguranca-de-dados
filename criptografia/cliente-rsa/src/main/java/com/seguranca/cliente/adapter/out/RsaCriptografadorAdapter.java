package com.seguranca.cliente.adapter.out;

import com.seguranca.cliente.application.port.out.CriptografadorPort;
import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;
import com.seguranca.cliente.domain.model.MensagemClara;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Adapter de saída — criptografia híbrida RSA + AES-256-GCM.
 *
 * <p>Fluxo:
 * <ol>
 *   <li>Gera uma chave de sessão AES-256 e IV aleatório de 12 bytes</li>
 *   <li>Encapsula (wraps) a chave AES com RSA/OAEP — resultado: 256 bytes</li>
 *   <li>Cifra a mensagem com AES/GCM/NoPadding (tag de 128 bits inclusa)</li>
 *   <li>Empacota: {@code wrappedKey[256] || iv[12] || aesCiphertext+tag[N]}</li>
 * </ol>
 *
 * <p>Vantagens sobre RSA puro: suporta mensagens de qualquer tamanho,
 * garante integridade via GCM e mantém confidencialidade com chave de sessão efêmera.
 */
public class RsaCriptografadorAdapter implements CriptografadorPort {

    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LENGTH    = 12; // bytes recomendados para GCM

    private static final OAEPParameterSpec OAEP_SPEC = new OAEPParameterSpec(
            "SHA-256", "MGF1",
            new MGF1ParameterSpec("SHA-256"),
            PSource.PSpecified.DEFAULT
    );

    @Override
    public MensagemCifrada criptografar(ChavePublicaRemota chavePublica, MensagemClara mensagem) {
        try {
            // 1. Reconstruir chave pública RSA a partir dos bytes DER/X.509
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(chavePublica.conteudo()));

            // 2. Gerar chave de sessão AES-256 efêmera
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey aesKey = kg.generateKey();

            // 3. Gerar IV aleatório de 12 bytes para GCM
            byte[] iv = new byte[IV_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            // 4. Encapsular chave AES com RSA-OAEP → 256 bytes (RSA-2048)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.WRAP_MODE, pub, OAEP_SPEC);
            byte[] wrappedKey = rsaCipher.wrap(aesKey);

            // 5. Cifrar mensagem com AES-256-GCM (ciphertext inclui tag de 16 bytes)
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] aesCiphertext = aesCipher.doFinal(
                    mensagem.texto().getBytes(StandardCharsets.UTF_8));

            // 6. Empacotar: wrappedKey[256] || iv[12] || aesCiphertext+tag[N]
            byte[] payload = new byte[wrappedKey.length + iv.length + aesCiphertext.length];
            System.arraycopy(wrappedKey,     0, payload, 0,                                  wrappedKey.length);
            System.arraycopy(iv,             0, payload, wrappedKey.length,                  iv.length);
            System.arraycopy(aesCiphertext,  0, payload, wrappedKey.length + iv.length,      aesCiphertext.length);

            return new MensagemCifrada(payload);
        } catch (Exception e) {
            throw new RuntimeException("Falha ao criptografar a mensagem", e);
        }
    }
}
