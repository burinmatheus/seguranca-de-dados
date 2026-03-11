package com.seguranca.cliente.adapter.out;

import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;
import com.seguranca.cliente.domain.model.MensagemClara;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RsaCriptografadorAdapter (híbrido RSA + AES-256-GCM)")
class RsaCriptografadorAdapterTest {

    private static final int WRAPPED_KEY_LENGTH = 256;
    private static final int IV_LENGTH          = 12;

    private RsaCriptografadorAdapter criptografador;
    private KeyPair par;

    @BeforeEach
    void setUp() throws Exception {
        criptografador = new RsaCriptografadorAdapter();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        par = kpg.generateKeyPair();
    }

    @Test
    @DisplayName("deve produzir payload com comprimento mínimo correto (256 wrappedKey + 12 IV + 1+ texto)")
    void deveProduzirPayloadComTamanhoMinimo() {
        ChavePublicaRemota chave = new ChavePublicaRemota(par.getPublic().getEncoded());

        MensagemCifrada cifrada = criptografador.criptografar(chave, new MensagemClara("A"));

        // wrappedKey(256) + IV(12) + AES-GCM-ciphertext+tag(>=17 para 1 byte de texto)
        assertTrue(cifrada.conteudo().length >= WRAPPED_KEY_LENGTH + IV_LENGTH + 17,
                "Payload deve ter pelo menos 285 bytes para 1 byte de texto");
    }

    @Test
    @DisplayName("o payload cifrado deve ser descriptografável com a chave privada correspondente")
    void payloadDeveSerDescriptografavelComChavePrivada() throws Exception {
        String textoOriginal = "Mensagem de teste 123";
        ChavePublicaRemota chave = new ChavePublicaRemota(par.getPublic().getEncoded());

        MensagemCifrada cifrada = criptografador.criptografar(chave, new MensagemClara(textoOriginal));
        byte[] payload = cifrada.conteudo();

        // Desempacotar manualmente para verificar o protocolo híbrido
        byte[] wrappedKey    = new byte[WRAPPED_KEY_LENGTH];
        byte[] iv            = new byte[IV_LENGTH];
        byte[] aesCiphertext = new byte[payload.length - WRAPPED_KEY_LENGTH - IV_LENGTH];
        System.arraycopy(payload, 0,                              wrappedKey,    0, WRAPPED_KEY_LENGTH);
        System.arraycopy(payload, WRAPPED_KEY_LENGTH,             iv,            0, IV_LENGTH);
        System.arraycopy(payload, WRAPPED_KEY_LENGTH + IV_LENGTH, aesCiphertext, 0, aesCiphertext.length);

        // Desencapsular chave AES com RSA-OAEP
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(par.getPrivate().getEncoded()));
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.UNWRAP_MODE, priv, new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT));
        SecretKey aesKey = (SecretKey) rsaCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        // Decifrar com AES-256-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        String decifrado = new String(aesCipher.doFinal(aesCiphertext), "UTF-8");

        assertEquals(textoOriginal, decifrado);
    }

    @Test
    @DisplayName("deve gerar payloads diferentes a cada chamada (IV e chave AES efêmeros)")
    void deveGerarPayloadsDiferentesACadaChamada() {
        ChavePublicaRemota chave = new ChavePublicaRemota(par.getPublic().getEncoded());
        MensagemClara mensagem = new MensagemClara("mesma mensagem");

        MensagemCifrada cifrada1 = criptografador.criptografar(chave, mensagem);
        MensagemCifrada cifrada2 = criptografador.criptografar(chave, mensagem);

        assertFalse(java.util.Arrays.equals(cifrada1.conteudo(), cifrada2.conteudo()),
                "Payloads devem diferir a cada chamada (IV e chave AES aleatórios)");
    }

    @Test
    @DisplayName("deve falhar ao usar chave pública inválida (bytes corrompidos)")
    void deveFalharComChavePublicaInvalida() {
        ChavePublicaRemota chaveInvalida = new ChavePublicaRemota(new byte[]{0, 1, 2, 3});

        assertThrows(RuntimeException.class, () ->
                criptografador.criptografar(chaveInvalida, new MensagemClara("teste")),
                "Era esperado RuntimeException para chave pública inválida"
        );
    }
}
