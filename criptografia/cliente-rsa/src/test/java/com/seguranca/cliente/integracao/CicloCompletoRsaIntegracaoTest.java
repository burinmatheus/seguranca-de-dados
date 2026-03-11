package com.seguranca.cliente.integracao;

import com.seguranca.cliente.adapter.out.RsaCriptografadorAdapter;
import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;
import com.seguranca.cliente.domain.model.MensagemClara;
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

/**
 * Teste de integração que simula o fluxo completo de criptografia híbrida
 * sem dependência de rede: PC1 gera as chaves, PC2 criptografa (híbrido),
 * PC1 descriptografa — tudo em memória.
 */
@DisplayName("Integração: ciclo completo RSA + AES-256-GCM PC1 ↔ PC2")
class CicloCompletoRsaIntegracaoTest {

    private static final int WRAPPED_KEY_LENGTH = 256;
    private static final int IV_LENGTH          = 12;

    @Test
    @DisplayName("PC2 deve criptografar (híbrido) e PC1 deve descriptografar corretamente")
    void cicloCompletoDeveFuncionar() throws Exception {
        // ── PC1: gera par de chaves ───────────────────────────────────────
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair par = kpg.generateKeyPair();
        byte[] chavePublicaBytes = par.getPublic().getEncoded();
        byte[] chavePrivadaBytes = par.getPrivate().getEncoded();

        // ── Simula envio da chave pública pela rede ───────────────────────
        ChavePublicaRemota chavePublicaRemota = new ChavePublicaRemota(chavePublicaBytes);

        // ── PC2: criptografa com o algoritmo híbrido ──────────────────────
        RsaCriptografadorAdapter criptografador = new RsaCriptografadorAdapter();
        String mensagemOriginal = "Comunicação segura PC1 ↔ PC2!";
        MensagemCifrada cifrada = criptografador.criptografar(
                chavePublicaRemota, new MensagemClara(mensagemOriginal));

        // ── Simula envio do payload híbrido pela rede ─────────────────────
        byte[] payload = cifrada.conteudo();
        assertTrue(payload.length > WRAPPED_KEY_LENGTH + IV_LENGTH,
                "Payload deve conter wrappedKey + IV + ciphertext");

        // ── PC1: desempacota e descriptografa manualmente ─────────────────
        byte[] wrappedKey    = new byte[WRAPPED_KEY_LENGTH];
        byte[] iv            = new byte[IV_LENGTH];
        byte[] aesCiphertext = new byte[payload.length - WRAPPED_KEY_LENGTH - IV_LENGTH];
        System.arraycopy(payload, 0,                              wrappedKey,    0, WRAPPED_KEY_LENGTH);
        System.arraycopy(payload, WRAPPED_KEY_LENGTH,             iv,            0, IV_LENGTH);
        System.arraycopy(payload, WRAPPED_KEY_LENGTH + IV_LENGTH, aesCiphertext, 0, aesCiphertext.length);

        // Desencapsular chave AES
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey chavePrivada = kf.generatePrivate(new PKCS8EncodedKeySpec(chavePrivadaBytes));
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.UNWRAP_MODE, chavePrivada, new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT));
        SecretKey aesKey = (SecretKey) rsaCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        // Decifrar com AES-256-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        String mensagemDecifrada = new String(aesCipher.doFinal(aesCiphertext), "UTF-8");

        // ── Validação ─────────────────────────────────────────────────────
        assertEquals(mensagemOriginal, mensagemDecifrada,
                "A mensagem descriptografada pelo PC1 deve ser igual à enviada pelo PC2");
    }

    @Test
    @DisplayName("PC2 NÃO deve conseguir descriptografar payload com chave pública errada")
    void pc2NaoDeveDescriptografarComChaveErrada() throws Exception {
        // PC1 gera as chaves
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair par = kpg.generateKeyPair();

        // PC2 criptografa com a chave pública do PC1
        RsaCriptografadorAdapter criptografador = new RsaCriptografadorAdapter();
        MensagemCifrada cifrada = criptografador.criptografar(
                new ChavePublicaRemota(par.getPublic().getEncoded()),
                new MensagemClara("segredo"));

        // PC1 tenta desencapsular wrappedKey com um par DIFERENTE → deve falhar
        KeyPair parErrado = kpg.generateKeyPair();
        byte[] payload = cifrada.conteudo();
        byte[] wrappedKey = new byte[WRAPPED_KEY_LENGTH];
        System.arraycopy(payload, 0, wrappedKey, 0, WRAPPED_KEY_LENGTH);

        assertThrows(Exception.class, () -> {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey chaveErrada = kf.generatePrivate(
                    new PKCS8EncodedKeySpec(parErrado.getPrivate().getEncoded()));
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.UNWRAP_MODE, chaveErrada, new OAEPParameterSpec(
                    "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT));
            rsaCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        }, "PC1 não deve conseguir desencapsular a chave AES com chave privada incorreta");
    }
}

