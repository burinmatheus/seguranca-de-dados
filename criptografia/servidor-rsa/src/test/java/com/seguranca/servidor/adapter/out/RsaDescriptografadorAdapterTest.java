package com.seguranca.servidor.adapter.out;

import com.seguranca.servidor.domain.model.ChaveAssimetrica;
import com.seguranca.servidor.domain.model.MensagemCifrada;
import com.seguranca.servidor.domain.model.MensagemClara;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RsaDescriptografadorAdapter (híbrido RSA + AES-256-GCM)")
class RsaDescriptografadorAdapterTest {

    private static final OAEPParameterSpec OAEP_SPEC = new OAEPParameterSpec(
            "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);

    private RsaGeradorDeChavesAdapter gerador;
    private RsaDescriptografadorAdapter descriptografador;

    @BeforeEach
    void setUp() {
        gerador = new RsaGeradorDeChavesAdapter();
        descriptografador = new RsaDescriptografadorAdapter();
    }

    /** Cria o payload híbrido: wrappedKey[256] || iv[12] || AES-GCM-ciphertext+tag */
    private byte[] criptografarHibrido(PublicKey pub, String mensagem) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, pub, OAEP_SPEC);
        byte[] wrappedKey = rsaCipher.wrap(aesKey);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] aesCiphertext = aesCipher.doFinal(mensagem.getBytes(StandardCharsets.UTF_8));

        byte[] payload = new byte[wrappedKey.length + iv.length + aesCiphertext.length];
        System.arraycopy(wrappedKey,    0, payload, 0,                             wrappedKey.length);
        System.arraycopy(iv,            0, payload, wrappedKey.length,             iv.length);
        System.arraycopy(aesCiphertext, 0, payload, wrappedKey.length + iv.length, aesCiphertext.length);
        return payload;
    }

    @Test
    @DisplayName("deve descriptografar uma mensagem cifrada com a chave pública correta")
    void deveDescriptografarComChaveCorreta() throws Exception {
        ChaveAssimetrica chaves = gerador.gerar();

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(chaves.chavePublica()));

        byte[] payload = criptografarHibrido(pub, "Mensagem secreta!");

        MensagemClara resultado = descriptografador.descriptografar(
                chaves.chavePrivada(), new MensagemCifrada(payload));

        assertEquals("Mensagem secreta!", resultado.texto());
    }

    @Test
    @DisplayName("deve falhar ao descriptografar com chave privada incorreta")
    void deveFalharComChavePrivadaIncorreta() throws Exception {
        ChaveAssimetrica chavesCorretas = gerador.gerar();
        ChaveAssimetrica chavesErradas  = gerador.gerar();

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(chavesCorretas.chavePublica()));
        byte[] payload = criptografarHibrido(pub, "Mensagem secreta!");

        // Tenta descriptografar com chave privada DIFERENTE — deve lançar RuntimeException
        assertThrows(RuntimeException.class, () ->
                descriptografador.descriptografar(
                        chavesErradas.chavePrivada(),
                        new MensagemCifrada(payload)),
                "Era esperado falha ao usar chave privada incorreta"
        );
    }

    @Test
    @DisplayName("deve preservar caracteres especiais e acentuação UTF-8")
    void devePreservarCaracteresEspeciais() throws Exception {
        ChaveAssimetrica chaves = gerador.gerar();
        String mensagemOriginal = "Olá, mundo! Çàü #$%@";

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(chaves.chavePublica()));
        byte[] payload = criptografarHibrido(pub, mensagemOriginal);

        MensagemClara resultado = descriptografador.descriptografar(
                chaves.chavePrivada(), new MensagemCifrada(payload));

        assertEquals(mensagemOriginal, resultado.texto());
    }

    @Test
    @DisplayName("GCM deve rejeitar payload adulterado (falha na verificação da tag)")
    void deveRejeitarPayloadAdulterado() throws Exception {
        ChaveAssimetrica chaves = gerador.gerar();
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(chaves.chavePublica()));

        byte[] payload = criptografarHibrido(pub, "Mensagem integra");
        // Adulterar último byte (pertence à tag GCM)
        payload[payload.length - 1] ^= 0xFF;

        assertThrows(RuntimeException.class, () ->
                descriptografador.descriptografar(chaves.chavePrivada(), new MensagemCifrada(payload)),
                "GCM deve rejeitar payload adulterado (AEADBadTagException)"
        );
    }
}

