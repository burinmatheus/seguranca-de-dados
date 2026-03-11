package com.seguranca.servidor.adapter.out;

import com.seguranca.servidor.domain.model.ChaveAssimetrica;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RsaGeradorDeChavesAdapter")
class RsaGeradorDeChavesAdapterTest {

    private RsaGeradorDeChavesAdapter gerador;

    @BeforeEach
    void setUp() {
        gerador = new RsaGeradorDeChavesAdapter();
    }

    @Test
    @DisplayName("deve gerar um par de chaves não nulo")
    void deveGerarParDeChavesNaoNulo() {
        ChaveAssimetrica chaves = gerador.gerar();

        assertNotNull(chaves);
        assertNotNull(chaves.chavePublica());
        assertNotNull(chaves.chavePrivada());
    }

    @Test
    @DisplayName("a chave pública deve ter tamanho compatível com RSA 2048")
    void chavePublicaDeveTerTamanhoCompativel() {
        ChaveAssimetrica chaves = gerador.gerar();

        // X.509 DER de RSA 2048 bits tem tipicamente entre 270 e 300 bytes
        assertTrue(chaves.chavePublica().length > 200,
                "Chave pública muito pequena: " + chaves.chavePublica().length + " bytes");
    }

    @Test
    @DisplayName("a chave privada deve ter tamanho compatível com RSA 2048 PKCS#8")
    void chavePrivadaDeveTerTamanhoCompativel() {
        ChaveAssimetrica chaves = gerador.gerar();

        // PKCS#8 DER de RSA 2048 bits tem tipicamente entre 1200 e 1300 bytes
        assertTrue(chaves.chavePrivada().length > 500,
                "Chave privada muito pequena: " + chaves.chavePrivada().length + " bytes");
    }

    @Test
    @DisplayName("cada chamada deve gerar um par de chaves diferente")
    void cadaChamadaDeveGerarChavesDiferentes() {
        ChaveAssimetrica chaves1 = gerador.gerar();
        ChaveAssimetrica chaves2 = gerador.gerar();

        assertNotEquals(
                java.util.Arrays.toString(chaves1.chavePublica()),
                java.util.Arrays.toString(chaves2.chavePublica()),
                "Duas chamadas ao gerador retornaram a mesma chave pública"
        );
    }
}
