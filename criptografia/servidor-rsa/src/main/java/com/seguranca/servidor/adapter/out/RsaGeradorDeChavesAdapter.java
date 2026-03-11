package com.seguranca.servidor.adapter.out;

import com.seguranca.servidor.application.port.out.GeradorDeChavesPort;
import com.seguranca.servidor.domain.model.ChaveAssimetrica;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Adapter de saída — gera par de chaves RSA usando {@code java.security}.
 * A chave pública é codificada em DER/X.509 e a privada em DER/PKCS#8.
 */
public class RsaGeradorDeChavesAdapter implements GeradorDeChavesPort {

    private static final int TAMANHO_CHAVE_BITS = 2048;

    @Override
    public ChaveAssimetrica gerar() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(TAMANHO_CHAVE_BITS);
            KeyPair par = kpg.generateKeyPair();
            return new ChaveAssimetrica(
                    par.getPublic().getEncoded(),   // formato X.509 (SubjectPublicKeyInfo)
                    par.getPrivate().getEncoded()   // formato PKCS#8
            );
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algoritmo RSA não disponível nesta JVM", e);
        }
    }
}
