package com.seguranca.servidor.application.port.out;

import com.seguranca.servidor.domain.model.ChaveAssimetrica;

/**
 * Porta de saída (outbound port) — contrato para geração do par de chaves RSA.
 * Implementada por {@code RsaGeradorDeChavesAdapter}.
 */
public interface GeradorDeChavesPort {
    ChaveAssimetrica gerar();
}
