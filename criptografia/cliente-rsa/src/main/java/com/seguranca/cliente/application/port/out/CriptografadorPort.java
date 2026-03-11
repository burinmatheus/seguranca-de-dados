package com.seguranca.cliente.application.port.out;

import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;
import com.seguranca.cliente.domain.model.MensagemClara;

/**
 * Porta de saída (outbound port) — contrato para criptografia RSA-OAEP.
 * Implementada por {@code RsaCriptografadorAdapter}.
 */
public interface CriptografadorPort {
    MensagemCifrada criptografar(ChavePublicaRemota chavePublica, MensagemClara mensagem);
}
