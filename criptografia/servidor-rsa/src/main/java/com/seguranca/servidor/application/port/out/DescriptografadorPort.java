package com.seguranca.servidor.application.port.out;

import com.seguranca.servidor.domain.model.MensagemCifrada;
import com.seguranca.servidor.domain.model.MensagemClara;

/**
 * Porta de saída (outbound port) — contrato para descriptografia RSA-OAEP.
 * Implementada por {@code RsaDescriptografadorAdapter}.
 */
public interface DescriptografadorPort {
    MensagemClara descriptografar(byte[] chavePrivadaBytes, MensagemCifrada mensagem);
}
