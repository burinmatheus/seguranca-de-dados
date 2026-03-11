package com.seguranca.cliente.application.port.out;

import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;

/**
 * Porta de saída (outbound port) — contrato para comunicação TCP do cliente.
 * Implementada por {@code TcpConexaoClienteAdapter}.
 *
 * <p>Protocolo esperado:
 * <ol>
 *   <li>{@link #conectarEReceberChavePublica}: conecta ao servidor e recebe a
 *       chave pública dele (4 bytes de tamanho + bytes DER).</li>
 *   <li>{@link #enviarEReceberConfirmacao}: envia a mensagem cifrada e recebe
 *       a confirmação do servidor.</li>
 * </ol>
 */
public interface ConexaoClientePort {
    ChavePublicaRemota conectarEReceberChavePublica();
    String enviarEReceberConfirmacao(MensagemCifrada mensagem);
}
