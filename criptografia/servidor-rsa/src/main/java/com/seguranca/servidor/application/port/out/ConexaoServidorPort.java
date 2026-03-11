package com.seguranca.servidor.application.port.out;

import com.seguranca.servidor.domain.model.MensagemCifrada;

/**
 * Porta de saída (outbound port) — contrato para comunicação TCP do servidor.
 * Implementada por {@code TcpConexaoServidorAdapter}.
 *
 * <p>Protocolo esperado:
 * <ol>
 *   <li>Aceitar a conexão do cliente</li>
 *   <li>Enviar a chave pública (4 bytes de tamanho + bytes DER)</li>
 *   <li>Receber a mensagem cifrada (4 bytes de tamanho + bytes cifrados)</li>
 *   <li>Enviar a confirmação final</li>
 * </ol>
 */
public interface ConexaoServidorPort {
    MensagemCifrada aguardarEReceberMensagem(byte[] chavePublicaBytes);
    void enviarConfirmacao(String mensagem);
}
