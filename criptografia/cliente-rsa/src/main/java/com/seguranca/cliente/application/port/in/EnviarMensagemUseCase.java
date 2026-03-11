package com.seguranca.cliente.application.port.in;

import com.seguranca.cliente.domain.model.MensagemClara;

/**
 * Porta de entrada (inbound port) — caso de uso do cliente.
 * Acionada pelo {@code ConsoleInputAdapter} após ler a mensagem do usuário.
 */
public interface EnviarMensagemUseCase {
    void enviar(MensagemClara mensagem);
}
