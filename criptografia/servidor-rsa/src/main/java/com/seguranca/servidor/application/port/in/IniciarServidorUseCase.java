package com.seguranca.servidor.application.port.in;

/**
 * Porta de entrada (inbound port) — caso de uso principal do servidor.
 * Orquestra: gerar chaves → trocar chave com o cliente → descriptografar.
 */
public interface IniciarServidorUseCase {
    void iniciar();
}
