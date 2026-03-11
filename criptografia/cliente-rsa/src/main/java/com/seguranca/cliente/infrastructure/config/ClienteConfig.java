package com.seguranca.cliente.infrastructure.config;

import com.seguranca.cliente.adapter.in.ConsoleInputAdapter;
import com.seguranca.cliente.adapter.out.RsaCriptografadorAdapter;
import com.seguranca.cliente.adapter.out.TcpConexaoClienteAdapter;
import com.seguranca.cliente.application.port.in.EnviarMensagemUseCase;
import com.seguranca.cliente.application.usecase.EnviarMensagemUseCaseImpl;

/**
 * Composição manual de dependências (Poor-Man's DI).
 * Para usar em dois computadores distintos, altere {@code HOST_SERVIDOR}
 * para o IP local do PC1 na rede.
 */
public class ClienteConfig {

    private static final String HOST_SERVIDOR = "127.0.0.1"; // altere para o IP do PC1 em rede
    private static final int    PORTA_SERVIDOR = 65432;

    public static ConsoleInputAdapter criar() {
        EnviarMensagemUseCase useCase = new EnviarMensagemUseCaseImpl(
                new RsaCriptografadorAdapter(),
                new TcpConexaoClienteAdapter(HOST_SERVIDOR, PORTA_SERVIDOR)
        );
        return new ConsoleInputAdapter(useCase);
    }
}
