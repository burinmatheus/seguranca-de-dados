package com.seguranca.servidor.infrastructure.config;

import com.seguranca.servidor.adapter.out.RsaDescriptografadorAdapter;
import com.seguranca.servidor.adapter.out.RsaGeradorDeChavesAdapter;
import com.seguranca.servidor.adapter.out.TcpConexaoServidorAdapter;
import com.seguranca.servidor.application.port.in.IniciarServidorUseCase;
import com.seguranca.servidor.application.usecase.IniciarServidorUseCaseImpl;

/**
 * Composição manual de dependências (Poor-Man's DI).
 *
 * <p>Instancia e conecta todos os adapters e o caso de uso sem framework
 * externo. Em um projeto real este seria o lugar para Spring @Configuration
 * ou similar.
 */
public class ServidorConfig {

    private static final int PORTA = 65432;

    public static IniciarServidorUseCase criar() {
        return new IniciarServidorUseCaseImpl(
                new RsaGeradorDeChavesAdapter(),
                new RsaDescriptografadorAdapter(),
                new TcpConexaoServidorAdapter(PORTA)
        );
    }
}
