package com.seguranca.cliente.application.usecase;

import com.seguranca.cliente.application.port.out.ConexaoClientePort;
import com.seguranca.cliente.application.port.out.CriptografadorPort;
import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;
import com.seguranca.cliente.domain.model.MensagemClara;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testa o caso de uso com doubles (fakes) in-memory — sem rede nem criptografia real.
 */
@DisplayName("EnviarMensagemUseCaseImpl")
class EnviarMensagemUseCaseImplTest {

    @Test
    @DisplayName("deve criptografar com a chave recebida do servidor e enviar")
    void deveCriptografarComChaveRecebidaDoServidor() {
        byte[] chavePublicaFake = new byte[]{10, 20, 30};
        byte[] mensagemCifradaFake = new byte[]{99, 88, 77};
        MensagemClara entrada = new MensagemClara("Olá PC1");

        AtomicReference<ChavePublicaRemota> chaveCaptured  = new AtomicReference<>();
        AtomicReference<MensagemClara>      mensagemCapt   = new AtomicReference<>();
        AtomicReference<MensagemCifrada>    cifradaCaptured = new AtomicReference<>();

        CriptografadorPort criptografadorFake = (chave, msg) -> {
            chaveCaptured.set(chave);
            mensagemCapt.set(msg);
            return new MensagemCifrada(mensagemCifradaFake);
        };

        ConexaoClientePort conexaoFake = new ConexaoClientePort() {
            @Override
            public ChavePublicaRemota conectarEReceberChavePublica() {
                return new ChavePublicaRemota(chavePublicaFake);
            }

            @Override
            public String enviarEReceberConfirmacao(MensagemCifrada msg) {
                cifradaCaptured.set(msg);
                return "OK: mensagem recebida e descriptografada.";
            }
        };

        EnviarMensagemUseCaseImpl useCase = new EnviarMensagemUseCaseImpl(
                criptografadorFake, conexaoFake);
        useCase.enviar(entrada);

        // A chave usada para cifrar deve ser a recebida do servidor
        assertArrayEquals(chavePublicaFake, chaveCaptured.get().conteudo());
        // A mensagem passada ao criptografador deve ser a de entrada
        assertEquals("Olá PC1", mensagemCapt.get().texto());
        // O conteúdo enviado ao servidor deve ser o retornado pelo criptografador
        assertArrayEquals(mensagemCifradaFake, cifradaCaptured.get().conteudo());
    }

    @Test
    @DisplayName("deve propagar exceção quando a conexão com o servidor falha")
    void devePropagar_ExcecaoDaConexao() {
        CriptografadorPort criptografadorFake = (chave, msg) ->
                new MensagemCifrada(new byte[]{1});

        ConexaoClientePort conexaoFake = new ConexaoClientePort() {
            @Override
            public ChavePublicaRemota conectarEReceberChavePublica() {
                throw new RuntimeException("servidor indisponível simulado");
            }

            @Override
            public String enviarEReceberConfirmacao(MensagemCifrada msg) {
                return "OK";
            }
        };

        EnviarMensagemUseCaseImpl useCase = new EnviarMensagemUseCaseImpl(
                criptografadorFake, conexaoFake);

        assertThrows(RuntimeException.class, () -> useCase.enviar(new MensagemClara("teste")));
    }
}
