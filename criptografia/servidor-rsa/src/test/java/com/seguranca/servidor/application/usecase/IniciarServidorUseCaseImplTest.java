package com.seguranca.servidor.application.usecase;

import com.seguranca.servidor.application.port.out.ConexaoServidorPort;
import com.seguranca.servidor.application.port.out.DescriptografadorPort;
import com.seguranca.servidor.application.port.out.GeradorDeChavesPort;
import com.seguranca.servidor.domain.model.ChaveAssimetrica;
import com.seguranca.servidor.domain.model.MensagemCifrada;
import com.seguranca.servidor.domain.model.MensagemClara;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testa o caso de uso com doubles (fakes) in-memory — sem rede nem criptografia real.
 * Verifica que o use case orquestra corretamente as chamadas às portas.
 */
@DisplayName("IniciarServidorUseCaseImpl")
class IniciarServidorUseCaseImplTest {

    @Test
    @DisplayName("deve chamar gerador, conexão e descriptografador na ordem correta")
    void deveOrquestrarChamadasNaOrdemCorreta() {
        byte[] chavePublicaFake  = new byte[]{1, 2, 3};
        byte[] chavePrivadaFake  = new byte[]{4, 5, 6};
        byte[] mensagemCifradaFake = new byte[]{7, 8, 9};
        String confirmacaoCapturada = null;

        // ── Fakes ──────────────────────────────────────────────────────────

        GeradorDeChavesPort geradorFake = () ->
                new ChaveAssimetrica(chavePublicaFake, chavePrivadaFake);

        DescriptografadorPort descriptografadorFake = (chavePriv, msg) -> {
            assertArrayEquals(chavePrivadaFake, chavePriv, "Chave privada errada passada ao descriptografador");
            assertArrayEquals(mensagemCifradaFake, msg.conteudo(), "Conteúdo cifrado errado");
            return new MensagemClara("mensagem decifrada");
        };

        AtomicReference<byte[]> chaveEnviada = new AtomicReference<>();
        AtomicReference<String> confEnviada  = new AtomicReference<>();

        ConexaoServidorPort conexaoFake = new ConexaoServidorPort() {
            @Override
            public MensagemCifrada aguardarEReceberMensagem(byte[] chavePublica) {
                chaveEnviada.set(chavePublica);
                return new MensagemCifrada(mensagemCifradaFake);
            }

            @Override
            public void enviarConfirmacao(String msg) {
                confEnviada.set(msg);
            }
        };

        // ── Executar ───────────────────────────────────────────────────────
        IniciarServidorUseCaseImpl useCase = new IniciarServidorUseCaseImpl(
                geradorFake, descriptografadorFake, conexaoFake);
        useCase.iniciar();

        // ── Verificar ──────────────────────────────────────────────────────
        assertArrayEquals(chavePublicaFake, chaveEnviada.get(),
                "A chave pública enviada ao cliente deve ser a gerada pelo gerador");
        assertNotNull(confEnviada.get(), "A confirmação deve ter sido enviada ao cliente");
        assertTrue(confEnviada.get().startsWith("OK"),
                "A confirmação deve iniciar com 'OK'");
    }

    @Test
    @DisplayName("deve propagar exceção quando o descriptografador falha")
    void devePropagar_ExcecaoDoDescriptografador() {
        GeradorDeChavesPort geradorFake = () ->
                new ChaveAssimetrica(new byte[]{1}, new byte[]{2});

        DescriptografadorPort descriptografadorFake = (chavePriv, msg) -> {
            throw new RuntimeException("chave incorreta simulada");
        };

        ConexaoServidorPort conexaoFake = new ConexaoServidorPort() {
            @Override
            public MensagemCifrada aguardarEReceberMensagem(byte[] chavePublica) {
                return new MensagemCifrada(new byte[]{9});
            }
            @Override
            public void enviarConfirmacao(String msg) {}
        };

        IniciarServidorUseCaseImpl useCase = new IniciarServidorUseCaseImpl(
                geradorFake, descriptografadorFake, conexaoFake);

        assertThrows(RuntimeException.class, useCase::iniciar);
    }
}
