package com.seguranca.cliente.application.usecase;

import com.seguranca.cliente.application.port.in.EnviarMensagemUseCase;
import com.seguranca.cliente.application.port.out.ConexaoClientePort;
import com.seguranca.cliente.application.port.out.CriptografadorPort;
import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;
import com.seguranca.cliente.domain.model.MensagemClara;

/**
 * Caso de uso do cliente (PC2).
 *
 * <p>Orquestra o fluxo completo:
 * <ol>
 *   <li>Conecta ao servidor e obtém a chave pública via {@link ConexaoClientePort}</li>
 *   <li>Criptografa a mensagem com a chave pública via {@link CriptografadorPort}</li>
 *   <li>Envia a mensagem cifrada e exibe a confirmação do servidor</li>
 * </ol>
 */
public class EnviarMensagemUseCaseImpl implements EnviarMensagemUseCase {

    private final CriptografadorPort criptografador;
    private final ConexaoClientePort conexaoCliente;

    public EnviarMensagemUseCaseImpl(CriptografadorPort criptografador,
                                     ConexaoClientePort conexaoCliente) {
        this.criptografador = criptografador;
        this.conexaoCliente = conexaoCliente;
    }

    @Override
    public void enviar(MensagemClara mensagem) {
        System.out.println("[*] Conectando ao servidor e recebendo chave pública...");
        ChavePublicaRemota chavePublica = conexaoCliente.conectarEReceberChavePublica();
        System.out.println("[+] Chave pública recebida ("
                + chavePublica.conteudo().length + " bytes).");

        System.out.println("[*] Criptografando mensagem com esquema híbrido RSA + AES-256-GCM...");
        MensagemCifrada mensagemCifrada = criptografador.criptografar(chavePublica, mensagem);
        System.out.println("[+] Payload híbrido gerado ("
                + mensagemCifrada.conteudo().length + " bytes).");
        System.out.println("[i] Formato: wrappedKey[256] + iv[12] + ciphertext+tag[N].");
        System.out.println("[i] Somente o PC1 (detentor da chave privada) pode recuperar a chave AES e ler a mensagem.");

        System.out.println("[*] Enviando payload híbrido ao servidor...");
        String confirmacao = conexaoCliente.enviarEReceberConfirmacao(mensagemCifrada);

        System.out.println("\n[Servidor] " + confirmacao);
        System.out.println("[+] Comunicação finalizada com sucesso.");
    }
}
