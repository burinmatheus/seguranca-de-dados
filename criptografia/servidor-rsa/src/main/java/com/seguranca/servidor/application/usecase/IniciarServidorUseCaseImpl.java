package com.seguranca.servidor.application.usecase;

import com.seguranca.servidor.application.port.in.IniciarServidorUseCase;
import com.seguranca.servidor.application.port.out.ConexaoServidorPort;
import com.seguranca.servidor.application.port.out.DescriptografadorPort;
import com.seguranca.servidor.application.port.out.GeradorDeChavesPort;
import com.seguranca.servidor.domain.model.ChaveAssimetrica;
import com.seguranca.servidor.domain.model.MensagemCifrada;
import com.seguranca.servidor.domain.model.MensagemClara;

/**
 * Caso de uso principal do servidor (PC1).
 *
 * <p>Orquestra o fluxo completo:
 * <ol>
 *   <li>Gera o par de chaves RSA via {@link GeradorDeChavesPort}</li>
 *   <li>Aguarda o cliente, envia a chave pública e recebe a mensagem cifrada
 *       via {@link ConexaoServidorPort}</li>
 *   <li>Descriptografa a mensagem com a chave privada via {@link DescriptografadorPort}</li>
 *   <li>Exibe o resultado e envia confirmação ao cliente</li>
 * </ol>
 */
public class IniciarServidorUseCaseImpl implements IniciarServidorUseCase {

    private final GeradorDeChavesPort geradorDeChaves;
    private final DescriptografadorPort descriptografador;
    private final ConexaoServidorPort conexaoServidor;

    public IniciarServidorUseCaseImpl(
            GeradorDeChavesPort geradorDeChaves,
            DescriptografadorPort descriptografador,
            ConexaoServidorPort conexaoServidor) {
        this.geradorDeChaves = geradorDeChaves;
        this.descriptografador = descriptografador;
        this.conexaoServidor = conexaoServidor;
    }

    @Override
    public void iniciar() {
        System.out.println("=".repeat(60));
        System.out.println("  SERVIDOR (PC1) — Criptografia Híbrida RSA + AES-256-GCM");
        System.out.println("=".repeat(60));

        System.out.println("\n[*] Gerando par de chaves RSA 2048 bits...");
        ChaveAssimetrica chaves = geradorDeChaves.gerar();
        System.out.println("[+] Par de chaves gerado. Chave pública ("
                + chaves.chavePublica().length + " bytes) pronta para envio.");

        System.out.println("[*] Aguardando cliente e realizando troca de chave...");
        MensagemCifrada mensagemCifrada =
                conexaoServidor.aguardarEReceberMensagem(chaves.chavePublica());

        byte[] payload = mensagemCifrada.conteudo();
        int wrappedKeyLen = 256;
        int ivLen         = 12;

        System.out.println("\n" + "=".repeat(60));
        System.out.println("  PAYLOAD HÍBRIDO RECEBIDO (" + payload.length + " bytes total):");
        System.out.println("=".repeat(60));

        // Seção 1: chave AES encapsulada com RSA-OAEP (256 bytes)
        System.out.println("\n  [1] Chave AES encapsulada com RSA-OAEP (" + wrappedKeyLen + " bytes):");
        StringBuilder hexWrapped = new StringBuilder("  ");
        for (int i = 0; i < wrappedKeyLen && i < payload.length; i++) {
            hexWrapped.append(String.format("%02X", payload[i]));
        }
        System.out.println(hexWrapped);

        // Seção 2: IV do GCM (12 bytes)
        System.out.println("\n  [2] IV (GCM, " + ivLen + " bytes):");
        StringBuilder hexIv = new StringBuilder("  ");
        for (int i = wrappedKeyLen; i < wrappedKeyLen + ivLen && i < payload.length; i++) {
            hexIv.append(String.format("%02X", payload[i]));
        }
        System.out.println(hexIv);

        // Seção 3: ciphertext AES-GCM + tag de 16 bytes
        int aesCiphertextLen = Math.max(0, payload.length - wrappedKeyLen - ivLen);
        System.out.println("\n  [3] Ciphertext AES-256-GCM + tag (" + aesCiphertextLen + " bytes):");
        StringBuilder hexCipher = new StringBuilder("  ");
        for (int i = wrappedKeyLen + ivLen; i < payload.length; i++) {
            hexCipher.append(String.format("%02X", payload[i]));
        }
        System.out.println(hexCipher + "\n");
        System.out.println("=".repeat(60));

        System.out.println("[*] Descriptografando mensagem com a chave privada...");
        MensagemClara mensagemClara =
                descriptografador.descriptografar(chaves.chavePrivada(), mensagemCifrada);

        System.out.println("\n" + "=".repeat(60));
        System.out.println("  MENSAGEM DESCRIPTOGRAFADA COM SUCESSO:");
        System.out.println("=".repeat(60));
        System.out.println("\n  >>> " + mensagemClara.texto() + "\n");
        System.out.println("=".repeat(60));

        conexaoServidor.enviarConfirmacao("OK: mensagem recebida e descriptografada.");
    }
}
