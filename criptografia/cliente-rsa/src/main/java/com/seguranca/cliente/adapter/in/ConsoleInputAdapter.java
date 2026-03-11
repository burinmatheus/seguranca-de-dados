package com.seguranca.cliente.adapter.in;

import com.seguranca.cliente.application.port.in.EnviarMensagemUseCase;
import com.seguranca.cliente.domain.model.MensagemClara;

import java.util.Scanner;

/**
 * Adapter de entrada (inbound adapter) — lê a mensagem do console e aciona
 * o caso de uso {@link EnviarMensagemUseCase}.
 *
 * <p>Em arquitetura hexagonal este adapter representa o "lado esquerdo":
 * é ele quem dirige a aplicação a partir da entrada do usuário.
 */
public class ConsoleInputAdapter {

    private final EnviarMensagemUseCase enviarMensagem;

    public ConsoleInputAdapter(EnviarMensagemUseCase enviarMensagem) {
        this.enviarMensagem = enviarMensagem;
    }

    public void executar() {
        System.out.println("=".repeat(60));
        System.out.println("  CLIENTE (PC2) — Criptografia Híbrida RSA + AES-256-GCM");
        System.out.println("=".repeat(60));
        System.out.println("-".repeat(60));

        Scanner scanner = new Scanner(System.in);
        System.out.print("  Digite a mensagem a ser enviada ao PC1: ");
        String texto = scanner.nextLine().trim();

        if (texto.isEmpty()) {
            System.out.println("[-] Mensagem vazia. Encerrando.");
            return;
        }

        System.out.println();
        enviarMensagem.enviar(new MensagemClara(texto));
    }
}
