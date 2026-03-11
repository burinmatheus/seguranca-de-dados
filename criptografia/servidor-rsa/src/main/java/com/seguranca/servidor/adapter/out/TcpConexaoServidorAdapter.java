package com.seguranca.servidor.adapter.out;

import com.seguranca.servidor.application.port.out.ConexaoServidorPort;
import com.seguranca.servidor.domain.model.MensagemCifrada;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Adapter de saída — gerencia a comunicação TCP do lado servidor.
 *
 * <p>Protocolo de framing: cada bloco de dados é precedido por 4 bytes
 * (big-endian) informando o tamanho, garantindo leituras completas sobre TCP.
 *
 * <p>Ciclo de vida da conexão:
 * <ol>
 *   <li>{@link #aguardarEReceberMensagem}: abre o ServerSocket, aceita o
 *       cliente, envia a chave pública, recebe a mensagem cifrada.</li>
 *   <li>{@link #enviarConfirmacao}: envia a confirmação e fecha o socket.</li>
 * </ol>
 */
public class TcpConexaoServidorAdapter implements ConexaoServidorPort {

    private final int porta;
    private Socket clienteSocket;
    private DataInputStream entrada;
    private DataOutputStream saida;

    public TcpConexaoServidorAdapter(int porta) {
        this.porta = porta;
    }

    @Override
    public MensagemCifrada aguardarEReceberMensagem(byte[] chavePublicaBytes) {
        try (ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(porta));
            System.out.println("[*] Escutando na porta " + porta + " ...");

            clienteSocket = serverSocket.accept();
            // ServerSocket é fechado pelo try-with-resources; a conexão aceita permanece ativa.
            System.out.println("[+] Cliente conectado: "
                    + clienteSocket.getInetAddress().getHostAddress()
                    + ":" + clienteSocket.getPort());

            entrada = new DataInputStream(clienteSocket.getInputStream());
            saida   = new DataOutputStream(clienteSocket.getOutputStream());

            // Enviar chave pública
            saida.writeInt(chavePublicaBytes.length);
            saida.write(chavePublicaBytes);
            saida.flush();
            System.out.println("[+] Chave pública enviada (" + chavePublicaBytes.length + " bytes).");

            // Receber mensagem cifrada
            int tamanho = entrada.readInt();
            byte[] conteudo = entrada.readNBytes(tamanho);
            System.out.println("[+] Mensagem cifrada recebida (" + tamanho + " bytes).");

            return new MensagemCifrada(conteudo);
        } catch (IOException e) {
            throw new RuntimeException("Erro de rede no servidor — porta " + porta, e);
        }
    }

    @Override
    public void enviarConfirmacao(String mensagem) {
        try {
            byte[] bytes = mensagem.getBytes(StandardCharsets.UTF_8);
            saida.writeInt(bytes.length);
            saida.write(bytes);
            saida.flush();
            clienteSocket.close();
            System.out.println("[+] Confirmação enviada. Conexão encerrada.");
        } catch (IOException e) {
            throw new RuntimeException("Erro ao enviar confirmação ao cliente", e);
        }
    }
}
