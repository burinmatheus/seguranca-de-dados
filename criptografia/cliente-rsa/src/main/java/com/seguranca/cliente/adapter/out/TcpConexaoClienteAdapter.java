package com.seguranca.cliente.adapter.out;

import com.seguranca.cliente.application.port.out.ConexaoClientePort;
import com.seguranca.cliente.domain.model.ChavePublicaRemota;
import com.seguranca.cliente.domain.model.MensagemCifrada;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Adapter de saída — gerencia a comunicação TCP do lado cliente.
 *
 * <p>Mantém o socket aberto entre as duas chamadas de porta para compartilhar
 * a mesma conexão: {@link #conectarEReceberChavePublica()} conecta e recebe
 * a chave pública; {@link #enviarEReceberConfirmacao(MensagemCifrada)} envia
 * a mensagem cifrada, recebe a confirmação e fecha a conexão.
 */
public class TcpConexaoClienteAdapter implements ConexaoClientePort {

    private final String host;
    private final int porta;
    private Socket socket;
    private DataInputStream entrada;
    private DataOutputStream saida;

    public TcpConexaoClienteAdapter(String host, int porta) {
        this.host = host;
        this.porta = porta;
    }

    @Override
    public ChavePublicaRemota conectarEReceberChavePublica() {
        try {
            socket = new Socket(host, porta);
            System.out.println("[+] Conexão estabelecida com " + host + ":" + porta);

            entrada = new DataInputStream(socket.getInputStream());
            saida   = new DataOutputStream(socket.getOutputStream());

            int tamanho = entrada.readInt();
            byte[] chaveBytes = entrada.readNBytes(tamanho);
            return new ChavePublicaRemota(chaveBytes);
        } catch (ConnectException e) {
            throw new RuntimeException(
                    "Não foi possível conectar a " + host + ":" + porta
                    + ". Verifique se o servidor está em execução.", e);
        } catch (IOException e) {
            throw new RuntimeException("Erro de rede ao conectar ao servidor", e);
        }
    }

    @Override
    public String enviarEReceberConfirmacao(MensagemCifrada mensagem) {
        try {
            saida.writeInt(mensagem.conteudo().length);
            saida.write(mensagem.conteudo());
            saida.flush();

            int tamanhoConf = entrada.readInt();
            byte[] confBytes = entrada.readNBytes(tamanhoConf);
            socket.close();
            return new String(confBytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Erro ao trocar dados com o servidor", e);
        }
    }
}
