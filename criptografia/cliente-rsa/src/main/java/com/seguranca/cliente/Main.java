package com.seguranca.cliente;

import com.seguranca.cliente.infrastructure.config.ClienteConfig;

public class Main {
    public static void main(String[] args) {
        ClienteConfig.criar().executar();
    }
}
