package com.seguranca.servidor;

import com.seguranca.servidor.infrastructure.config.ServidorConfig;

public class Main {
    public static void main(String[] args) {
        ServidorConfig.criar().iniciar();
    }
}
