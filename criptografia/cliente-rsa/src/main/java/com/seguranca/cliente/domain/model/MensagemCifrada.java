package com.seguranca.cliente.domain.model;

/** Representa a mensagem criptografada com a chave pública do servidor. */
public record MensagemCifrada(byte[] conteudo) {}
