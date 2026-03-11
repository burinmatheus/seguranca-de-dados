package com.seguranca.servidor.domain.model;

/** Representa uma mensagem criptografada (bytes crus). */
public record MensagemCifrada(byte[] conteudo) {}
