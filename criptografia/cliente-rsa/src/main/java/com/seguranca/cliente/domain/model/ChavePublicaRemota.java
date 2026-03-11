package com.seguranca.cliente.domain.model;

/**
 * Representa a chave pública recebida do servidor.
 * Os bytes estão no formato DER/X.509 (SubjectPublicKeyInfo).
 */
public record ChavePublicaRemota(byte[] conteudo) {}
