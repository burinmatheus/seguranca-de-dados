package com.seguranca.servidor.domain.model;

/**
 * Representa o par de chaves RSA no domínio.
 * Os bytes estão no formato DER: público = X.509, privado = PKCS#8.
 */
public record ChaveAssimetrica(byte[] chavePublica, byte[] chavePrivada) {}
