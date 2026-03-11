# Relatorio - Atividade Pratica de Criptografia Hibrida

**Disciplina:** Seguranca de Dados  
**Entrega:** 16 de marco de 2026  
**Atividade:** Sistema cliente-servidor com criptografia de chave publica + criptografia simetrica  
**Proposta:** Troca segura de mensagens entre PC1 e PC2 com RSA-OAEP + AES-256-GCM

---

## 1. Descricao do Cenario de Aplicacao

O sistema simula uma comunicacao segura entre dois computadores:

- **PC1 (Servidor):** gera par de chaves RSA e mantem a chave privada local.
- **PC2 (Cliente):** recebe a chave publica do servidor e usa essa chave para encapsular uma chave AES de sessao.
- A mensagem e cifrada com AES-256-GCM, e o servidor recupera a chave AES com RSA-OAEP para descriptografar.

Esse modelo reproduz o padrao usado em protocolos reais: criptografia assimetrica para distribuicao segura de chave e criptografia simetrica autenticada para dados.

### Por que usar modelo hibrido?

RSA puro nao e adequado para mensagens arbitrariamente grandes e tem custo computacional elevado para cifrar dados extensos. No modo hibrido:

- RSA protege apenas a chave de sessao (curta).
- AES-GCM protege o conteudo de forma eficiente.
- A tag GCM garante integridade/autenticidade da mensagem.

### Contextos reais equivalentes

| Contexto | Equivalencia com este projeto |
|---|---|
| TLS/HTTPS | Servidor divulga chave publica; cliente negocia segredo de sessao |
| PGP/S-MIME | Remetente cifra para o destinatario com chave publica |
| APIs seguras | Dados de aplicacao trafegam em canal cifrado com autenticacao |

---

## 2. Diagramas C4 (PlantUML)

Todos os diagramas estao no arquivo [`docs/sistema-rsa-completo.plantuml`](docs/sistema-rsa-completo.plantuml).

| Diagrama | Nivel | Conteudo |
|---|---|---|
| `c4-context` | C4 Level 1 | Visao geral do sistema |
| `c4-container` | C4 Level 2 | Containers Java/Maven e rede TCP |
| `c4-component-servidor` | C4 Level 3 | Componentes internos do servidor-rsa |
| `c4-component-cliente` | C4 Level 3 | Componentes internos do cliente-rsa |
| `c4-dynamic` | C4 Level 3 | Fluxo numerado do protocolo hibrido |
| `sequence-troca-de-chaves` | Sequencia | Chamadas de API Java na troca de chave e cifra |

---

## 3. Arquitetura da Solucao

O projeto usa **Java 25** com dois modulos Maven independentes e arquitetura **Hexagonal (Ports & Adapters)**:

| Modulo | Papel | Pacote raiz |
|---|---|---|
| `servidor-rsa` | PC1: gera RSA, recebe payload, desencapsula AES, descriptografa | `com.seguranca.servidor` |
| `cliente-rsa` | PC2: recebe chave publica, gera AES, encapsula com RSA, cifra mensagem | `com.seguranca.cliente` |

### Camadas

| Camada | Responsabilidade |
|---|---|
| `domain/model` | Records imutaveis da regra de negocio |
| `application/port/in` | Contratos de entrada dos casos de uso |
| `application/port/out` | Contratos de saida (rede, criptografia) |
| `application/usecase` | Orquestracao do fluxo |
| `adapter/in` | Entrada externa (console) |
| `adapter/out` | Implementacoes de criptografia e TCP |
| `infrastructure/config` | Composicao manual de dependencias |

---

## 4. Fluxo de Comunicacao Detalhado

### 4.1 Sequencia geral

1. PC1 gera par RSA 2048 bits.
2. PC2 conecta em TCP na porta `65432`.
3. PC1 envia chave publica DER/X.509.
4. PC2 reconstrui `PublicKey`.
5. PC2 gera chave AES-256 efemera e IV de 12 bytes.
6. PC2 encapsula chave AES com RSA-OAEP (`Cipher.WRAP_MODE`).
7. PC2 cifra texto com AES/GCM/NoPadding.
8. PC2 envia payload combinado ao servidor.
9. PC1 separa payload (`wrappedKey`, `iv`, `ciphertext+tag`).
10. PC1 desencapsula chave AES com chave privada RSA (`Cipher.UNWRAP_MODE`).
11. PC1 descriptografa com AES-GCM e valida automaticamente a tag.
12. PC1 envia confirmacao ao cliente.

### 4.2 Formato do payload

```text
wrappedKey[256] || iv[12] || aesCiphertext+tag[N]
```

- `wrappedKey[256]`: resultado RSA-OAEP com chave publica do servidor.
- `iv[12]`: nonce aleatorio por mensagem.
- `aesCiphertext+tag[N]`: saida do AES-GCM (tag de 16 bytes embutida).

### 4.3 Framing na rede

O protocolo TCP usa:

```text
writeInt(tamanho) + write(bytes)
```

para envio da chave publica, payload cifrado e confirmacao.

---

## 5. Parametros Criptograficos

| Parametro | Valor |
|---|---|
| Modelo | Criptografia hibrida |
| RSA | 2048 bits |
| Padding RSA | OAEP + SHA-256 + MGF1 |
| Cipher RSA | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` |
| AES | 256 bits |
| Modo AES | GCM |
| Cipher AES | `AES/GCM/NoPadding` |
| Tag GCM | 128 bits |
| IV GCM | 12 bytes |
| Chave publica na rede | DER/X.509 (`X509EncodedKeySpec`) |
| Chave privada no servidor | DER/PKCS#8 (`PKCS8EncodedKeySpec`) |
| Porta TCP | 65432 |

---

## 6. Estrutura de Arquivos

```text
seguranca-de-dados/
|-- README.md
|-- RELATORIO.md
|-- docs/
|   `-- sistema-rsa-completo.plantuml
|-- servidor-rsa/
|   `-- src/main/java/com/seguranca/servidor/
|       |-- adapter/out/
|       |   |-- RsaGeradorDeChavesAdapter.java
|       |   |-- RsaDescriptografadorAdapter.java
|       |   `-- TcpConexaoServidorAdapter.java
|       |-- application/usecase/IniciarServidorUseCaseImpl.java
|       `-- domain/model/MensagemCifrada.java
`-- cliente-rsa/
    `-- src/main/java/com/seguranca/cliente/
        |-- adapter/out/
        |   |-- RsaCriptografadorAdapter.java
        |   `-- TcpConexaoClienteAdapter.java
        |-- application/usecase/EnviarMensagemUseCaseImpl.java
        `-- domain/model/MensagemCifrada.java
```

---

## 7. Como Executar

### 7.1 Pre-requisitos

- Java 25
- Maven 3.8+

### 7.2 Build

```bash
cd servidor-rsa && mvn package -q
cd ../cliente-rsa && mvn package -q
```

### 7.3 Execucao local (2 terminais)

**Terminal 1 (Servidor):**

```bash
cd servidor-rsa
java -jar target/servidor-rsa.jar
```

**Terminal 2 (Cliente):**

```bash
cd cliente-rsa
java -jar target/cliente-rsa.jar
```

### 7.4 Execucao em rede local

1. Descobrir IP do PC1.
2. Ajustar `HOST_SERVIDOR` em `cliente-rsa/src/main/java/com/seguranca/cliente/infrastructure/config/ClienteConfig.java`.
3. Recompilar cliente e executar ambos.

---

## 8. Exemplo de Saida no Console

### 8.1 Servidor (PC1)

```text
============================================================
  SERVIDOR (PC1) - Criptografia Hibrida RSA + AES-256-GCM
============================================================
[*] Gerando par de chaves RSA 2048 bits...
[*] Aguardando cliente e realizando troca de chave...

============================================================
  PAYLOAD HIBRIDO RECEBIDO (N bytes total):
============================================================
  [1] Chave AES encapsulada com RSA-OAEP (256 bytes):
  ...
  [2] IV (GCM, 12 bytes):
  ...
  [3] Ciphertext AES-256-GCM + tag (M bytes):
  ...
============================================================
[*] Descriptografando mensagem com a chave privada...
```

### 8.2 Cliente (PC2)

```text
[*] Conectando ao servidor e recebendo chave publica...
[*] Criptografando mensagem com esquema hibrido RSA + AES-256-GCM...
[*] Enviando payload hibrido ao servidor...
[Servidor] OK: mensagem recebida e descriptografada.
```

---

## 9. Testes Automatizados

O projeto possui **18 testes** no total:

- `servidor-rsa`: **10 testes** (unitarios + use case)
- `cliente-rsa`: **8 testes** (unitarios + integracao)

### Coberturas principais

- Cifra e decifra no fluxo hibrido.
- Rejeicao de chave invalida.
- Rejeicao de chave privada incorreta.
- Integridade GCM: payload adulterado falha na validacao.
- Orquestracao dos casos de uso sem rede real (fakes/mocks).

### Comando

```bash
cd servidor-rsa && mvn test
cd ../cliente-rsa && mvn test
```

Resultado esperado: `BUILD SUCCESS` nos dois modulos.

---

## 10. Conceitos de Seguranca Demonstrados

| Conceito | Demonstracao no projeto |
|---|---|
| Confidencialidade | Dados trafegam cifrados e apenas PC1 possui chave privada RSA |
| Integridade/autenticidade | Tag GCM valida adulteracao do payload |
| Distribuicao de chaves | Chave publica pode ser transmitida sem expor chave privada |
| Chave de sessao efemera | Nova chave AES por mensagem |
| Mitigacao de ataques legados | Uso de OAEP em vez de PKCS#1 v1.5 |

---

## 11. Limitacoes e Melhorias Futuras

### Limitacao atual

A chave publica do servidor nao e autenticada por certificado/fingerprint. Em ambiente hostil, isso permite risco de MITM.

### Melhorias recomendadas

1. Validar fingerprint da chave publica no cliente.
2. Usar certificados X.509 assinados.
3. Adicionar assinatura digital das mensagens.
4. Evoluir para canal TLS com autenticacao mutua.

---

## 12. Tecnologias Utilizadas

| Item | Versao / Detalhe |
|---|---|
| Linguagem | Java 25 (Temurin-25.0.1+8) |
| Build | Maven 3.9.9 |
| Testes | JUnit Jupiter 5.10.2 |
| Criptografia | APIs padrao `java.security` e `javax.crypto` |
| Rede | `Socket` / `ServerSocket` |
| Arquitetura | Hexagonal + Clean Architecture |
| Diagramacao | PlantUML com modelo C4 |

---

## 13. Referencias

- RFC 8017 - PKCS #1 v2.2 (RSA OAEP)
- NIST SP 800-131A - Recomendacoes de algoritmos e tamanhos de chave
- NIST SP 800-38D - GCM mode
- OWASP Cryptographic Storage Cheat Sheet
- Oracle Java Security Standard Algorithm Names
- C4 Model (Simon Brown)
