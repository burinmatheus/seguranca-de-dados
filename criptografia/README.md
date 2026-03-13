# Sistema de Criptografia Hibrida RSA + AES-256-GCM

Sistema cliente-servidor em Java 25 com arquitetura hexagonal demonstrando
criptografia hibrida:

- RSA-OAEP (2048 bits) para encapsular a chave de sessao AES.
- AES-256-GCM para criptografar a mensagem e garantir integridade (tag GCM).

```
PC1 (Servidor)                                 PC2 (Cliente)
 - Gera par de chaves RSA 2048               <-->  - Recebe chave publica RSA
 - Envia chave publica DER/X.509                  - Gera chave AES-256 + IV (12 bytes)
 - Recebe payload hibrido                          - Encapsula chave AES com RSA-OAEP
 - Desencapsula chave AES com chave privada        - Cifra mensagem com AES/GCM
 - Descriptografa mensagem                          - Envia payload: wrappedKey||iv||ciphertext
```

---

## Pre-requisitos

- Java 25+ (`java --version`)
- Maven 3.8+ (`mvn --version`)

> Execute os comandos abaixo a partir da pasta `criptografia/`.

---

## Compilar

```bash
cd servidor-rsa && mvn package -q
cd ../cliente-rsa && mvn package -q
```

---

## Executar (mesmo computador)

**Terminal 1 - PC1 (Servidor):**

```bash
cd servidor-rsa
java -jar target/servidor-rsa.jar
```

**Terminal 2 - PC2 (Cliente):**

```bash
cd cliente-rsa
java -jar target/cliente-rsa.jar
```

O cliente solicita uma mensagem no console, cifra com o modo hibrido e envia.
O servidor exibe no console os segmentos do payload em hexadecimal:

- chave AES encapsulada (RSA-OAEP)
- IV do GCM
- ciphertext + tag GCM

Em seguida, descriptografa e imprime a mensagem clara.

---

## Executar em dois computadores na mesma rede

1. Descubra o IP de PC1: `ifconfig | grep "inet "`
2. Edite `cliente-rsa/src/main/java/com/seguranca/cliente/infrastructure/config/ClienteConfig.java`:
   altere `HOST_SERVIDOR` para o IP de PC1.
3. Recompile: `cd cliente-rsa && mvn package -q`
4. Execute os JARs em cada computador.

---

## Protocolo de Mensagem

O framing TCP permanece `writeInt + write` (4 bytes big-endian + payload).

Formato do payload criptografado (cliente -> servidor):

```text
wrappedKey[256] || iv[12] || aesCiphertext+tag[N]
```

- `wrappedKey[256]`: chave AES encapsulada via `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`
- `iv[12]`: nonce aleatorio do AES-GCM
- `aesCiphertext+tag[N]`: resultado de `AES/GCM/NoPadding` (inclui tag de 16 bytes)

---

## Testes

```bash
cd servidor-rsa && mvn test   # 10 testes
cd ../cliente-rsa && mvn test # 8 testes
```

Resultado esperado: `BUILD SUCCESS` em ambos os modulos.

---

## Estrutura do Projeto

```
seguranca-de-dados/
`-- criptografia/
    |-- README.md
    |-- RELATORIO.md
    |-- docs/
    |   `-- sistema-rsa-completo.plantuml   <- 1 diagrama de fluxo em etapas
    |
    |-- servidor-rsa/   (PC1)
    |   |-- pom.xml
    |   `-- src/main/java/com/seguranca/servidor/
    |       |-- domain/model/               (ChaveAssimetrica, MensagemCifrada, MensagemClara)
    |       |-- application/port/           (interfaces de entrada e saida)
    |       |-- application/usecase/        (orquestracao do fluxo)
    |       |-- adapter/out/                (RSA unwrap + AES-GCM decrypt + TCP)
    |       `-- infrastructure/config/      (wiring de dependencias)
    |
    `-- cliente-rsa/    (PC2)
        |-- pom.xml
        `-- src/main/java/com/seguranca/cliente/
            |-- domain/model/               (ChavePublicaRemota, MensagemClara, MensagemCifrada)
            |-- application/port/           (interfaces de entrada e saida)
            |-- application/usecase/        (orquestracao do fluxo)
            |-- adapter/                    (console + RSA wrap + AES-GCM + TCP)
            `-- infrastructure/config/      (wiring de dependencias)
```

---

## Detalhes Tecnicos

| Parametro | Valor |
|---|---|
| Criptografia hibrida | RSA-OAEP (troca de chave) + AES-256-GCM (dados) |
| RSA | 2048 bits |
| Cipher RSA | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` |
| Cipher AES | `AES/GCM/NoPadding` |
| Tag GCM | 128 bits |
| IV GCM | 12 bytes aleatorios |
| Serializacao da chave publica | DER / X.509 (`X509EncodedKeySpec`) |
| Framing TCP | Int big-endian (4 bytes) + payload |
| Porta | 65432 |
| Java | 25 (Temurin-25.0.1+8) |
| Build | Maven 3.9.9 |
| Testes | JUnit Jupiter 5.10.2 |

---

## Diagrama de Fluxo (PlantUML)

Arquivo: [`docs/sistema-rsa-completo.plantuml`](docs/sistema-rsa-completo.plantuml)

Renderizar no VS Code com a extensao **PlantUML** (`Alt+D`) ou em [plantuml.com/plantuml](https://plantuml.com/plantuml).

O arquivo contem um diagrama de sequencia com o fluxo completo em 4 etapas:

1. Preparacao e conexao
2. Criptografia no cliente
3. Processamento no servidor
4. Confirmacao e encerramento

---

## Seguranca

- OAEP evita as fragilidades de PKCS#1 v1.5 (Bleichenbacher).
- AES-GCM adiciona autenticacao/integridade: payload adulterado e rejeitado.
- Chave AES e efemera por mensagem, reduzindo impacto de comprometimento pontual.

Observacao: este projeto didatico ainda nao autentica a chave publica do servidor.
Para mitigar MITM em ambiente real, use certificado assinado ou fingerprint validado.
