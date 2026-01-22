# Aplicação de Mensageria Segura Multi-Cliente

## 🎯 Visão Geral
Este projeto implementa uma aplicação de chat segura com um servidor central, garantindo:
*   **Confidencialidade**: Criptografia AES-128-GCM.
*   **Integridade**: Tags de Autenticação GCM.
*   **Autenticidade**: Assinaturas RSA e Certificados X.509.
*   **Sigilo Perfeito (Forward Secrecy)**: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral).
*   **Anti-Replay**: Números de sequência monotônicos com validação no servidor.

## 📂 Estrutura
*   `secure_chat/certs/`: Armazena a Chave Privada RSA e o Certificado do Servidor.
*   `secure_chat/core/security.py`: Primitivas criptográficas (ECDHE, HKDF, AES-GCM).
*   `secure_chat/core/protocol.py`: Definição da estrutura dos pacotes de rede.
*   `secure_chat/server.py`: Servidor central que gerencia múltiplos clientes.
*   `secure_chat/client.py`: Interface de Linha de Comando (CLI) do Cliente.
*   `secure_chat/setup_pki.py`: Script de inicialização da infraestrutura de chaves.
*   `secure_chat/tests/`: Testes unitários e simulações de ataques.

## 🚀 Como Rodar

### 1. Pré-requisitos
Instale as dependências:
```bash
pip install cryptography
```

### 2. Inicialização (Fase 1)
Gere a Identidade do Servidor (Chave RSA + Certificado Autoassinado):
```bash
cd secure_chat
python3 setup_pki.py
```
*Isso cria os arquivos `certs/server_key.pem` e `certs/server_cert.pem`.*

### 3. Iniciar o Servidor
```bash
python3 server.py
```
*O servidor ficará escutando em 0.0.0.0:8000.*

### 4. Iniciar Clientes
Abra novos terminais para cada cliente:
```bash
# Cliente A (Alice)
python3 client.py Alice
```
```bash
# Cliente B (Bob)
python3 client.py Bob
```

### 5. Enviar Mensagens
No terminal da Alice:
```text
@Bob Ola Bob, esta mensagem eh segura!
```

## 🛡️ Verificação de Segurança
Para verificar a proteção **Anti-Replay**:
1. Certifique-se de que o Servidor está rodando.
2. Execute o script de ataque:
```bash
python3 tests/attack_replay.py
```
**Resultado Esperado**: O script enviará um pacote válido, verificará seu funcionamento e depois tentará reenviá-lo. O script deve reportar `[SUCESSO] Conexão Reiniciada` ou desconexão pelo servidor.

## 🧪 Testes Unitários
Execute os testes do núcleo criptográfico:
```bash
python3 -m unittest tests/test_crypto.py
```
