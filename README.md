# envelope-digital-seguranca-de-sistemas

Implementação do **Envelope Digital Assinado** (Trabalho 01 — Segurança em
Sistemas Computacionais, UFPI), no padrão **Encrypt-then-Sign**:

- **Criar envelope:** gera chave AES-256 e IV aleatórios, cifra a mensagem com
  AES-256-CBC (PKCS#7), cifra a chave de sessão com RSA-OAEP (chave pública do
  destinatário), assina o criptograma com RSA (chave privada do remetente) e
  grava tudo em um arquivo JSON.
- **Abrir envelope:** lê o JSON, **verifica a assinatura primeiro** (e
  interrompe se for inválida), recupera a chave com a chave privada do
  destinatário e decifra a mensagem.

## Divisão da equipe

| Integrante | Responsabilidade | Arquivos |
|---|---|---|
| 1 | RSA-OAEP e assinatura RSA | `rsa_utils.py` |
| 2 | AES-256-CBC e montagem/leitura do JSON | `aes_utils.py`, `envelope_builder.py` |
| 3 | Interface, integração e tratamento de erros | `main.py`, `README.md` |

## Requisitos de ambiente

- Python 3.9 ou superior
- Biblioteca `cryptography` (em `requirements.txt`)
- Opcional: `pytest`, para rodar os testes

## Instalação

Na raiz do repositório:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Compilação e execução

Python é interpretado, então não há etapa de compilação. Para executar:

```bash
cd trabalho-seguranca
python main.py
```

O programa mostra um menu:

1. **Criar envelope:** pede a mensagem, a chave pública do destinatário, a
   chave privada do remetente, os hashes (SHA-256 ou SHA-512), a codificação
   (Base64 ou Hex) e o nome do arquivo JSON de saída.
2. **Abrir envelope:** pede o JSON, a chave privada do destinatário, a chave
   pública do remetente e o nome do arquivo de saída. Os hashes e a codificação
   são lidos do próprio JSON.

Tecle **Enter** para aceitar o valor sugerido entre colchetes. As sugestões
apontam para os arquivos de teste descritos abaixo.

## Estrutura dos arquivos de teste

```
trabalho-seguranca/
├── main.py, rsa_utils.py, aes_utils.py, envelope_builder.py
├── chaves/                  # pares RSA de 2048 bits, PEM e sem senha
│   ├── destinatario_public.pem   destinatario_private.pem
│   └── remetente_public.pem      remetente_private.pem
├── dados/
│   └── mensagem.txt         # mensagem em claro de exemplo (UTF-8)
└── testes/                  # testes automatizados de cada módulo
```

- **Mensagem:** texto em UTF-8. Espaços e quebras de linha no final são
  ignorados, pois alterariam o dado cifrado.
- **Chaves:** RSA em PEM, sem senha, com 2048 bits ou mais. Para gerar um novo
  par:

  ```bash
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out privada.pem
  ```
  ```bash
  openssl pkey -in privada.pem -pubout -out publica.pem
  ```

- **Envelope:** JSON com as seções `parametros` e `envelope`, no padrão do
  enunciado.

Teste completo: crie o envelope a partir de `dados/mensagem.txt` e depois
abra-o. O arquivo decifrado deve ser igual ao original.

Testes automatizados:

```bash
cd trabalho-seguranca
python -m pytest testes
```

## Tratamento de erros

O programa não fecha com erro inesperado. Cada falha mostra uma mensagem e
volta ao menu:

| Situação | Mensagem |
|---|---|
| Arquivo inexistente | `[ERRO] Arquivo não encontrado`, com o caminho |
| Chave em formato incorreto, trocada ou de outra pessoa | `[ERRO] Chave ou dado inválido`, com a dica do que conferir |
| Chave privada com senha | `[ERRO]` pedindo uma chave sem senha |
| JSON malformado | `[ERRO] JSON malformado`, com linha e coluna |
| Campo ausente no JSON | `[ERRO] Campo obrigatório ausente` |
| Assinatura inválida | `ALERTA DE INTEGRIDADE`: nada é decifrado nem gravado |

## Interoperabilidade

O formato segue o protocolo do enunciado, compatível com o CyberChef e com os
programas dos outros grupos:

- o RSA-OAEP cifra o **texto** codificado da chave de sessão (não os bytes), e
  a MGF1 usa o mesmo hash do OAEP;
- a assinatura (RSA PKCS#1 v1.5) é feita sobre o **texto** do campo
  `mensagem_cifrada`;
- a mensagem é cifrada em UTF-8, e todos os campos usam a mesma codificação.

## Documentação de cada módulo

A explicação detalhada do código do Integrante 2 está em `Explicacao-int2.md`.
