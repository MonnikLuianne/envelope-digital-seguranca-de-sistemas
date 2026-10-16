# Envelope Digital Assinado

Implementação do **Trabalho 01 — Segurança em Sistemas Computacionais (UFPI)**,
no padrão **Encrypt-then-Sign**:

- **Criar envelope:** gera chave AES-256 e IV aleatórios, cifra a mensagem com
  AES-256-CBC (PKCS#7), cifra a chave de sessão com RSA-OAEP (chave pública do
  destinatário), assina o criptograma com RSA (chave privada do remetente) e
  grava tudo em um arquivo JSON.
- **Abrir envelope:** lê o JSON, **verifica a assinatura primeiro** (e
  interrompe se for inválida), recupera a chave com a chave privada do
  destinatário e decifra a mensagem.

---

## Equipe

- MONNIK LUIANNE OLIVEIRA NASCIMENTO VELOSO BARBOSA
- FRANCISCO EDUARDO MESQUITA CRUZ
- LUIDGE DE SOUSA CARVALHO

## Divisão da equipe

| Integrante | Responsabilidade | Arquivos |
|---|---|---|
| 1 | RSA-OAEP e assinatura RSA | `rsa_utils.py` |
| 2 | AES-256-CBC e montagem/leitura do JSON | `aes_utils.py`, `envelope_builder.py` |
| 3 | Interface, integração e tratamento de erros | `main.py` |

---

## Requisitos de ambiente

- Python **3.9** ou superior
- Biblioteca `cryptography` (listada em `requirements.txt`)

---

## Instalação

Na raiz do repositório:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Execução

```bash
cd trabalho-seguranca
python main.py
```

O programa exibe um menu:

```
=== Envelope Digital Assinado (Encrypt-then-Sign) ===

1) Criar envelope (cifrar e assinar)
2) Abrir envelope (verificar e decifrar)
0) Sair
```

Tecle **Enter** para aceitar o valor sugerido entre colchetes. As sugestões
apontam para os arquivos de teste descritos abaixo.

### Criar envelope

O programa solicita:

| Campo | Exemplo |
|---|---|
| Arquivo da mensagem (UTF-8) | `dados/mensagem.txt` |
| Chave pública do destinatário (PEM) | `chaves/destinatario_public.pem` |
| Chave privada do remetente (PEM) | `chaves/remetente_private.pem` |
| Hash do RSA-OAEP | `SHA-256` ou `SHA-512` |
| Hash da assinatura | `SHA-256` ou `SHA-512` |
| Codificação | `Base64` ou `Hex` |
| Nome do arquivo de saída | `dados/envelope.json` |

### Abrir envelope

O programa solicita:

| Campo | Exemplo |
|---|---|
| Arquivo do envelope (JSON) | `dados/envelope.json` |
| Chave privada do destinatário (PEM) | `chaves/destinatario_private.pem` |
| Chave pública do remetente (PEM) | `chaves/remetente_public.pem` |
| Nome do arquivo de saída | `dados/mensagem_decifrada.txt` |

Os parâmetros de hash e codificação são lidos diretamente do JSON, sem nova
entrada do usuário.

---

## Estrutura dos arquivos

```
envelope-digital-seguranca-de-sistemas/
├── requirements.txt
├── README.md
└── trabalho-seguranca/
    ├── main.py               # interface, integração e tratamento de erros
    ├── rsa_utils.py          # RSA-OAEP (cifragem da chave) e assinatura RSA
    ├── aes_utils.py          # AES-256-CBC, padding PKCS#7, codificação Base64/Hex
    ├── envelope_builder.py   # montagem, gravação, leitura e validação do JSON
    ├── chaves/               # pares RSA de 2048 bits em PEM, sem senha
    │   ├── destinatario_public.pem
    │   ├── destinatario_private.pem
    │   ├── remetente_public.pem
    │   └── remetente_private.pem
    └── dados/
        └── mensagem.txt      # mensagem em claro de exemplo (UTF-8)
```

### Arquivos de teste fornecidos

- **`dados/mensagem.txt`** — texto em UTF-8 pronto para cifrar.
- **`chaves/`** — dois pares RSA de 2048 bits, em PEM e sem senha, um para o
  destinatário e um para o remetente.

Para gerar um novo par de chaves:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out privada.pem
openssl pkey -in privada.pem -pubout -out publica.pem
```

---

## Formato do envelope JSON

```json
{
  "parametros": {
    "algoritmo_simetrico": "AES-256-CBC",
    "padding_simetrico": "PKCS7",
    "algoritmo_chave": "RSA-OAEP",
    "hash_oaep": "SHA-256",
    "algoritmo_assinatura": "RSA",
    "hash_assinatura": "SHA-256",
    "codificacao": "Base64"
  },
  "envelope": {
    "iv": "<IV de 16 bytes codificado>",
    "chave_sessao": "<chave AES cifrada com RSA-OAEP codificada>",
    "mensagem_cifrada": "<criptograma AES-256-CBC codificado>",
    "assinatura": "<assinatura RSA do criptograma codificada>"
  }
}
```

---

## Tratamento de erros

O programa nunca encerra com erro inesperado. Toda falha exibe uma mensagem
clara e retorna ao menu:

| Situação | Mensagem exibida |
|---|---|
| Arquivo não encontrado | `[ERRO] Arquivo não encontrado: <caminho>` |
| Chave em formato incorreto ou trocada | `[ERRO] Chave ou dado inválido` |
| Chave privada protegida por senha | `[ERRO]` orientando usar chave sem senha |
| JSON malformado | `[ERRO] JSON malformado` com linha e coluna |
| Campo obrigatório ausente no JSON | `[ERRO] Campo obrigatório ausente` |
| Assinatura digital inválida | `!!! ALERTA DE INTEGRIDADE !!!` — nada é decifrado nem gravado |

---

## Interoperabilidade

O formato segue estritamente o protocolo do enunciado, compatível com o
CyberChef e com os programas dos outros grupos:

- O RSA-OAEP cifra o **texto codificado** da chave de sessão (Base64 ou Hex),
  não os bytes brutos; a MGF1 usa o mesmo hash do OAEP.
- A assinatura RSA (PKCS#1 v1.5) é calculada sobre o **texto do campo
  `mensagem_cifrada`**, exatamente como ele aparece no JSON.
- A mensagem é tratada em UTF-8 e todos os campos usam a mesma codificação.

---

## Documentação dos módulos

### `rsa_utils.py` — RSA-OAEP e assinatura (Integrante 1)

Funções principais:

| Função | O que faz |
|---|---|
| `cifrar_chave_sessao(chave, pub_pem, hash, cod)` | Cifra a chave de sessão codificada com RSA-OAEP. |
| `decifrar_chave_sessao(chave_cif, priv_pem, hash, cod)` | Recupera a chave de sessão. |
| `assinar(ciphertext_str, priv_pem, hash, cod)` | Assina o criptograma codificado com RSA PKCS#1 v1.5. |
| `verificar_assinatura(ciphertext_str, assinatura, pub_pem, hash, cod)` | Verifica a assinatura; retorna `True` ou `False`. |

O hash informado é usado tanto no OAEP quanto na MGF1, conforme exigido pelo
protocolo.

---

### `aes_utils.py` — AES-256-CBC e codificação (Integrante 2)

#### Conceitos aplicados

- **AES-256**: cifra simétrica de bloco; a mesma chave de 32 bytes (256 bits)
  cifra e decifra.
- **Modo CBC** (Cipher Block Chaining): cada bloco é combinado via XOR com o
  bloco cifrado anterior antes de ser cifrado, impedindo que blocos iguais de
  plaintext gerem blocos iguais de ciphertext.
- **IV**: vetor de inicialização de 16 bytes gerado aleatoriamente; não é
  secreto e vai aberto no envelope.
- **Padding PKCS#7**: completa o último bloco com N bytes de valor N. Se o
  texto já for múltiplo de 16 bytes, acrescenta um bloco inteiro de valor 16.
  Na decifragem, bytes de padding inválidos indicam chave ou IV errados.
- **Base64 / Hex**: formas de representar bytes binários como texto para o
  JSON. Hex usa 2 caracteres por byte; Base64 usa ~1,33 caractere por byte.
- **`os.urandom`**: gerador criptograficamente seguro (CSPRNG) do sistema
  operacional, usado para gerar a chave e o IV.

#### Funções principais

| Função | O que faz |
|---|---|
| `gerar_chave_iv()` | Gera aleatoriamente chave de 32 bytes e IV de 16 bytes. |
| `codificar_chave(chave, cod)` | Representa a chave em Base64 ou Hex como bytes ASCII — é isso que o RSA cifra (passo 2 do enunciado). |
| `decodificar_chave(chave_cod, cod)` | Converte o texto saído do RSA de volta para os 32 bytes da chave AES. |
| `cifrar_aes(plaintext, chave, iv, cod)` | Cifra o texto com AES-256-CBC/PKCS#7 e retorna o criptograma codificado. |
| `decifrar_aes(ciphertext_str, chave, iv, cod)` | Decifra o criptograma e retorna o texto UTF-8 original. |
| `codificar(dados, cod)` | Converte bytes para texto Base64 ou Hex. |
| `decodificar(texto, cod, campo)` | Converte texto Base64 ou Hex de volta para bytes, com mensagem de erro indicando o campo. |

**Nota de implementação:** a função `codificar_chave` cifra a chave já
codificada (texto ASCII), e não os 32 bytes crus. Assim, quem decifrar com
RSA recupera o texto Base64/Hex, que em seguida é convertido de volta para
bytes por `decodificar_chave`. Essa é a interpretação correta dos passos 2 e 3
do enunciado, garantindo compatibilidade com o CyberChef.

---

### `envelope_builder.py` — Envelope JSON (Integrante 2)

#### Funções principais

| Função | O que faz |
|---|---|
| `criar_parametros(hash_oaep, hash_assinatura, cod)` | Monta o bloco `parametros` com os valores fixos do protocolo e as escolhas do usuário. |
| `montar_envelope(params, iv, chave_sessao, msg_cifrada, assinatura)` | Monta o dicionário completo do envelope na estrutura exata do enunciado. |
| `salvar_envelope(envelope, caminho)` | Grava o JSON em disco (UTF-8, indentado, com tratamento de todos os erros de I/O). |
| `ler_envelope(caminho)` | Lê o JSON, trata todos os erros de I/O e de parse, e chama `validar_envelope`. |
| `validar_envelope(dados)` | Valida a estrutura completa do dicionário lido e devolve a versão normalizada. |
| `validar_parametros(params)` | Valida e normaliza o bloco `parametros`, aceitando variações de maiúsculas (ex.: `"sha256"` vira `"SHA-256"`). |

**Compatibilidade com outros grupos:** o `ler_envelope` abre o arquivo como
`utf-8-sig`, aceitando também UTF-8 com BOM (gerado pelo Bloco de Notas do
Windows). O `decodificar` remove espaços e quebras de linha antes de
decodificar, aceitando Base64 com quebras de coluna e Hex com espaços, como o
CyberChef pode gerar.

---

### `main.py` — Interface e integração (Integrante 3)

Orquestra os três módulos acima no fluxo completo:

**Criar envelope:**
1. Lê o arquivo de mensagem e remove espaços finais.
2. Gera chave AES e IV (`gerar_chave_iv`).
3. Cifra a chave codificada com RSA-OAEP (`cifrar_chave_sessao`).
4. Cifra a mensagem com AES-256-CBC (`cifrar_aes`).
5. Assina o criptograma codificado com RSA (`assinar`).
6. Monta e grava o JSON (`montar_envelope`, `salvar_envelope`).

**Abrir envelope:**
1. Lê e valida o JSON (`ler_envelope`).
2. Verifica a assinatura — **para aqui se inválida** (`verificar_assinatura`).
3. Decifra a chave de sessão (`decifrar_chave_sessao`, `decodificar_chave`).
4. Decifra a mensagem (`decifrar_aes`) e grava o arquivo de saída.

A função `executar` envolve cada operação em `try/except` abrangente, de modo
que nenhuma exceção — nem as inesperadas — encerra o programa. O usuário recebe
uma mensagem orientativa e volta ao menu.
