# envelope-digital-seguranca-de-sistemas

Implementação do **Envelope Digital Assinado** (Trabalho 01 — Segurança em
Sistemas Computacionais, UFPI). O programa usa criptografia híbrida no padrão
**Encrypt-then-Sign**:

- **Criação:** gera uma chave de sessão AES-256 e um IV aleatórios, cifra a
  mensagem com AES-256-CBC (PKCS#7), cifra a chave de sessão com RSA-OAEP
  (chave pública do destinatário), assina o criptograma com RSA (chave privada
  do remetente) e grava tudo em um único arquivo JSON.
- **Abertura:** lê e valida o JSON, **verifica a assinatura antes de tudo**
  (interrompe se for inválida), recupera a chave de sessão com a chave privada
  do destinatário e decifra a mensagem original.

O formato do JSON e os algoritmos seguem o protocolo do enunciado, e o
resultado é compatível com as receitas do [CyberChef](https://gchq.github.io/CyberChef/).

## Equipe e divisão

| Integrante | Responsabilidade | Arquivos |
|---|---|---|
| Integrante 1 | Criptografia assimétrica (RSA-OAEP e assinatura RSA) | `rsa_utils.py` |
| Integrante 2 | Criptografia simétrica (AES-256-CBC) e montagem/leitura do JSON | `aes_utils.py`, `envelope_builder.py` |
| Integrante 3 | Interface, integração e tratamento de erros | `main.py`, `README.md` |

## Requisitos de ambiente

- **Python 3.9 ou superior** (testado com Python 3.14).
- Biblioteca **[cryptography](https://cryptography.io)**, listada em
  `requirements.txt`.
- *Opcional:* `pytest`, para rodar os testes automatizados.
- *Opcional:* OpenSSL, para gerar novos pares de chaves RSA.

Funciona em Linux, macOS e Windows.

## Instalação

A partir da raiz do repositório:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Compilação

Python é interpretado, então **não há etapa de compilação**. Para apenas
conferir se os arquivos não têm erro de sintaxe:

```bash
python -m py_compile trabalho-seguranca/*.py
```

## Execução

Os comandos abaixo partem da pasta `trabalho-seguranca/`:

```bash
cd trabalho-seguranca
```

### Menu interativo (recomendado)

```bash
python main.py
```

O menu pergunta cada arquivo e parâmetro. Tecle **Enter** para aceitar o valor
sugerido entre colchetes, que aponta para os arquivos de exemplo de `dados/` e
`chaves/`. Também dá para **arrastar o arquivo para o terminal**: caminhos
entre aspas ou com espaços escapados (`\ `) são aceitos. Antes de sobrescrever
um arquivo existente, o programa pede confirmação.

### Linha de comando

**Criar o envelope** (cifrar e assinar):

```bash
python main.py cifrar -m dados/mensagem.txt -d chaves/destinatario_public.pem -r chaves/remetente_private.pem -o dados/envelope.json --hash-oaep SHA-512 --hash-assinatura SHA-512 --codificacao Base64
```

**Abrir o envelope** (verificar e decifrar):

```bash
python main.py decifrar -e dados/envelope.json -d chaves/destinatario_private.pem -r chaves/remetente_public.pem -o dados/mensagem_decifrada.txt
```

| Comando | Opção | Descrição |
|---|---|---|
| `cifrar` | `-m`, `--mensagem` | texto em claro (UTF-8) |
| | `-d`, `--chave-publica-destinatario` | chave **pública** do destinatário (PEM) |
| | `-r`, `--chave-privada-remetente` | chave **privada** do remetente (PEM) |
| | `-o`, `--saida` | arquivo JSON do envelope a gerar |
| | `--hash-oaep` | `SHA-256` (padrão) ou `SHA-512`, usado no OAEP e na MGF1 |
| | `--hash-assinatura` | `SHA-256` (padrão) ou `SHA-512` |
| | `--codificacao` | `Base64` (padrão) ou `Hex`, aplicada a todos os campos |
| `decifrar` | `-e`, `--envelope` | arquivo JSON do envelope |
| | `-d`, `--chave-privada-destinatario` | chave **privada** do destinatário (PEM) |
| | `-r`, `--chave-publica-remetente` | chave **pública** do remetente (PEM) |
| | `-o`, `--saida` | arquivo onde a mensagem decifrada será gravada |
| ambos | `-f`, `--sobrescrever` | permite substituir um arquivo de saída existente |

Os parâmetros de abertura (hashes e codificação) são lidos do próprio JSON.
Use `python main.py cifrar -h` ou `python main.py decifrar -h` para ver a ajuda.

**Códigos de saída:** `0` sucesso, `1` erro de entrada ou de processamento,
`2` argumentos inválidos na linha de comando, `3` **assinatura inválida**
(integridade violada) e `130` operação cancelada (Ctrl+C).

## Estrutura do projeto e dos arquivos de teste

```
trabalho-seguranca/
├── main.py                 # interface (menu + CLI), orquestração e tratamento de erros
├── rsa_utils.py            # RSA-OAEP e assinatura RSA (Integrante 1)
├── aes_utils.py            # AES-256-CBC (Integrante 2)
├── envelope_builder.py     # montagem e leitura do JSON (Integrante 2)
├── stubs.py                # substitutos temporários do Integrante 2 (ver abaixo)
├── interfaces.py           # contrato de funções entre os módulos
├── chaves/                 # pares RSA de 2048 bits usados nos testes
│   ├── destinatario_public.pem    destinatario_private.pem
│   └── remetente_public.pem       remetente_private.pem
├── dados/
│   └── mensagem.txt        # texto em claro de exemplo (UTF-8, com acentos)
└── testes/
    ├── test_rsa_utils.py
    ├── test_aes_utils.py
    ├── test_envelope.py
    └── test_main.py        # fluxo completo, compatibilidade com o CyberChef e erros
```

Requisitos de cada arquivo de entrada:

- **Mensagem em claro:** arquivo de texto **UTF-8**. Espaços e quebras de linha
  no **final** são removidos antes da cifragem, com aviso na tela (veja
  "Interoperabilidade").
- **Chaves:** RSA em formato **PEM, sem senha**, com **2048 bits ou mais**
  (SHA-512 no OAEP exige no mínimo 2048). Para gerar um novo par com OpenSSL:

  ```bash
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out chaves/remetente_private.pem
  ```
  ```bash
  openssl pkey -in chaves/remetente_private.pem -pubout -out chaves/remetente_public.pem
  ```

- **Envelope (saída da criação e entrada da abertura):** JSON com a estrutura
  exigida pelo enunciado:

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
          "chave_sessao": "<chave de sessão cifrada com RSA-OAEP, codificada>",
          "mensagem_cifrada": "<criptograma AES codificado>",
          "assinatura": "<assinatura RSA sobre o texto de mensagem_cifrada>"
      }
  }
  ```

Para um teste completo: cifre `dados/mensagem.txt` com a chave **pública do
destinatário** e a **privada do remetente**, e depois abra o envelope com a
**privada do destinatário** e a **pública do remetente**. O arquivo decifrado
deve ser idêntico ao original.

## Testes automatizados

```bash
cd trabalho-seguranca
python -m pytest testes
```

`testes/test_main.py` também pode ser executado sem pytest, com
`python testes/test_main.py`. Ele cobre:

- ida e volta em todas as combinações de hash (SHA-256/SHA-512) e codificação
  (Base64/Hex);
- **compatibilidade com o CyberChef nos dois sentidos**: uma implementação
  independente das receitas abre os envelopes do programa, e o programa abre
  envelopes montados como no CyberChef;
- assinatura adulterada: alerta de integridade, código `3` e nenhum arquivo
  gravado. A assinatura é verificada **antes** de qualquer decifragem;
- JSON malformado, campo ausente, parâmetro não suportado e campo com
  codificação inválida;
- arquivo inexistente, chaves trocadas (pública ↔ privada), chave de outro
  destinatário, PEM corrompido, chave RSA pequena demais, mensagem vazia ou
  fora de UTF-8, e proteção contra sobrescrita.

## Interoperabilidade com o CyberChef

Cada etapa do programa corresponde a uma receita do CyberChef:

| Etapa | Receita do CyberChef | Detalhe que garante a compatibilidade |
|---|---|---|
| Chave e IV | Pseudo-Random Number Generator → To Base64 | chave de 32 bytes (44 caracteres Base64) e IV de 16 bytes |
| Chave de sessão | RSA Encrypt (RSA-OAEP) → To Base64 | o RSA cifra o **texto codificado** da chave, não os bytes; MGF1 usa o mesmo hash do OAEP |
| Mensagem | Encode text (UTF-8) → To Hex → AES Encrypt (CBC, Input Hex) → To Base64 | texto em UTF-8 e padding PKCS#7 |
| Assinatura | RSA Sign → To Base64 | assina o **texto** de `mensagem_cifrada` exatamente como vai no JSON, com PKCS#1 v1.5 (sem PSS) |
| Abertura | From Base64 → RSA Verify / RSA Decrypt / AES Decrypt → Decode text | verifica sobre o texto exato do campo |

Cuidados aplicados no código:

- **Nenhum Enter ou espaço no final dos dados:** o texto em claro é lido sem os
  espaços e quebras de linha finais. Todos os campos do JSON são gravados sem
  qualquer espaço ou quebra de linha, e a assinatura é calculada sobre o campo
  já normalizado. No CyberChef, um Enter a mais no Input passaria a fazer
  parte do dado cifrado ou assinado.
- **Uma única codificação** (Base64 ou Hex) em todos os campos, inclusive no
  texto da chave que o RSA cifra.
- Arquivos gravados em UTF-8 sem conversão de fim de linha.

Os envelopes foram validados no próprio CyberChef nos dois sentidos: o CyberChef
verificou a assinatura ("Verified OK") e decifrou a mensagem gerada pelo
programa, e o programa abriu um envelope cuja chave de sessão e mensagem foram
cifradas no CyberChef.

> **Nota:** versões recentes do CyberChef têm campos extras no AES ("IV
> Length" e "Include IV in output"/"IV from input"). Deixe-os vazios ou em
> *Off*, confira *Mode = CBC* e os formatos de Input/Output da receita.

## Tratamento de erros

Nenhum erro encerra o programa com *traceback*. Cada falha mostra o que
aconteceu, o detalhe técnico (quando útil) e **como corrigir**. As entradas
são validadas antes de qualquer processamento, e nada é gravado quando
ocorre erro.

| Situação | Comportamento |
|---|---|
| Arquivo inexistente, pasta no lugar de arquivo ou sem permissão | `[ERRO]` indicando qual arquivo e a partir de qual pasta o caminho relativo foi resolvido |
| Chave pública informada no lugar da privada (ou vice-versa) | `[ERRO]` indicando a troca e o arquivo esperado |
| PEM corrompido, certificado, chave com senha ou chave não RSA | `[ERRO]` com o comando OpenSSL para corrigir |
| Chave RSA pequena demais para o OAEP escolhido | `[ERRO]` com o limite calculado; use 2048 bits ou mais |
| JSON malformado | `[ERRO]` com a linha e a coluna do problema |
| Campo ausente, parâmetro não suportado, Base64/Hex inválido, IV sem 16 bytes | `[ERRO]` apontando o campo |
| **Assinatura inválida** | **ALERTA DE INTEGRIDADE**: a abertura é interrompida, nada é decifrado nem gravado, as causas prováveis são listadas e o código de saída é `3` |
| Chave privada de outro destinatário ou `hash_oaep` divergente | `[ERRO]` ao decifrar a chave de sessão |
| Mensagem vazia ou fora de UTF-8 | `[ERRO]` pedindo para salvar o arquivo em UTF-8 |
| Arquivo de saída já existe ou é igual a uma entrada | pede confirmação (menu), exige `-f` (CLI) ou recusa, para não destruir a entrada |
| Ctrl+C ou fim da entrada | "Operação cancelada", sem *traceback* |

## Stubs temporários

`aes_utils.py` e `envelope_builder.py` são entregues pelo Integrante 2.
Enquanto eles ainda não expõem as funções do contrato (`gerar_chave_iv`,
`cifrar_aes`, `decifrar_aes`, `montar_envelope` e `ler_envelope`), o
`main.py` usa as versões de `stubs.py`, com as mesmas assinaturas, e exibe um
`[AVISO]` na tela. Quando os módulos reais estiverem prontos, o `main.py`
passa a usá-los automaticamente, sem nenhuma alteração, e `stubs.py` pode ser
removido.
