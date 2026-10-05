# Integrante 2: Criptografia simétrica e envelope JSON

Este documento explica, linha a linha, os dois módulos da parte do Integrante 2 no Trabalho 01 (Envelope Digital Assinado):

| Arquivo | O que faz |
|---|---|
| `aes_utils.py` | Gera a chave e o IV, cifra e decifra com AES-256-CBC/PKCS#7 e converte bytes para Base64/Hex e de volta. |
| `envelope_builder.py` | Monta, grava, lê e valida o arquivo JSON do envelope. |

Requisito: Python 3.8+ e a biblioteca `cryptography` (`pip install cryptography`).

---

## Conceitos usados no código

- **AES-256**: cifra simétrica de bloco. A mesma chave cifra e decifra. "256" é o tamanho da chave: 256 bits = 32 bytes.
- **Bloco**: o AES sempre processa pedaços de 16 bytes (128 bits).
- **Modo CBC** (Cipher Block Chaining): antes de cifrar cada bloco, ele é combinado (XOR) com o bloco cifrado anterior. Com isso, dois blocos iguais de texto não geram blocos cifrados iguais.
- **IV** (vetor de inicialização): o primeiro bloco não tem um "anterior", então ele é combinado com o IV. O IV tem 16 bytes, é aleatório a cada cifragem e não é secreto: vai aberto no envelope.
- **Padding PKCS#7**: o texto precisa ter tamanho múltiplo de 16. O PKCS#7 completa o último bloco com N bytes de valor N. Por exemplo, se faltam 3 bytes, ele acrescenta `03 03 03`. Se o texto já tiver tamanho múltiplo de 16, ele acrescenta um bloco inteiro de `10` (16 em hexadecimal). Na decifragem esses bytes são removidos. Se estiverem errados, é sinal de chave errada ou de dados corrompidos.
- **Base64 / Hex**: o resultado da cifragem são bytes binários, que não podem ir direto num JSON. Base64 e Hex são duas formas de escrever esses bytes como texto. Hex usa 2 caracteres por byte. Base64 usa cerca de 1,33 caractere por byte.
- **UTF-8**: a forma de transformar texto (com acentos) em bytes. O "ç", por exemplo, vira 2 bytes: `c3 a7`.

---

# Parte 1: `aes_utils.py`

### Linhas 1–10: docstring do módulo

```python
"""
aes_utils.py — Criptografia simétrica (Integrante 2).
...
"""
```
Texto entre três aspas no início do arquivo. É a documentação do módulo e não executa nada. Aparece quando alguém roda `help(aes_utils)`.

### Linhas 12–17: importações

```python
import base64
import binascii
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
```
| Linha | Explicação |
|---|---|
| 12 | `base64`: módulo padrão do Python para codificar e decodificar Base64. |
| 13 | `binascii`: usado só para capturar `binascii.Error`, o erro que o `base64` lança quando o texto é inválido. |
| 14 | `os`: fornece `os.urandom`, o gerador de números aleatórios seguro do sistema operacional. |
| 16 | `padding`: implementação do PKCS#7 da biblioteca `cryptography`. |
| 17 | `Cipher`, `algorithms`, `modes`: as peças para montar o cifrador. `algorithms.AES` é o algoritmo e `modes.CBC` é o modo. |

O enunciado exige uma biblioteca de criptografia consolidada, então nada de criptografia foi implementado à mão.

### Linhas 19–22: constantes

```python
TAMANHO_CHAVE = 32  # AES-256 -> 256 bits
TAMANHO_IV = 16     # bloco do AES -> 128 bits

CODIFICACOES = ("Base64", "Hex")
```
| Linha | Explicação |
|---|---|
| 19 | Tamanho da chave em bytes: 32 bytes × 8 = 256 bits, por isso "AES-256". |
| 20 | Tamanho do IV em bytes: igual ao bloco do AES, 16 bytes = 128 bits. |
| 22 | As duas codificações aceitas pelo protocolo. Fica como referência para quem usa o módulo. |

Os nomes estão em MAIÚSCULAS porque, por convenção do Python, são constantes que não devem ser alteradas.

### Linhas 25–26: exceção própria

```python
class ErroAES(Exception):
    """Erro na cifragem/decifragem simétrica ou na codificação dos dados."""
```
Cria um tipo de erro específico do módulo, herdando de `Exception`. Qualquer falha aqui é lançada como `ErroAES`. Assim o `main.py` (Integrante 3) só precisa de um `except ErroAES` para mostrar a mensagem ao usuário, sem que o programa feche com erro (exigência do enunciado: nenhuma exceção sem tratamento).

---

## Codificação Base64 / Hex

### Linhas 33–43: `normalizar_codificacao`

```python
def normalizar_codificacao(codificacao):
    if isinstance(codificacao, str):
        valor = codificacao.strip().lower()
        if valor == "base64":
            return "Base64"
        if valor in ("hex", "hexadecimal"):
            return "Hex"
    raise ErroAES(
        f"Codificação inválida: {codificacao!r}. Use 'Base64' ou 'Hex'."
    )
```
| Linha | Explicação |
|---|---|
| `if isinstance(..., str)` | Só tenta interpretar se for texto. Se vier `None` ou um número, vai direto para o erro. |
| `.strip().lower()` | Remove espaços nas pontas e passa para minúsculas. Assim `"BASE64"`, `" base64 "` e `"Base64"` são tratados igual. |
| `return "Base64"` / `return "Hex"` | Devolve sempre a grafia oficial do enunciado. |
| `raise ErroAES(...)` | Se não for nenhuma das duas, lança um erro claro. `{codificacao!r}` mostra o valor entre aspas, para o usuário ver exatamente o que digitou. |

Por que normalizar: outros grupos podem escrever `"hex"` em minúsculas no JSON. Aceitar as variações aumenta a interoperabilidade.

### Linhas 46–51: `codificar`

```python
def codificar(dados, codificacao):
    codificacao = normalizar_codificacao(codificacao)
    if codificacao == "Base64":
        return base64.b64encode(dados).decode("ascii")
    return dados.hex()
```
| Linha | Explicação |
|---|---|
| 1ª | Garante que a codificação é válida e está na grafia padrão. |
| `b64encode(dados)` | Converte bytes para Base64. O resultado ainda é do tipo `bytes` (ex.: `b"SGVsbG8="`). |
| `.decode("ascii")` | Transforma esses bytes em `str` normal (`"SGVsbG8="`), que é o que vai no JSON. |
| `dados.hex()` | Método nativo do Python que gera o Hex em minúsculas, sem separadores (ex.: `"48656c6c6f"`), o mesmo formato do CyberChef. |

### Linhas 54–79: `decodificar`

```python
def decodificar(texto, codificacao, campo="dado"):
    codificacao = normalizar_codificacao(codificacao)
    if isinstance(texto, bytes):
        try:
            texto = texto.decode("ascii")
        except UnicodeDecodeError:
            raise ErroAES(f"O campo '{campo}' contém caracteres não-ASCII.")
    if not isinstance(texto, str):
        raise ErroAES(f"O campo '{campo}' deve ser um texto codificado.")

    limpo = "".join(texto.split())
    try:
        if codificacao == "Base64":
            return base64.b64decode(limpo, validate=True)
        return bytes.fromhex(limpo)
    except (binascii.Error, ValueError):
        raise ErroAES(...)
```
É o inverso de `codificar`: recebe texto Base64/Hex e devolve os bytes originais.

| Trecho | Explicação |
|---|---|
| `campo="dado"` | Parâmetro opcional usado só na mensagem de erro, para dizer **qual** campo está com problema (ex.: `"O campo 'iv' não é um Hex válido"`). |
| `if isinstance(texto, bytes)` | Aceita também `bytes`. É o caso da chave decifrada pelo RSA, que sai como bytes (`b"q83v..."`). Converte para `str`. |
| `except UnicodeDecodeError` | Base64 e Hex só usam caracteres ASCII. Se tiver outra coisa, os dados são inválidos. |
| `if not isinstance(texto, str)` | Recusa tipos errados, como números ou `None`. |
| `"".join(texto.split())` | `split()` quebra o texto em todo espaço, tab ou quebra de linha, e o `join` cola os pedaços sem nada. O efeito é remover todos os espaços em branco. Assim o código aceita Base64 com quebra de linha e Hex separado por espaços, como o CyberChef pode gerar. |
| `b64decode(limpo, validate=True)` | Decodifica o Base64. O `validate=True` faz recusar caracteres inválidos em vez de ignorá-los em silêncio. |
| `bytes.fromhex(limpo)` | Decodifica o Hex. Aceita maiúsculas e minúsculas. |
| `except (binascii.Error, ValueError)` | `binascii.Error` vem do Base64 inválido e `ValueError` do Hex inválido. Os dois viram um `ErroAES` com uma mensagem orientando o usuário. |

---

## Chave de sessão e IV

### Linhas 86–91: `gerar_chave_iv`

```python
def gerar_chave_iv():
    return os.urandom(TAMANHO_CHAVE), os.urandom(TAMANHO_IV)
```
Gera 32 bytes aleatórios para a chave e 16 para o IV e devolve os dois como uma tupla `(chave, iv)`.

`os.urandom` usa o gerador criptograficamente seguro do sistema operacional (CSPRNG, `/dev/urandom` no Linux). **Não se usa o módulo `random`**, porque ele é previsível: com algumas saídas dá para descobrir as próximas, o que entregaria a chave.

### Linhas 94–102: `codificar_chave`

```python
def codificar_chave(chave, codificacao):
    _validar_chave(chave)
    return codificar(chave, codificacao).encode("ascii")
```
Implementa o **passo 2** do enunciado: "Converter a chave e o IV conforme representações definidas pelo usuário". No passo 3, o que o RSA cifra é essa chave **já codificada**, não os 32 bytes crus.

| Linha | Explicação |
|---|---|
| `_validar_chave(chave)` | Garante que a chave tem exatamente 32 bytes. |
| `codificar(...)` | Transforma em texto Base64 (44 caracteres) ou Hex (64 caracteres). |
| `.encode("ascii")` | Volta para `bytes`, porque a função de RSA do Integrante 1 recebe bytes. |

Uso no fluxo de cifragem: `cifrar_chave_sessao(codificar_chave(chave, cod), ...)`.

### Linhas 105–116: `decodificar_chave`

```python
def decodificar_chave(chave_codificada, codificacao):
    chave = decodificar(chave_codificada, codificacao, campo="chave_sessao")
    if len(chave) != TAMANHO_CHAVE:
        raise ErroAES(...)
    return chave
```
O inverso: recebe o que saiu do RSA decifrado (a chave em Base64/Hex) e devolve os 32 bytes para usar no AES.

A checagem `len(chave) != 32` pega um erro comum de integração. Se outro programa cifrou a chave crua em vez da codificada, o resultado não terá 32 bytes, e o usuário recebe uma mensagem clara em vez de um erro confuso do AES.

### Linhas 119–130: `_validar_chave` e `_validar_iv`

```python
def _validar_chave(chave):
    if not isinstance(chave, (bytes, bytearray)) or len(chave) != TAMANHO_CHAVE:
        raise ErroAES(...)

def _validar_iv(iv):
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != TAMANHO_IV:
        raise ErroAES(...)
```
Funções auxiliares. O `_` no início do nome indica, por convenção, que são de uso interno do módulo. Elas conferem duas coisas:
1. O tipo é `bytes` ou `bytearray` (ambos representam bytes).
2. O tamanho é 32 para a chave e 16 para o IV.

Se a chave tiver 16 bytes, a biblioteca usaria AES-128 sem avisar. Essa checagem impede isso e garante AES-256.

---

## AES-256-CBC + PKCS#7

### Linhas 137–157: `cifrar_aes`

```python
def cifrar_aes(plaintext, chave, iv, codificacao):
    _validar_chave(chave)
    _validar_iv(iv)
    codificacao = normalizar_codificacao(codificacao)

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    elif not isinstance(plaintext, (bytes, bytearray)):
        raise ErroAES("O texto em claro deve ser str ou bytes.")

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    dados = padder.update(bytes(plaintext)) + padder.finalize()

    cifrador = Cipher(algorithms.AES(bytes(chave)), modes.CBC(bytes(iv))).encryptor()
    ciphertext = cifrador.update(dados) + cifrador.finalize()
    return codificar(ciphertext, codificacao)
```
| Trecho | Explicação |
|---|---|
| 3 primeiras linhas | Validam a chave, o IV e a codificação **antes** de fazer qualquer coisa. |
| `plaintext.encode("utf-8")` | Se o texto vier como `str`, converte para bytes em UTF-8, como o enunciado exige. O AES trabalha com bytes, não com letras. |
| `elif not isinstance(...)` | Recusa qualquer coisa que não seja texto ou bytes. |
| `padding.PKCS7(algorithms.AES.block_size)` | Cria o padding PKCS#7 para o tamanho do bloco do AES. `block_size` está em **bits** (128), que é o que a biblioteca espera. |
| `.padder()` | Pega o objeto que **adiciona** o padding. |
| `padder.update(...) + padder.finalize()` | `update` processa os dados e `finalize` acrescenta os bytes de padding no final. O resultado tem tamanho múltiplo de 16. |
| `Cipher(algorithms.AES(chave), modes.CBC(iv))` | Monta o cifrador AES em modo CBC com a chave e o IV. Como a chave tem 32 bytes, é AES-256. |
| `.encryptor()` | Pega o objeto que **cifra**. |
| `cifrador.update(dados) + cifrador.finalize()` | Cifra os dados. `finalize` encerra a operação. |
| `return codificar(...)` | Devolve o criptograma como texto Base64/Hex, pronto para ir no campo `mensagem_cifrada` do JSON. |

### Linhas 160–193: `decifrar_aes`

```python
def decifrar_aes(ciphertext_str, chave, iv, codificacao):
    _validar_chave(chave)
    _validar_iv(iv)
    ciphertext = decodificar(ciphertext_str, codificacao, campo="mensagem_cifrada")

    if len(ciphertext) == 0 or len(ciphertext) % TAMANHO_IV != 0:
        raise ErroAES(...)

    decifrador = Cipher(algorithms.AES(bytes(chave)), modes.CBC(bytes(iv))).decryptor()
    dados = decifrador.update(ciphertext) + decifrador.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        dados = unpadder.update(dados) + unpadder.finalize()
    except ValueError:
        raise ErroAES(...)

    try:
        return dados.decode("utf-8")
    except UnicodeDecodeError:
        raise ErroAES(...)
```
O caminho inverso da cifragem, na ordem contrária.

| Trecho | Explicação |
|---|---|
| `decodificar(...)` | Converte o texto Base64/Hex do JSON de volta para bytes. |
| `len(...) % 16 != 0` | Todo criptograma AES-CBC tem tamanho múltiplo de 16 e pelo menos 1 bloco. Se não tiver, os dados estão corrompidos ou a codificação está errada. Essa checagem evita um erro confuso da biblioteca. |
| `.decryptor()` | Agora o objeto **decifra**. Usa a mesma chave e o mesmo IV da cifragem. |
| `.unpadder()` | Objeto que **remove** o padding PKCS#7. |
| `except ValueError` | Se os últimos bytes não forem um padding válido, a biblioteca lança `ValueError`. Na prática, quase sempre isso significa **chave ou IV errados** (a decifragem gera lixo) ou dados adulterados. Vira um `ErroAES` com uma explicação para o usuário. |
| `dados.decode("utf-8")` | Converte os bytes de volta para texto, com os acentos. |
| `except UnicodeDecodeError` | Se o padding passou por acaso, mas os bytes não formam um texto UTF-8 válido, também é sinal de chave errada. |

---

# Parte 2: `envelope_builder.py`

### Linhas 1–25: docstring

Documenta o formato obrigatório do JSON (seção 4 do enunciado) e avisa que os erros são do tipo `ErroEnvelope`. Não executa nada.

### Linhas 27–35: importações

```python
import json

from aes_utils import (
    TAMANHO_IV,
    ErroAES,
    codificar,
    decodificar,
    normalizar_codificacao,
)
```
| Linha | Explicação |
|---|---|
| 27 | `json`: módulo padrão para ler e escrever JSON. |
| 29–35 | Reaproveita funções do `aes_utils.py`, assim a lógica de Base64/Hex fica num lugar só. Por isso os dois arquivos precisam estar na mesma pasta. |

### Linhas 38–57: constantes do protocolo

```python
PARAMETROS_FIXOS = {
    "algoritmo_simetrico": "AES-256-CBC",
    "padding_simetrico": "PKCS7",
    "algoritmo_chave": "RSA-OAEP",
    "algoritmo_assinatura": "RSA",
}

HASHES = ("SHA-256", "SHA-512")

CAMPOS_PARAMETROS = ("algoritmo_simetrico", "padding_simetrico", "algoritmo_chave",
                     "hash_oaep", "algoritmo_assinatura", "hash_assinatura", "codificacao")
CAMPOS_ENVELOPE = ("iv", "chave_sessao", "mensagem_cifrada", "assinatura")
```
| Constante | Explicação |
|---|---|
| `PARAMETROS_FIXOS` | Os 4 parâmetros que o enunciado define como **fixos** ("fixo em ..."). Um envelope com outro valor nesses campos não é compatível com o protocolo. |
| `HASHES` | Os dois hashes permitidos em `hash_oaep` e `hash_assinatura`. |
| `CAMPOS_PARAMETROS` | Os 7 campos obrigatórios de `parametros`, **na ordem do enunciado**. Essa ordem é usada para gerar o JSON igual ao modelo. |
| `CAMPOS_ENVELOPE` | Os 4 campos obrigatórios de `envelope`, também na ordem do enunciado. |

São tuplas (com parênteses) em vez de listas porque não devem mudar.

### Linhas 60–61: exceção própria

```python
class ErroEnvelope(Exception):
    """Erro na montagem, gravação, leitura ou validação do envelope JSON."""
```
O mesmo princípio do `ErroAES`: um único tipo de erro para tudo que der errado com o JSON.

---

## Normalização e validação dos parâmetros

### Linhas 68–77: `_normalizar_hash`

```python
def _normalizar_hash(valor, campo):
    if isinstance(valor, str):
        compacto = valor.strip().upper().replace("-", "").replace("_", "")
        for h in HASHES:
            if compacto == h.replace("-", ""):
                return h
    raise ErroEnvelope(...)
```
| Trecho | Explicação |
|---|---|
| `.strip().upper()` | Remove espaços e passa para maiúsculas. |
| `.replace("-", "").replace("_", "")` | Tira hífens e sublinhados. `"sha-256"`, `"SHA256"` e `"sha_256"` viram todos `"SHA256"`. |
| `for h in HASHES` | Compara com `"SHA256"` e `"SHA512"` (os oficiais sem hífen). |
| `return h` | Devolve a grafia oficial, com hífen: `"SHA-256"` ou `"SHA-512"`. |
| `raise` | Se nenhum bater (ex.: `"SHA-1"`), dá erro. O SHA-1 é inseguro e não é permitido. |

### Linhas 80–87: `_normalizar_fixo`

```python
def _normalizar_fixo(valor, campo):
    esperado = PARAMETROS_FIXOS[campo]
    if not isinstance(valor, str) or valor.strip().upper() != esperado.upper():
        raise ErroEnvelope(...)
    return esperado
```
Confere se um parâmetro fixo tem o valor certo, sem diferenciar maiúsculas de minúsculas, e devolve a grafia oficial. Exemplo: se o JSON disser `"algoritmo_simetrico": "AES-128-ECB"`, dá erro com a mensagem "Este protocolo exige 'AES-256-CBC'".

### Linhas 90–117: `validar_parametros`

```python
def validar_parametros(params):
    if not isinstance(params, dict):
        raise ErroEnvelope("O campo 'parametros' deve ser um objeto JSON.")

    faltando = [c for c in CAMPOS_PARAMETROS if c not in params]
    if faltando:
        raise ErroEnvelope("Campos ausentes em 'parametros': " + ", ".join(faltando))

    try:
        codificacao = normalizar_codificacao(params["codificacao"])
    except ErroAES as e:
        raise ErroEnvelope(f"Parâmetro 'codificacao' inválido: {e}")

    normalizado = { ...cada campo passa pela função de validação... }
    return normalizado
```
| Trecho | Explicação |
|---|---|
| `isinstance(params, dict)` | `parametros` precisa ser um objeto JSON (`{...}`), que no Python vira `dict`. |
| `faltando = [c for c in ... if c not in params]` | *List comprehension*: monta a lista dos campos obrigatórios que não estão no JSON. |
| `", ".join(faltando)` | Junta os nomes numa frase, ex.: `"hash_oaep, codificacao"`. O usuário vê **todos** os campos que faltam de uma vez. |
| `try / except ErroAES` | `normalizar_codificacao` vem do outro módulo e lança `ErroAES`. Aqui ele é convertido em `ErroEnvelope`, para que o módulo de envelope sempre lance o mesmo tipo de erro. |
| `normalizado = {...}` | Cria um **novo** dicionário com cada campo validado e na grafia oficial. Como os campos são escritos nessa ordem, o JSON gerado sai na ordem do enunciado (desde o Python 3.7, dicionários mantêm a ordem de inserção). |

### Linhas 120–127: `criar_parametros`

```python
def criar_parametros(hash_oaep="SHA-256", hash_assinatura="SHA-256", codificacao="Base64"):
    return validar_parametros({
        **PARAMETROS_FIXOS,
        "hash_oaep": hash_oaep,
        "hash_assinatura": hash_assinatura,
        "codificacao": codificacao,
    })
```
Atalho para o `main.py`. Ele só informa as 3 escolhas do usuário, e o resto é preenchido sozinho.
- Os valores depois do `=` são padrões: se nada for informado, usa SHA-256 e Base64.
- `**PARAMETROS_FIXOS` "desempacota" o dicionário dos fixos dentro do novo, o que equivale a copiar as 4 linhas fixas.
- No final passa por `validar_parametros`, então um hash inválido também dá erro aqui.

---

## Montagem e gravação

### Linhas 134–160: `montar_envelope`

```python
def montar_envelope(params, iv, chave_sessao, msg_cifrada, assinatura):
    params = validar_parametros(params)
    codificacao = params["codificacao"]

    if isinstance(iv, (bytes, bytearray)):
        if len(iv) != TAMANHO_IV:
            raise ErroEnvelope(...)
        iv = codificar(bytes(iv), codificacao)

    envelope = {
        "iv": iv,
        "chave_sessao": chave_sessao,
        "mensagem_cifrada": msg_cifrada,
        "assinatura": assinatura,
    }
    _validar_campos_envelope(envelope, codificacao)

    return {"parametros": params, "envelope": envelope}
```
| Trecho | Explicação |
|---|---|
| `validar_parametros(params)` | Valida e normaliza os parâmetros antes de montar. |
| `if isinstance(iv, bytes...)` | O IV sai do `gerar_chave_iv()` como bytes. Nesse caso a função confere se tem 16 bytes e o converte para Base64/Hex. Se já vier como texto, usa como está. |
| `envelope = {...}` | Os outros três campos já chegam codificados como texto: a chave de sessão e a assinatura vêm do RSA (Integrante 1) e a mensagem cifrada vem do `cifrar_aes`. |
| `_validar_campos_envelope(...)` | Confere se cada campo é texto válido na codificação escolhida. Isso pega o erro de, por exemplo, misturar Base64 num envelope marcado como Hex. |
| `return {...}` | Devolve o dicionário completo com a estrutura exata do enunciado. |

### Linhas 163–178: `salvar_envelope`

```python
def salvar_envelope(envelope, caminho_json):
    if not isinstance(envelope, dict) or "parametros" not in envelope or "envelope" not in envelope:
        raise ErroEnvelope(...)
    try:
        with open(caminho_json, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except IsADirectoryError: ...
    except PermissionError: ...
    except FileNotFoundError: ...
    except OSError as e: ...
```
| Trecho | Explicação |
|---|---|
| 1º `if` | Garante que o que está sendo salvo é um envelope de verdade. |
| `with open(..., "w", encoding="utf-8")` | Abre o arquivo para escrita (`"w"`), em UTF-8. O `with` fecha o arquivo sozinho no final, mesmo se der erro. |
| `json.dump(..., indent=2)` | Escreve o JSON com 2 espaços de recuo, legível para humanos. |
| `ensure_ascii=False` | Grava os acentos como são, em vez de `ç`. Os campos cifrados não têm acentos, mas isso deixa o arquivo mais limpo. |
| `f.write("\n")` | Quebra de linha no final do arquivo (boa prática em arquivos de texto). |
| `IsADirectoryError` | O usuário informou uma pasta em vez de um arquivo. |
| `PermissionError` | Sem permissão para escrever ali. |
| `FileNotFoundError` | A pasta de destino não existe (ex.: `pasta_inexistente/envelope.json`). |
| `OSError` | Qualquer outro erro de disco (disco cheio etc.). Vem por último porque é a "mãe" dos três anteriores: se viesse primeiro, capturaria tudo e as mensagens específicas nunca apareceriam. |

---

## Leitura e validação

### Linhas 185–203: `_validar_campos_envelope`

```python
def _validar_campos_envelope(envelope, codificacao):
    faltando = [c for c in CAMPOS_ENVELOPE if c not in envelope]
    if faltando:
        raise ErroEnvelope(...)

    for campo in CAMPOS_ENVELOPE:
        valor = envelope[campo]
        if not isinstance(valor, str) or not valor.strip():
            raise ErroEnvelope(...)
        try:
            dados = decodificar(valor, codificacao, campo=campo)
        except ErroAES as e:
            raise ErroEnvelope(str(e))
        if campo == "iv" and len(dados) != TAMANHO_IV:
            raise ErroEnvelope(...)
```
Usada tanto na montagem quanto na leitura. Para cada um dos 4 campos:
1. **Existe?** Se não, lista os que faltam.
2. **É texto não vazio?** `not valor.strip()` pega `""` e `"   "`.
3. **É Base64/Hex válido?** Tenta decodificar. Se falhar, repassa a mensagem do `ErroAES` como `ErroEnvelope`.
4. **O IV tem 16 bytes?** O único campo com tamanho fixo e conhecido. A chave de sessão e a assinatura dependem do tamanho da chave RSA, e a mensagem depende do texto, então não dá para fixar o tamanho deles.

### Linhas 206–219: `validar_envelope`

```python
def validar_envelope(dados):
    if not isinstance(dados, dict):
        raise ErroEnvelope(...)
    for bloco in ("parametros", "envelope"):
        if bloco not in dados:
            raise ErroEnvelope(...)
    if not isinstance(dados["envelope"], dict):
        raise ErroEnvelope(...)

    params = validar_parametros(dados["parametros"])
    envelope = {c: dados["envelope"][c] for c in CAMPOS_ENVELOPE if c in dados["envelope"]}
    _validar_campos_envelope(envelope, params["codificacao"])
    return {"parametros": params, "envelope": envelope}
```
| Trecho | Explicação |
|---|---|
| 1º `if` | O JSON precisa ser um objeto `{...}`. Um arquivo com `[1, 2, 3]` é JSON válido, mas não é um envelope. |
| `for bloco in ...` | Confere se os dois blocos principais existem. |
| `isinstance(dados["envelope"], dict)` | O bloco `envelope` precisa ser um objeto. |
| `validar_parametros(...)` | Valida e normaliza os parâmetros. A codificação validada é usada no passo seguinte. |
| `envelope = {c: ... for c in ...}` | *Dict comprehension*: copia só os 4 campos conhecidos, na ordem padrão, e ignora campos extras que outro grupo possa ter adicionado. |
| `_validar_campos_envelope(...)` | Valida os 4 campos. |

### Linhas 222–247: `ler_envelope`

```python
def ler_envelope(caminho_json):
    try:
        with open(caminho_json, "r", encoding="utf-8-sig") as f:
            dados = json.load(f)
    except FileNotFoundError: ...
    except IsADirectoryError: ...
    except PermissionError: ...
    except UnicodeDecodeError: ...
    except json.JSONDecodeError as e:
        raise ErroEnvelope(f"JSON malformado em '{caminho_json}' (linha {e.lineno}, coluna {e.colno}): {e.msg}.")
    except OSError as e: ...

    return validar_envelope(dados)
```
A função que o `main.py` chama para abrir um envelope.

| Trecho | Explicação |
|---|---|
| `open(..., "r", encoding="utf-8-sig")` | Abre para leitura. O `utf-8-sig` aceita UTF-8 normal e também UTF-8 com BOM, uma marca invisível que o Bloco de Notas do Windows coloca no início do arquivo. Sem isso, um envelope criado no Windows por outro grupo daria erro. |
| `json.load(f)` | Lê o arquivo e converte o JSON em dicionário Python. |
| `FileNotFoundError` | O arquivo não existe. Esse é um dos erros que o enunciado cita. |
| `IsADirectoryError` / `PermissionError` | O caminho é uma pasta, ou não há permissão de leitura. |
| `UnicodeDecodeError` | O arquivo não é texto. Por exemplo, o usuário escolheu uma imagem por engano. |
| `json.JSONDecodeError` | O JSON está malformado (falta uma vírgula, uma chave etc.). Esse também é citado no enunciado. A mensagem mostra a **linha e a coluna** do problema para o usuário corrigir. |
| `OSError` | Qualquer outro erro de leitura. Fica por último pelo mesmo motivo do `salvar_envelope`. |
| `return validar_envelope(dados)` | Com o arquivo lido, valida todo o conteúdo e devolve o envelope normalizado. Os campos continuam como texto codificado. O `main.py` usa `decodificar()` quando precisa dos bytes. |

---

# Como os módulos se encaixam no programa

### Criar o envelope (Encrypt-then-Sign)

```python
chave, iv = gerar_chave_iv()                                   # Integrante 2
msg = cifrar_aes(texto, chave, iv, cod)                        # Integrante 2
chave_cif = cifrar_chave_sessao(codificar_chave(chave, cod),   # Integrante 1 (+ 2)
                                pub_dest, hash_oaep, cod)
assinatura = assinar(msg, priv_rem, hash_assinatura)           # Integrante 1
params = criar_parametros(hash_oaep, hash_assinatura, cod)     # Integrante 2
env = montar_envelope(params, iv, chave_cif, msg, assinatura)  # Integrante 2
salvar_envelope(env, "envelope.json")                          # Integrante 2
```

### Abrir o envelope

```python
env = ler_envelope("envelope.json")                            # Integrante 2
p, e = env["parametros"], env["envelope"]
verificar_assinatura(e["mensagem_cifrada"], e["assinatura"],   # Integrante 1
                     pub_rem, p["hash_assinatura"])            # se inválida -> para aqui
chave = decodificar_chave(                                     # Integrante 2
    decifrar_chave_sessao(e["chave_sessao"], priv_dest,        # Integrante 1
                          p["hash_oaep"], p["codificacao"]),
    p["codificacao"])
iv = decodificar(e["iv"], p["codificacao"], campo="iv")        # Integrante 2
texto = decifrar_aes(e["mensagem_cifrada"], chave, iv,         # Integrante 2
                     p["codificacao"])
```

Em qualquer passo, os erros chegam como `ErroAES` ou `ErroEnvelope`, cada um com uma mensagem pronta para mostrar ao usuário.
