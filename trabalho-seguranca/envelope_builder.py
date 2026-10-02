"""
envelope_builder.py — Montagem, gravação e leitura do envelope JSON (Integrante 2).

Estrutura obrigatória (seção 4 do enunciado):

{
  "parametros": {
    "algoritmo_simetrico": "AES-256-CBC",
    "padding_simetrico": "PKCS7",
    "algoritmo_chave": "RSA-OAEP",
    "hash_oaep": "SHA-256" | "SHA-512",
    "algoritmo_assinatura": "RSA",
    "hash_assinatura": "SHA-256" | "SHA-512",
    "codificacao": "Base64" | "Hex"
  },
  "envelope": {
    "iv": "...",
    "chave_sessao": "...",
    "mensagem_cifrada": "...",
    "assinatura": "..."
  }
}

Todas as falhas são sinalizadas com ErroEnvelope (mensagem em português).
"""

import json

from aes_utils import (
    TAMANHO_IV,
    ErroAES,
    codificar,
    decodificar,
    normalizar_codificacao,
)

# Valores fixos exigidos pelo protocolo
PARAMETROS_FIXOS = {
    "algoritmo_simetrico": "AES-256-CBC",
    "padding_simetrico": "PKCS7",
    "algoritmo_chave": "RSA-OAEP",
    "algoritmo_assinatura": "RSA",
}

HASHES = ("SHA-256", "SHA-512")

# Ordem dos campos no JSON gerado (igual ao enunciado)
CAMPOS_PARAMETROS = (
    "algoritmo_simetrico",
    "padding_simetrico",
    "algoritmo_chave",
    "hash_oaep",
    "algoritmo_assinatura",
    "hash_assinatura",
    "codificacao",
)
CAMPOS_ENVELOPE = ("iv", "chave_sessao", "mensagem_cifrada", "assinatura")


class ErroEnvelope(Exception):
    """Erro na montagem, gravação, leitura ou validação do envelope JSON."""


# ---------------------------------------------------------------------------
# Normalização / validação dos parâmetros
# ---------------------------------------------------------------------------

def _normalizar_hash(valor, campo):
    """Aceita 'SHA-256', 'sha256', 'SHA256'... e devolve 'SHA-256'/'SHA-512'."""
    if isinstance(valor, str):
        compacto = valor.strip().upper().replace("-", "").replace("_", "")
        for h in HASHES:
            if compacto == h.replace("-", ""):
                return h
    raise ErroEnvelope(
        f"Parâmetro '{campo}' inválido: {valor!r}. Use 'SHA-256' ou 'SHA-512'."
    )


def _normalizar_fixo(valor, campo):
    esperado = PARAMETROS_FIXOS[campo]
    if not isinstance(valor, str) or valor.strip().upper() != esperado.upper():
        raise ErroEnvelope(
            f"Parâmetro '{campo}' não suportado: {valor!r}. "
            f"Este protocolo exige {esperado!r}."
        )
    return esperado


def validar_parametros(params):
    """Valida o bloco 'parametros' e devolve uma cópia normalizada,
    com os valores na grafia canônica e os campos na ordem do enunciado.
    """
    if not isinstance(params, dict):
        raise ErroEnvelope("O campo 'parametros' deve ser um objeto JSON.")

    faltando = [c for c in CAMPOS_PARAMETROS if c not in params]
    if faltando:
        raise ErroEnvelope(
            "Campos ausentes em 'parametros': " + ", ".join(faltando)
        )

    try:
        codificacao = normalizar_codificacao(params["codificacao"])
    except ErroAES as e:
        raise ErroEnvelope(f"Parâmetro 'codificacao' inválido: {e}")

    normalizado = {
        "algoritmo_simetrico": _normalizar_fixo(params["algoritmo_simetrico"], "algoritmo_simetrico"),
        "padding_simetrico": _normalizar_fixo(params["padding_simetrico"], "padding_simetrico"),
        "algoritmo_chave": _normalizar_fixo(params["algoritmo_chave"], "algoritmo_chave"),
        "hash_oaep": _normalizar_hash(params["hash_oaep"], "hash_oaep"),
        "algoritmo_assinatura": _normalizar_fixo(params["algoritmo_assinatura"], "algoritmo_assinatura"),
        "hash_assinatura": _normalizar_hash(params["hash_assinatura"], "hash_assinatura"),
        "codificacao": codificacao,
    }
    return normalizado


def criar_parametros(hash_oaep="SHA-256", hash_assinatura="SHA-256", codificacao="Base64"):
    """Atalho para montar o bloco 'parametros' a partir das escolhas do usuário."""
    return validar_parametros({
        **PARAMETROS_FIXOS,
        "hash_oaep": hash_oaep,
        "hash_assinatura": hash_assinatura,
        "codificacao": codificacao,
    })


# ---------------------------------------------------------------------------
# Montagem e gravação
# ---------------------------------------------------------------------------

def montar_envelope(params, iv, chave_sessao, msg_cifrada, assinatura):
    """Monta o dicionário do envelope no formato exato do enunciado.

    params:       dict de parâmetros (pode vir de criar_parametros()).
    iv:           bytes (16) — será codificado conforme params['codificacao'];
                  também aceita str já codificada.
    chave_sessao: str — chave de sessão cifrada com RSA-OAEP, já codificada.
    msg_cifrada:  str — criptograma AES, já codificado.
    assinatura:   str — assinatura do criptograma, já codificada.
    """
    params = validar_parametros(params)
    codificacao = params["codificacao"]

    if isinstance(iv, (bytes, bytearray)):
        if len(iv) != TAMANHO_IV:
            raise ErroEnvelope(f"IV inválido: esperado {TAMANHO_IV} bytes, recebido {len(iv)}.")
        iv = codificar(bytes(iv), codificacao)

    envelope = {
        "iv": iv,
        "chave_sessao": chave_sessao,
        "mensagem_cifrada": msg_cifrada,
        "assinatura": assinatura,
    }
    _validar_campos_envelope(envelope, codificacao)

    return {"parametros": params, "envelope": envelope}


def salvar_envelope(envelope, caminho_json):
    """Grava o envelope em disco como JSON UTF-8 indentado."""
    if not isinstance(envelope, dict) or "parametros" not in envelope or "envelope" not in envelope:
        raise ErroEnvelope("Envelope inválido: use o dicionário retornado por montar_envelope().")
    try:
        with open(caminho_json, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except IsADirectoryError:
        raise ErroEnvelope(f"'{caminho_json}' é um diretório, não um arquivo.")
    except PermissionError:
        raise ErroEnvelope(f"Sem permissão para gravar em '{caminho_json}'.")
    except FileNotFoundError:
        raise ErroEnvelope(f"Diretório de destino inexistente para '{caminho_json}'.")
    except OSError as e:
        raise ErroEnvelope(f"Não foi possível gravar '{caminho_json}': {e.strerror or e}")


# ---------------------------------------------------------------------------
# Leitura e validação
# ---------------------------------------------------------------------------

def _validar_campos_envelope(envelope, codificacao):
    """Confere presença, tipo e codificação de cada campo do bloco 'envelope'."""
    faltando = [c for c in CAMPOS_ENVELOPE if c not in envelope]
    if faltando:
        raise ErroEnvelope("Campos ausentes em 'envelope': " + ", ".join(faltando))

    for campo in CAMPOS_ENVELOPE:
        valor = envelope[campo]
        if not isinstance(valor, str) or not valor.strip():
            raise ErroEnvelope(f"O campo 'envelope.{campo}' deve ser um texto não vazio.")
        try:
            dados = decodificar(valor, codificacao, campo=campo)
        except ErroAES as e:
            raise ErroEnvelope(str(e))
        if campo == "iv" and len(dados) != TAMANHO_IV:
            raise ErroEnvelope(
                f"O IV deve ter {TAMANHO_IV} bytes (128 bits); "
                f"o envelope contém {len(dados)} bytes."
            )


def validar_envelope(dados):
    """Valida um envelope já carregado (dict) e devolve uma versão normalizada."""
    if not isinstance(dados, dict):
        raise ErroEnvelope("O JSON deve ser um objeto com os campos 'parametros' e 'envelope'.")
    for bloco in ("parametros", "envelope"):
        if bloco not in dados:
            raise ErroEnvelope(f"Campo obrigatório '{bloco}' ausente no JSON.")
    if not isinstance(dados["envelope"], dict):
        raise ErroEnvelope("O campo 'envelope' deve ser um objeto JSON.")

    params = validar_parametros(dados["parametros"])
    envelope = {c: dados["envelope"][c] for c in CAMPOS_ENVELOPE if c in dados["envelope"]}
    _validar_campos_envelope(envelope, params["codificacao"])
    return {"parametros": params, "envelope": envelope}


def ler_envelope(caminho_json):
    """Lê o arquivo JSON do envelope, valida todos os campos obrigatórios e
    devolve o dicionário normalizado ({'parametros': ..., 'envelope': ...}).

    Os campos do 'envelope' continuam codificados (texto); use
    aes_utils.decodificar() quando precisar dos bytes.
    """
    try:
        with open(caminho_json, "r", encoding="utf-8-sig") as f:
            dados = json.load(f)
    except FileNotFoundError:
        raise ErroEnvelope(f"Arquivo de envelope não encontrado: '{caminho_json}'.")
    except IsADirectoryError:
        raise ErroEnvelope(f"'{caminho_json}' é um diretório, não um arquivo.")
    except PermissionError:
        raise ErroEnvelope(f"Sem permissão para ler '{caminho_json}'.")
    except UnicodeDecodeError:
        raise ErroEnvelope(f"'{caminho_json}' não é um arquivo de texto UTF-8.")
    except json.JSONDecodeError as e:
        raise ErroEnvelope(
            f"JSON malformado em '{caminho_json}' (linha {e.lineno}, coluna {e.colno}): {e.msg}."
        )
    except OSError as e:
        raise ErroEnvelope(f"Não foi possível ler '{caminho_json}': {e.strerror or e}")

    return validar_envelope(dados)
