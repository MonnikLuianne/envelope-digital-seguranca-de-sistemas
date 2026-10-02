"""
aes_utils.py — Criptografia simétrica (Integrante 2).

AES-256 em modo CBC com padding PKCS#7, chave de 32 bytes e IV de 16 bytes,
além das funções de codificação textual (Base64 / Hex) usadas por todo o
envelope.

Todas as falhas são sinalizadas com ErroAES (mensagem em português), para que
a camada de interface possa tratá-las sem exceções inesperadas.
"""

import base64
import binascii
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAMANHO_CHAVE = 32  # AES-256 -> 256 bits
TAMANHO_IV = 16     # bloco do AES -> 128 bits

CODIFICACOES = ("Base64", "Hex")


class ErroAES(Exception):
    """Erro na cifragem/decifragem simétrica ou na codificação dos dados."""


# ---------------------------------------------------------------------------
# Codificação Base64 / Hex
# ---------------------------------------------------------------------------

def normalizar_codificacao(codificacao):
    """Converte 'base64', 'BASE64', 'hex', 'HEX'... para 'Base64' ou 'Hex'."""
    if isinstance(codificacao, str):
        valor = codificacao.strip().lower()
        if valor == "base64":
            return "Base64"
        if valor in ("hex", "hexadecimal"):
            return "Hex"
    raise ErroAES(
        f"Codificação inválida: {codificacao!r}. Use 'Base64' ou 'Hex'."
    )


def codificar(dados, codificacao):
    """Codifica bytes em texto Base64 ou Hex (minúsculo, sem separadores)."""
    codificacao = normalizar_codificacao(codificacao)
    if codificacao == "Base64":
        return base64.b64encode(dados).decode("ascii")
    return dados.hex()


def decodificar(texto, codificacao, campo="dado"):
    """Decodifica texto Base64 ou Hex para bytes.

    `campo` só é usado para deixar a mensagem de erro mais clara.
    """
    codificacao = normalizar_codificacao(codificacao)
    if isinstance(texto, bytes):
        try:
            texto = texto.decode("ascii")
        except UnicodeDecodeError:
            raise ErroAES(f"O campo '{campo}' contém caracteres não-ASCII.")
    if not isinstance(texto, str):
        raise ErroAES(f"O campo '{campo}' deve ser um texto codificado.")

    # Tolera quebras de linha/espaços (ex.: Base64 com quebra a cada 64 col.
    # ou Hex separado por espaços, como o CyberChef pode gerar).
    limpo = "".join(texto.split())
    try:
        if codificacao == "Base64":
            return base64.b64decode(limpo, validate=True)
        return bytes.fromhex(limpo)
    except (binascii.Error, ValueError):
        raise ErroAES(
            f"O campo '{campo}' não é um {codificacao} válido. "
            f"Verifique se a codificação do envelope está correta."
        )


# ---------------------------------------------------------------------------
# Chave de sessão e IV
# ---------------------------------------------------------------------------

def gerar_chave_iv():
    """Gera aleatoriamente (CSPRNG) uma chave AES-256 e um IV de 128 bits.

    Retorna (chave, iv) como bytes de 32 e 16 posições.
    """
    return os.urandom(TAMANHO_CHAVE), os.urandom(TAMANHO_IV)


def codificar_chave(chave, codificacao):
    """Passo 2 da especificação: representa a chave na codificação escolhida.

    Retorna os bytes ASCII da chave codificada — é ISSO que deve ser cifrado
    com RSA-OAEP (a especificação cifra a chave *codificada*, não os 32 bytes
    crus). Ex.: em Base64 são 44 bytes; em Hex, 64 bytes.
    """
    _validar_chave(chave)
    return codificar(chave, codificacao).encode("ascii")


def decodificar_chave(chave_codificada, codificacao):
    """Inverso de codificar_chave: recebe a saída do RSA-OAEP decifrado
    (bytes ou str com a chave em Base64/Hex) e devolve os 32 bytes da chave.
    """
    chave = decodificar(chave_codificada, codificacao, campo="chave_sessao")
    if len(chave) != TAMANHO_CHAVE:
        raise ErroAES(
            f"A chave de sessão decifrada tem {len(chave)} bytes; esperado "
            f"{TAMANHO_CHAVE} (AES-256). Confira a codificação ou a chave "
            f"privada do destinatário."
        )
    return chave


def _validar_chave(chave):
    if not isinstance(chave, (bytes, bytearray)) or len(chave) != TAMANHO_CHAVE:
        raise ErroAES(
            f"Chave AES inválida: são necessários {TAMANHO_CHAVE} bytes (256 bits)."
        )


def _validar_iv(iv):
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != TAMANHO_IV:
        raise ErroAES(
            f"IV inválido: são necessários {TAMANHO_IV} bytes (128 bits)."
        )


# ---------------------------------------------------------------------------
# AES-256-CBC + PKCS#7
# ---------------------------------------------------------------------------

def cifrar_aes(plaintext, chave, iv, codificacao):
    """Cifra o texto em claro com AES-256-CBC/PKCS#7.

    plaintext: str (será codificado em UTF-8) ou bytes.
    Retorna o criptograma codificado em Base64 ou Hex.
    """
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


def decifrar_aes(ciphertext_str, chave, iv, codificacao):
    """Decifra um criptograma AES-256-CBC/PKCS#7 codificado em Base64 ou Hex.

    Retorna o texto original (str UTF-8).
    """
    _validar_chave(chave)
    _validar_iv(iv)
    ciphertext = decodificar(ciphertext_str, codificacao, campo="mensagem_cifrada")

    if len(ciphertext) == 0 or len(ciphertext) % TAMANHO_IV != 0:
        raise ErroAES(
            "O criptograma não tem tamanho múltiplo de 16 bytes: "
            "os dados estão corrompidos ou a codificação está errada."
        )

    decifrador = Cipher(algorithms.AES(bytes(chave)), modes.CBC(bytes(iv))).decryptor()
    dados = decifrador.update(ciphertext) + decifrador.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        dados = unpadder.update(dados) + unpadder.finalize()
    except ValueError:
        raise ErroAES(
            "Padding PKCS#7 inválido: chave de sessão ou IV incorretos, "
            "ou mensagem cifrada corrompida."
        )

    try:
        return dados.decode("utf-8")
    except UnicodeDecodeError:
        raise ErroAES(
            "A mensagem decifrada não é um texto UTF-8 válido: "
            "chave de sessão ou IV provavelmente incorretos."
        )
