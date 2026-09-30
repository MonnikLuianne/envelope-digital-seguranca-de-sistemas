"""
Stubs TEMPORÁRIOS das funções do Integrante 2 (aes_utils.py + envelope_builder.py).

O main.py só usa este arquivo enquanto aes_utils.py / envelope_builder.py não
expuserem as funções do contrato abaixo. Quando o Integrante 2 entregar os
módulos, o main.py passa a usá-los automaticamente e este arquivo pode ser
removido.

Em vez de retornos fixos, os stubs fazem a operação mínima de verdade, para
que o fluxo completo (e a interoperabilidade com o CyberChef) possa ser
testado de ponta a ponta.

Contrato assumido pelo main.py (divisao_trabalho_seguranca.pdf):
    gerar_chave_iv() -> (bytes, bytes)                      chave de 32 bytes, IV de 16
    cifrar_aes(plaintext, chave, iv, codificacao) -> str    plaintext: str (UTF-8)
    decifrar_aes(ciphertext_str, chave, iv, codificacao) -> str
    montar_envelope(params, iv, chave_sessao, msg_cifrada, assinatura) -> dict
        params: dict "parametros"; demais argumentos: textos já codificados
    ler_envelope(caminho_json) -> dict                      JSON completo, validado
"""

import base64
import json
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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


def _codificar(dados, codificacao):
    if codificacao.upper() == "BASE64":
        return base64.b64encode(dados).decode("ascii")

    if codificacao.upper() == "HEX":
        return dados.hex()

    raise ValueError("Codificação não suportada. Use Base64 ou Hex.")


def _decodificar(texto, codificacao):
    if codificacao.upper() == "BASE64":
        return base64.b64decode(texto, validate=True)

    if codificacao.upper() == "HEX":
        return bytes.fromhex(texto)

    raise ValueError("Codificação não suportada. Use Base64 ou Hex.")


def gerar_chave_iv():
    return os.urandom(32), os.urandom(16)


def cifrar_aes(plaintext, chave, iv, codificacao):
    preenchedor = padding.PKCS7(128).padder()
    dados = preenchedor.update(plaintext.encode("utf-8")) + preenchedor.finalize()

    cifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    criptograma = cifrador.update(dados) + cifrador.finalize()

    return _codificar(criptograma, codificacao)


def decifrar_aes(ciphertext_str, chave, iv, codificacao):
    decifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
    dados = decifrador.update(_decodificar(ciphertext_str, codificacao))
    dados += decifrador.finalize()

    removedor = padding.PKCS7(128).unpadder()
    texto = removedor.update(dados) + removedor.finalize()

    return texto.decode("utf-8")


def montar_envelope(params, iv, chave_sessao, msg_cifrada, assinatura):
    return {
        "parametros": dict(params),
        "envelope": {
            "iv": iv,
            "chave_sessao": chave_sessao,
            "mensagem_cifrada": msg_cifrada,
            "assinatura": assinatura,
        },
    }


def ler_envelope(caminho_json):
    with open(caminho_json, "r", encoding="utf-8") as arquivo:
        dados = json.load(arquivo)

    if not isinstance(dados, dict):
        raise ValueError("O JSON deve ser um objeto com 'parametros' e 'envelope'.")

    for secao, campos in (("parametros", CAMPOS_PARAMETROS),
                          ("envelope", CAMPOS_ENVELOPE)):
        if not isinstance(dados.get(secao), dict):
            raise ValueError(f"Seção obrigatória ausente: '{secao}'.")

        faltando = [campo for campo in campos if campo not in dados[secao]]
        if faltando:
            raise ValueError(
                f"Campo(s) ausente(s) em '{secao}': {', '.join(faltando)}."
            )

    return dados
