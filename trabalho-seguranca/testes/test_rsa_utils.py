import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rsa_utils import (
    cifrar_chave_sessao,
    decifrar_chave_sessao,
    assinar,
    verificar_assinatura
)


def test_rsa_oaep():
    chave_original = b"12345678901234567890123456789012"

    chave_cifrada = cifrar_chave_sessao(
        chave_original,
        "chaves/destinatario_public.pem",
        "SHA-256",
        "Base64"
    )

    chave_recuperada = decifrar_chave_sessao(
        chave_cifrada,
        "chaves/destinatario_private.pem",
        "SHA-256",
        "Base64"
    )

    assert chave_original == chave_recuperada


def test_assinatura_valida():
    ciphertext = "mensagem-cifrada-de-teste"

    assinatura = assinar(
        ciphertext,
        "chaves/remetente_private.pem",
        "SHA-256"
    )

    resultado = verificar_assinatura(
        ciphertext,
        assinatura,
        "chaves/remetente_public.pem",
        "SHA-256"
    )

    assert resultado is True


def test_assinatura_invalida():
    ciphertext = "mensagem-cifrada-de-teste"

    assinatura = assinar(
        ciphertext,
        "chaves/remetente_private.pem",
        "SHA-256"
    )

    resultado = verificar_assinatura(
        "mensagem-alterada",
        assinatura,
        "chaves/remetente_public.pem",
        "SHA-256"
    )

    assert resultado is False


if __name__ == "__main__":
    test_rsa_oaep()
    test_assinatura_valida()
    test_assinatura_invalida()

    print("Todos os testes de RSA passaram!")