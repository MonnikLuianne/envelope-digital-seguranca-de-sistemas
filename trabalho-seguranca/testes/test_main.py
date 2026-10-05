import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import criar_envelope, abrir_envelope, executar, IntegridadeViolada

MENSAGEM = "Mensagem de teste com acentuação: ação, maçã, pão"


def criar(pasta, codificacao="Base64", hash_func="SHA-256"):
    entrada = os.path.join(pasta, "mensagem.txt")
    envelope = os.path.join(pasta, "envelope.json")

    with open(entrada, "w", encoding="utf-8") as arquivo:
        arquivo.write(MENSAGEM + "\n")  # o Enter final deve ser ignorado

    criar_envelope(entrada, "chaves/destinatario_public.pem",
                   "chaves/remetente_private.pem", envelope,
                   hash_func, hash_func, codificacao)
    return envelope


def test_ida_e_volta():
    for codificacao, hash_func in (("Base64", "SHA-256"), ("Hex", "SHA-512")):
        with tempfile.TemporaryDirectory() as pasta:
            envelope = criar(pasta, codificacao, hash_func)
            saida = os.path.join(pasta, "decifrada.txt")

            texto = abrir_envelope(envelope, "chaves/destinatario_private.pem",
                                   "chaves/remetente_public.pem", saida)

            assert texto == MENSAGEM


def test_json_segue_o_padrao_do_enunciado():
    with tempfile.TemporaryDirectory() as pasta:
        envelope = criar(pasta, "Hex", "SHA-512")

        with open(envelope, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)

        assert list(dados) == ["parametros", "envelope"]
        assert dados["parametros"] == {
            "algoritmo_simetrico": "AES-256-CBC",
            "padding_simetrico": "PKCS7",
            "algoritmo_chave": "RSA-OAEP",
            "hash_oaep": "SHA-512",
            "algoritmo_assinatura": "RSA",
            "hash_assinatura": "SHA-512",
            "codificacao": "Hex",
        }
        assert list(dados["envelope"]) == ["iv", "chave_sessao",
                                           "mensagem_cifrada", "assinatura"]

        for campo, valor in dados["envelope"].items():
            assert valor and valor == valor.strip(), f"campo '{campo}' inválido"
            bytes.fromhex(valor)  # todos os campos em Hex válido

        assert len(bytes.fromhex(dados["envelope"]["iv"])) == 16


def test_assinatura_invalida_interrompe():
    with tempfile.TemporaryDirectory() as pasta:
        envelope = criar(pasta)

        with open(envelope, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
        cifrada = dados["envelope"]["mensagem_cifrada"]
        trocado = "B" if cifrada[0] == "A" else "A"
        dados["envelope"]["mensagem_cifrada"] = trocado + cifrada[1:]
        with open(envelope, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo)

        saida = os.path.join(pasta, "decifrada.txt")
        try:
            abrir_envelope(envelope, "chaves/destinatario_private.pem",
                           "chaves/remetente_public.pem", saida)
            assert False, "deveria ter detectado a assinatura inválida"
        except IntegridadeViolada:
            pass

        assert not os.path.exists(saida)


def test_erros_nao_derrubam_o_programa():
    with tempfile.TemporaryDirectory() as pasta:
        malformado = os.path.join(pasta, "ruim.json")
        with open(malformado, "w", encoding="utf-8") as arquivo:
            arquivo.write('{"parametros": ')

        saida = os.path.join(pasta, "x.txt")
        casos = [
            # arquivo inexistente
            lambda: abrir_envelope("nao_existe.json", "chaves/destinatario_private.pem",
                                   "chaves/remetente_public.pem", saida),
            # JSON malformado
            lambda: abrir_envelope(malformado, "chaves/destinatario_private.pem",
                                   "chaves/remetente_public.pem", saida),
            # chaves trocadas: pública no lugar da privada
            lambda: abrir_envelope(criar(pasta), "chaves/destinatario_public.pem",
                                   "chaves/remetente_public.pem", saida),
            # chave privada de outra pessoa
            lambda: abrir_envelope(criar(pasta), "chaves/remetente_private.pem",
                                   "chaves/remetente_public.pem", saida),
        ]

        for caso in casos:
            executar(caso)  # não pode lançar exceção


if __name__ == "__main__":
    test_ida_e_volta()
    test_json_segue_o_padrao_do_enunciado()
    test_assinatura_invalida_interrompe()
    test_erros_nao_derrubam_o_programa()

    print("Todos os testes do main.py passaram!")
