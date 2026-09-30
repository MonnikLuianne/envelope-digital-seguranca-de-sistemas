"""
Testes de integração do main.py (Integrante 3): fluxo completo, compatibilidade
com as receitas do CyberChef e tratamento de erros.

Executar a partir de trabalho-seguranca/:
    python -m pytest testes/test_main.py      ou      python testes/test_main.py
"""

import base64
import contextlib
import io
import json
import os
import sys
import tempfile

DIR_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DIR_PROJETO)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as preenchimento
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import main


CHAVES = os.path.join(DIR_PROJETO, "chaves")
PUB_DEST = os.path.join(CHAVES, "destinatario_public.pem")
PRIV_DEST = os.path.join(CHAVES, "destinatario_private.pem")
PUB_REM = os.path.join(CHAVES, "remetente_public.pem")
PRIV_REM = os.path.join(CHAVES, "remetente_private.pem")

MENSAGEM = "Mensagem de teste com acentuação: ação, maçã, pão - 100% UTF-8 ✓"

COMBINACOES = [
    ("SHA-256", "SHA-256", "Base64"),
    ("SHA-512", "SHA-512", "Base64"),
    ("SHA-256", "SHA-512", "Hex"),
    ("SHA-512", "SHA-256", "Hex"),
]

HASH = {"SHA-256": hashes.SHA256, "SHA-512": hashes.SHA512}


# ---------------------------------------------------------------------------
# Auxiliares
# ---------------------------------------------------------------------------

def rodar(*argv):
    """Executa main.main() capturando a saída; devolve (código, texto exibido)."""
    saida, erro = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
        codigo = main.main(list(argv))
    return codigo, saida.getvalue() + erro.getvalue()


def escrever(pasta, nome, conteudo):
    caminho = os.path.join(pasta, nome)
    if isinstance(conteudo, str):
        conteudo = conteudo.encode("utf-8")
    with open(caminho, "wb") as arquivo:
        arquivo.write(conteudo)
    return caminho


def ler(caminho):
    with open(caminho, "rb") as arquivo:
        return arquivo.read().decode("utf-8")


def criar(pasta, texto=MENSAGEM, *opcoes, publica=PUB_DEST, privada=PRIV_REM):
    entrada = escrever(pasta, "mensagem.txt", texto)
    envelope = os.path.join(pasta, "envelope.json")
    codigo, exibido = rodar("cifrar", "-m", entrada, "-d", publica, "-r", privada,
                            "-o", envelope, "-f", *opcoes)
    return codigo, envelope, exibido


def abrir(pasta, envelope, privada=PRIV_DEST, publica=PUB_REM):
    saida = os.path.join(pasta, "decifrada.txt")
    codigo, exibido = rodar("decifrar", "-e", envelope, "-d", privada,
                            "-r", publica, "-o", saida, "-f")
    return codigo, saida, exibido


def trocar_caractere(texto, posicao=10):
    """Adultera um caractere mantendo o texto válido em Base64/Hex."""
    trocado = "a" if texto[posicao] != "a" else "b"
    return texto[:posicao] + trocado + texto[posicao + 1:]


def alterar_envelope(caminho, alteracao):
    with open(caminho, encoding="utf-8") as arquivo:
        dados = json.load(arquivo)
    alteracao(dados)
    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(dados, arquivo)


def carregar_publica(caminho):
    with open(caminho, "rb") as arquivo:
        return serialization.load_pem_public_key(arquivo.read())


def carregar_privada(caminho):
    with open(caminho, "rb") as arquivo:
        return serialization.load_pem_private_key(arquivo.read(), password=None)


def gravar_par_rsa(pasta, bits):
    privada = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    caminho_privada = escrever(pasta, f"privada_{bits}.pem", privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    caminho_publica = escrever(pasta, f"publica_{bits}.pem", privada.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return caminho_publica, caminho_privada


def oaep(nome_hash):
    # CyberChef: MGF1 usa o mesmo hash do OAEP.
    return padding.OAEP(mgf=padding.MGF1(HASH[nome_hash]()),
                        algorithm=HASH[nome_hash](), label=None)


def codec(codificacao):
    if codificacao == "Base64":
        return (lambda b: base64.b64encode(b).decode("ascii"),
                lambda s: base64.b64decode(s, validate=True))
    return (lambda b: b.hex(), bytes.fromhex)


# Implementação independente das receitas do PDF do CyberChef (sem os módulos
# do projeto), usada para provar a interoperabilidade nos dois sentidos.

def abrir_como_cyberchef(dados):
    p, e = dados["parametros"], dados["envelope"]
    _, dec = codec(p["codificacao"])

    # 1. RSA Verify: Message = texto de mensagem_cifrada, PKCS#1 v1.5.
    carregar_publica(PUB_REM).verify(dec(e["assinatura"]),
                                     e["mensagem_cifrada"].encode("utf-8"),
                                     padding.PKCS1v15(), HASH[p["hash_assinatura"]]())

    # 2. RSA Decrypt (OAEP): devolve o TEXTO codificado da chave de sessão.
    texto_chave = carregar_privada(PRIV_DEST).decrypt(
        dec(e["chave_sessao"]), oaep(p["hash_oaep"])).decode("ascii")

    # 3. AES Decrypt (CBC) + remoção do PKCS#7 + Decode text (UTF-8).
    decifrador = Cipher(algorithms.AES(dec(texto_chave)),
                        modes.CBC(dec(e["iv"]))).decryptor()
    dados_claros = decifrador.update(dec(e["mensagem_cifrada"])) + decifrador.finalize()
    removedor = preenchimento.PKCS7(128).unpadder()
    texto = (removedor.update(dados_claros) + removedor.finalize()).decode("utf-8")

    return texto_chave, texto


def criar_como_cyberchef(texto, nome_hash, codificacao):
    enc, _ = codec(codificacao)
    chave, iv = os.urandom(32), os.urandom(16)
    texto_chave = enc(chave)

    preenchedor = preenchimento.PKCS7(128).padder()
    dados = preenchedor.update(texto.encode("utf-8")) + preenchedor.finalize()
    cifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    mensagem_cifrada = enc(cifrador.update(dados) + cifrador.finalize())

    return {
        "parametros": {
            "algoritmo_simetrico": "AES-256-CBC",
            "padding_simetrico": "PKCS7",
            "algoritmo_chave": "RSA-OAEP",
            "hash_oaep": nome_hash,
            "algoritmo_assinatura": "RSA",
            "hash_assinatura": nome_hash,
            "codificacao": codificacao,
        },
        "envelope": {
            "iv": enc(iv),
            "chave_sessao": enc(carregar_publica(PUB_DEST).encrypt(
                texto_chave.encode("ascii"), oaep(nome_hash))),
            "mensagem_cifrada": mensagem_cifrada,
            "assinatura": enc(carregar_privada(PRIV_REM).sign(
                mensagem_cifrada.encode("utf-8"), padding.PKCS1v15(),
                HASH[nome_hash]())),
        },
    }


# ---------------------------------------------------------------------------
# Fluxo completo e interoperabilidade
# ---------------------------------------------------------------------------

def test_ida_e_volta_em_todas_as_combinacoes():
    for hash_oaep, hash_assinatura, codificacao in COMBINACOES:
        with tempfile.TemporaryDirectory() as pasta:
            codigo, envelope, _ = criar(pasta, MENSAGEM, "--hash-oaep", hash_oaep,
                                        "--hash-assinatura", hash_assinatura,
                                        "--codificacao", codificacao)
            assert codigo == main.SAIDA_OK

            codigo, decifrada, _ = abrir(pasta, envelope)
            assert codigo == main.SAIDA_OK
            assert ler(decifrada) == MENSAGEM


def test_envelope_segue_as_receitas_do_cyberchef():
    for hash_oaep, hash_assinatura, codificacao in COMBINACOES:
        with tempfile.TemporaryDirectory() as pasta:
            # Enter e espaços no final não podem entrar no dado cifrado.
            codigo, envelope, exibido = criar(
                pasta, MENSAGEM + " \r\n\n", "--hash-oaep", hash_oaep,
                "--hash-assinatura", hash_assinatura, "--codificacao", codificacao)
            assert codigo == main.SAIDA_OK
            assert "Removido(s) 4 caractere(s)" in exibido

            with open(envelope, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)

            assert list(dados) == ["parametros", "envelope"]
            assert list(dados["parametros"]) == list(main.CAMPOS_PARAMETROS)
            assert list(dados["envelope"]) == list(main.CAMPOS_ENVELOPE)
            for valor in dados["envelope"].values():
                assert valor == "".join(valor.split()), "campo com espaço/quebra"

            texto_chave, texto = abrir_como_cyberchef(dados)
            assert len(texto_chave) == (44 if codificacao == "Base64" else 64)
            assert texto == MENSAGEM


def test_abre_envelope_criado_como_no_cyberchef():
    for nome_hash in ("SHA-256", "SHA-512"):
        for codificacao in main.CODIFICACOES:
            with tempfile.TemporaryDirectory() as pasta:
                envelope = escrever(pasta, "envelope.json", json.dumps(
                    criar_como_cyberchef(MENSAGEM, nome_hash, codificacao)))

                codigo, decifrada, _ = abrir(pasta, envelope)
                assert codigo == main.SAIDA_OK
                assert ler(decifrada) == MENSAGEM


# ---------------------------------------------------------------------------
# Tratamento de erros
# ---------------------------------------------------------------------------

def test_criptograma_alterado_dispara_alerta_e_nada_e_gravado():
    with tempfile.TemporaryDirectory() as pasta:
        _, envelope, _ = criar(pasta)

        alterar_envelope(envelope, lambda d: d["envelope"].update(
            mensagem_cifrada=trocar_caractere(d["envelope"]["mensagem_cifrada"])))

        codigo, saida, exibido = abrir(pasta, envelope)
        assert codigo == main.SAIDA_INTEGRIDADE
        assert "ALERTA DE INTEGRIDADE" in exibido
        assert not os.path.exists(saida)


def test_assinatura_verificada_antes_de_decifrar():
    # Com assinatura adulterada E chave privada errada, o alerta de integridade
    # tem de vir primeiro: nenhuma decifragem é tentada.
    with tempfile.TemporaryDirectory() as pasta:
        _, envelope, _ = criar(pasta)
        _, outra_privada = gravar_par_rsa(pasta, 2048)

        alterar_envelope(envelope, lambda d: d["envelope"].update(
            assinatura=trocar_caractere(d["envelope"]["assinatura"])))

        codigo, _, exibido = abrir(pasta, envelope, privada=outra_privada)
        assert codigo == main.SAIDA_INTEGRIDADE
        assert "[3/4]" not in exibido


def test_espaco_no_fim_do_criptograma_e_apontado_como_causa():
    with tempfile.TemporaryDirectory() as pasta:
        _, envelope, _ = criar(pasta)
        alterar_envelope(envelope, lambda d: d["envelope"].update(
            mensagem_cifrada=d["envelope"]["mensagem_cifrada"] + "\n"))

        codigo, _, exibido = abrir(pasta, envelope)
        assert codigo == main.SAIDA_INTEGRIDADE
        assert "contém espaço ou quebra de linha" in exibido


def test_json_malformado():
    with tempfile.TemporaryDirectory() as pasta:
        envelope = escrever(pasta, "envelope.json", '{"parametros": {"hash_oaep": ')

        codigo, _, exibido = abrir(pasta, envelope)
        assert codigo == main.SAIDA_ERRO
        assert "não é um JSON válido" in exibido
        assert "linha 1" in exibido


def test_campo_obrigatorio_ausente():
    with tempfile.TemporaryDirectory() as pasta:
        _, envelope, _ = criar(pasta)
        alterar_envelope(envelope, lambda d: d["envelope"].pop("iv"))

        codigo, _, exibido = abrir(pasta, envelope)
        assert codigo == main.SAIDA_ERRO
        assert "ausente" in exibido and "iv" in exibido


def test_parametro_nao_suportado():
    with tempfile.TemporaryDirectory() as pasta:
        _, envelope, _ = criar(pasta)
        alterar_envelope(envelope, lambda d: d["parametros"].update(
            algoritmo_simetrico="AES-128-CBC"))

        codigo, _, exibido = abrir(pasta, envelope)
        assert codigo == main.SAIDA_ERRO
        assert "Parâmetro não suportado" in exibido


def test_campo_com_codificacao_invalida():
    with tempfile.TemporaryDirectory() as pasta:
        _, envelope, _ = criar(pasta)
        alterar_envelope(envelope, lambda d: d["envelope"].update(iv="%%%"))

        codigo, _, exibido = abrir(pasta, envelope)
        assert codigo == main.SAIDA_ERRO
        assert "não é um texto Base64 válido" in exibido


def test_arquivo_inexistente():
    with tempfile.TemporaryDirectory() as pasta:
        codigo, _, exibido = abrir(pasta, os.path.join(pasta, "nao_existe.json"))
        assert codigo == main.SAIDA_ERRO
        assert "Arquivo não encontrado" in exibido

        codigo, _, exibido = criar(pasta, publica=os.path.join(pasta, "nada.pem"))
        assert codigo == main.SAIDA_ERRO
        assert "chave pública do destinatário" in exibido


def test_chaves_trocadas():
    with tempfile.TemporaryDirectory() as pasta:
        codigo, _, exibido = criar(pasta, publica=PRIV_DEST)
        assert codigo == main.SAIDA_ERRO
        assert "chave PRIVADA no lugar" in exibido

        _, envelope, _ = criar(pasta)
        codigo, _, exibido = abrir(pasta, envelope, privada=PUB_DEST)
        assert codigo == main.SAIDA_ERRO
        assert "não é uma chave PRIVADA" in exibido


def test_chave_privada_de_outro_destinatario():
    with tempfile.TemporaryDirectory() as pasta:
        _, envelope, _ = criar(pasta)
        _, outra_privada = gravar_par_rsa(pasta, 2048)

        codigo, _, exibido = abrir(pasta, envelope, privada=outra_privada)
        assert codigo == main.SAIDA_ERRO
        assert "decifrar a chave de sessão" in exibido


def test_pem_invalido_ou_corrompido():
    with tempfile.TemporaryDirectory() as pasta:
        sem_pem = escrever(pasta, "texto.pem", "isto não é uma chave")
        codigo, _, exibido = criar(pasta, publica=sem_pem)
        assert codigo == main.SAIDA_ERRO
        assert "não está no formato PEM" in exibido

        corrompida = escrever(pasta, "corrompida.pem",
                              "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
        codigo, _, exibido = criar(pasta, publica=corrompida)
        assert codigo == main.SAIDA_ERRO
        assert "corrompida" in exibido


def test_chave_pequena_demais_para_oaep_sha512():
    with tempfile.TemporaryDirectory() as pasta:
        publica_1024, _ = gravar_par_rsa(pasta, 1024)

        codigo, _, exibido = criar(pasta, MENSAGEM, "--hash-oaep", "SHA-512",
                                   publica=publica_1024)
        assert codigo == main.SAIDA_ERRO
        assert "pequena demais" in exibido


def test_mensagem_vazia_ou_fora_de_utf8():
    with tempfile.TemporaryDirectory() as pasta:
        codigo, _, exibido = criar(pasta, " \n\n")
        assert codigo == main.SAIDA_ERRO
        assert "vazio" in exibido

        codigo, _, exibido = criar(pasta, "ação".encode("latin-1"))
        assert codigo == main.SAIDA_ERRO
        assert "não está em UTF-8" in exibido


def test_nao_sobrescreve_sem_permissao():
    with tempfile.TemporaryDirectory() as pasta:
        entrada = escrever(pasta, "mensagem.txt", MENSAGEM)
        existente = escrever(pasta, "envelope.json", "conteúdo anterior")

        codigo, exibido = rodar("cifrar", "-m", entrada, "-d", PUB_DEST,
                                "-r", PRIV_REM, "-o", existente)
        assert codigo == main.SAIDA_ERRO
        assert "já existe" in exibido
        assert ler(existente) == "conteúdo anterior"

        codigo, exibido = rodar("cifrar", "-m", entrada, "-d", PUB_DEST,
                                "-r", PRIV_REM, "-o", entrada, "-f")
        assert codigo == main.SAIDA_ERRO
        assert "é um dos arquivos de entrada" in exibido


if __name__ == "__main__":
    testes = [f for nome, f in sorted(globals().items()) if nome.startswith("test_")]
    for teste in testes:
        teste()
        print(f"ok  {teste.__name__}")

    print(f"Todos os {len(testes)} testes de main.py passaram!")
