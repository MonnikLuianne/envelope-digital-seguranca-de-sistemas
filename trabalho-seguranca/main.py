"""
Envelope Digital Assinado (Encrypt-then-Sign) - interface, integração e
tratamento de erros (Integrante 3).

Orquestra os módulos da equipe:
    rsa_utils.py         (Integrante 1) RSA-OAEP da chave de sessão e assinatura RSA
    aes_utils.py         (Integrante 2) AES-256-CBC com PKCS#7
    envelope_builder.py  (Integrante 2) montagem e leitura do JSON

Uso:
    python main.py                 menu interativo
    python main.py cifrar ...      cria o envelope   (python main.py cifrar -h)
    python main.py decifrar ...    abre o envelope   (python main.py decifrar -h)
"""

import argparse
import base64
import json
import os
import sys
from contextlib import contextmanager

try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ModuleNotFoundError:
    sys.exit(
        "[ERRO] A biblioteca 'cryptography' não está instalada.\n"
        "       Como corrigir: pip install -r requirements.txt"
    )

try:
    from rsa_utils import (
        assinar,
        cifrar_chave_sessao,
        decifrar_chave_sessao,
        verificar_assinatura,
    )
except Exception as erro:
    sys.exit(
        "[ERRO] Não foi possível carregar rsa_utils.py (Integrante 1): "
        f"{type(erro).__name__}: {erro}"
    )

# Enquanto aes_utils.py / envelope_builder.py (Integrante 2) não expõem as
# funções do contrato, usa os stubs temporários de stubs.py (mesmas assinaturas).
MODULOS_EM_STUB = {}

try:
    from aes_utils import cifrar_aes, decifrar_aes, gerar_chave_iv
except Exception as erro:
    from stubs import cifrar_aes, decifrar_aes, gerar_chave_iv
    MODULOS_EM_STUB["aes_utils.py"] = erro

try:
    from envelope_builder import ler_envelope, montar_envelope
except Exception as erro:
    from stubs import ler_envelope, montar_envelope
    MODULOS_EM_STUB["envelope_builder.py"] = erro


DIR_BASE = os.path.dirname(os.path.abspath(__file__))

HASHES = ("SHA-256", "SHA-512")
CODIFICACOES = ("Base64", "Hex")
BYTES_HASH = {"SHA-256": 32, "SHA-512": 64}

TAMANHO_CHAVE = 32   # AES-256
TAMANHO_IV = 16      # 128 bits
TAMANHO_BLOCO = 16   # bloco do AES

CAMPOS_PARAMETROS = (
    "algoritmo_simetrico",
    "padding_simetrico",
    "algoritmo_chave",
    "hash_oaep",
    "algoritmo_assinatura",
    "hash_assinatura",
    "codificacao",
)
PARAMETROS_FIXOS = (
    "algoritmo_simetrico",
    "padding_simetrico",
    "algoritmo_chave",
    "algoritmo_assinatura",
)
CAMPOS_ENVELOPE = ("iv", "chave_sessao", "mensagem_cifrada", "assinatura")

SAIDA_OK = 0
SAIDA_ERRO = 1
SAIDA_INTEGRIDADE = 3
SAIDA_CANCELADA = 130

DICA_ESTRUTURA = (
    "O JSON deve ter a seção 'parametros' (" + ", ".join(CAMPOS_PARAMETROS)
    + ") e a seção 'envelope' (" + ", ".join(CAMPOS_ENVELOPE) + ")."
)
DICA_PEM = (
    "Confira se o arquivo foi copiado inteiro, com as linhas -----BEGIN/END-----. "
    "Para gerar um par: openssl genpkey -algorithm RSA "
    "-pkeyopt rsa_keygen_bits:2048 -out privada.pem"
)
DICA_CERTIFICADO = (
    "O arquivo é um certificado X.509. Extraia a chave pública com: "
    "openssl x509 -in certificado.pem -pubkey -noout > publica.pem"
)

BANNER = """
==============================================================
  Envelope Digital Assinado (Encrypt-then-Sign)
  AES-256-CBC + RSA-OAEP + assinatura RSA (SHA-256 / SHA-512)
==============================================================
Dica: tecle Enter para aceitar o valor [entre colchetes]. Também
é possível arrastar o arquivo para o terminal."""


class ErroEnvelope(Exception):
    """Falha prevista: mensagem clara, detalhe técnico e dica de correção."""

    def __init__(self, mensagem, dica=None, detalhe=None):
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.dica = dica
        self.detalhe = detalhe


class IntegridadeViolada(ErroEnvelope):
    """Assinatura inválida: a abertura do envelope é interrompida."""


# ---------------------------------------------------------------------------
# Mensagens na tela
# ---------------------------------------------------------------------------

def descrever(erro):
    mensagem = str(erro)
    return f"{type(erro).__name__}: {mensagem}" if mensagem else type(erro).__name__


def avisar(mensagem):
    print(f"[AVISO] {mensagem}")


def avisar_stubs():
    for modulo, motivo in MODULOS_EM_STUB.items():
        # Função ausente é o caso esperado; outros erros (ex.: sintaxe) são exibidos.
        funcao_ausente = type(motivo) is ImportError
        avisar(
            f"{modulo} ainda não implementa o contrato; usando o stub temporário "
            "de stubs.py" + ("." if funcao_ausente else f" ({descrever(motivo)}).")
        )


def exibir_erro(erro):
    sys.stdout.flush()
    linhas = [f"\n[ERRO] {erro.mensagem}"]
    if erro.detalhe:
        linhas.append(f"       Detalhe técnico: {erro.detalhe}")
    if erro.dica:
        linhas.append(f"       Como corrigir: {erro.dica}")
    print("\n".join(linhas), file=sys.stderr)


def exibir_alerta_integridade(erro):
    sys.stdout.flush()
    faixa = "!" * 66
    print(f"\n{faixa}\n  ALERTA DE INTEGRIDADE: {erro.mensagem}\n{faixa}",
          file=sys.stderr)
    if erro.dica:
        print(erro.dica, file=sys.stderr)


@contextmanager
def etapa(numero, total, descricao, falha, dica=None):
    """Exibe o progresso de uma etapa e converte qualquer exceção em ErroEnvelope."""
    print(f"[{numero}/{total}] {descricao}...", end=" ", flush=True)
    try:
        yield
    except ErroEnvelope:
        print("FALHOU")
        raise
    except Exception as erro:
        print("FALHOU")
        raise ErroEnvelope(falha, dica=dica, detalhe=descrever(erro)) from erro
    print("OK")


# ---------------------------------------------------------------------------
# Codificação e validação de valores
# ---------------------------------------------------------------------------

def sem_espacos(texto):
    """Remove espaços e quebras de linha, que nunca fazem parte de Base64/Hex."""
    return "".join(texto.split())


def compactar(valor):
    return "".join(ch for ch in str(valor).upper() if ch.isalnum())


def normalizar_opcao(valor, opcoes, campo):
    """Aceita variações como 'sha512' ou 'HEX' e devolve a forma canônica."""
    for opcao in opcoes:
        if compactar(opcao) == compactar(valor):
            return opcao

    raise ErroEnvelope(
        f"Valor inválido para {campo}: {valor!r}.",
        dica=f"Use {' ou '.join(opcoes)}.",
    )


def codificar(dados, codificacao):
    if codificacao == "Base64":
        return base64.b64encode(dados).decode("ascii")

    return dados.hex()


def decodificar(texto, codificacao, campo):
    """Decodifica um campo Base64/Hex de forma estrita, com erro claro."""
    try:
        if codificacao == "Base64":
            return base64.b64decode(sem_espacos(texto), validate=True)

        return bytes.fromhex(sem_espacos(texto))
    except ValueError as erro:  # inclui binascii.Error
        raise ErroEnvelope(
            f"O campo '{campo}' não é um texto {codificacao} válido.",
            dica=f"Todos os campos do envelope devem estar em {codificacao}, "
                 "conforme 'parametros.codificacao'.",
            detalhe=descrever(erro),
        ) from erro


def texto_codificado(valor, campo, codificacao):
    """Normaliza o texto devolvido por um módulo antes de usá-lo no envelope.

    Espaços e quebras de linha (Base64 quebrado em linhas, Enter no final)
    passariam a fazer parte do dado assinado e quebrariam a compatibilidade
    com o CyberChef, por isso são removidos.
    """
    if isinstance(valor, bytes):
        valor = valor.decode("ascii")

    if not isinstance(valor, str) or not valor.strip():
        raise ErroEnvelope(
            f"O módulo devolveu um valor inválido para '{campo}' "
            f"({type(valor).__name__}).",
            dica="O contrato exige texto codificado (Base64 ou Hex).",
        )

    valor = sem_espacos(valor)
    decodificar(valor, codificacao, campo)
    return valor


def exigir_bytes(valor, tamanho, nome):
    if not isinstance(valor, bytes) or len(valor) != tamanho:
        raise ErroEnvelope(
            f"gerar_chave_iv() devolveu {nome} inválido: esperado {tamanho} bytes.",
            dica="Confira aes_utils.gerar_chave_iv (Integrante 2).",
        )


def exigir_capacidade_oaep(bits, hash_oaep, tamanho_texto, codificacao):
    """O RSA-OAEP cifra no máximo k - 2*hLen - 2 bytes (RFC 8017)."""
    limite = (bits + 7) // 8 - 2 * BYTES_HASH[hash_oaep] - 2
    if tamanho_texto > limite:
        raise ErroEnvelope(
            f"A chave pública do destinatário ({bits} bits) é pequena demais para "
            f"cifrar a chave de sessão em {codificacao} ({tamanho_texto} caracteres) "
            f"com RSA-OAEP/{hash_oaep}: o limite é {max(limite, 0)} bytes.",
            dica="Use chaves RSA de 2048 bits ou mais "
                 "(SHA-512 no OAEP exige no mínimo 2048 bits).",
        )


def montar_parametros(hash_oaep, hash_assinatura, codificacao):
    """Seção 'parametros' do JSON, na ordem do enunciado."""
    return {
        "algoritmo_simetrico": "AES-256-CBC",
        "padding_simetrico": "PKCS7",
        "algoritmo_chave": "RSA-OAEP",
        "hash_oaep": hash_oaep,
        "algoritmo_assinatura": "RSA",
        "hash_assinatura": hash_assinatura,
        "codificacao": codificacao,
    }


def validar_envelope(dados):
    """Valida estrutura, parâmetros e codificação de todos os campos.

    Devolve (parametros normalizados, campos do envelope).
    """
    if not isinstance(dados, dict):
        raise ErroEnvelope("O envelope deve ser um objeto JSON { ... }.",
                           dica=DICA_ESTRUTURA)

    for secao in ("parametros", "envelope"):
        if not isinstance(dados.get(secao), dict):
            raise ErroEnvelope(
                f"Seção obrigatória ausente ou inválida no JSON: '{secao}'.",
                dica=DICA_ESTRUTURA,
            )

    parametros, envelope = dados["parametros"], dados["envelope"]
    faltando = [f"parametros.{c}" for c in CAMPOS_PARAMETROS if c not in parametros]
    faltando += [f"envelope.{c}" for c in CAMPOS_ENVELOPE if c not in envelope]
    if faltando:
        raise ErroEnvelope(
            "Campo(s) obrigatório(s) ausente(s) no JSON: " + ", ".join(faltando) + ".",
            dica=DICA_ESTRUTURA,
        )

    normalizados = montar_parametros(
        normalizar_opcao(parametros["hash_oaep"], HASHES, "parametros.hash_oaep"),
        normalizar_opcao(parametros["hash_assinatura"], HASHES,
                         "parametros.hash_assinatura"),
        normalizar_opcao(parametros["codificacao"], CODIFICACOES,
                         "parametros.codificacao"),
    )
    for campo in PARAMETROS_FIXOS:
        if compactar(parametros[campo]) != compactar(normalizados[campo]):
            raise ErroEnvelope(
                f"Parâmetro não suportado: {campo} = {parametros[campo]!r}.",
                dica=f"Este protocolo usa {campo} = {normalizados[campo]!r}.",
            )

    codificacao = normalizados["codificacao"]
    campos = {}
    for campo in CAMPOS_ENVELOPE:
        valor = envelope[campo]
        if not isinstance(valor, str) or not valor.strip():
            raise ErroEnvelope(
                f"O campo 'envelope.{campo}' está vazio ou não é texto.",
                dica=f"Ele deve conter um texto {codificacao}.",
            )
        campos[campo] = valor

    iv = decodificar(campos["iv"], codificacao, "envelope.iv")
    if len(iv) != TAMANHO_IV:
        raise ErroEnvelope(
            f"O IV deve ter {TAMANHO_IV} bytes (128 bits), mas tem {len(iv)}.",
            dica="O campo 'envelope.iv' está truncado ou em outra codificação.",
        )

    criptograma = decodificar(campos["mensagem_cifrada"], codificacao,
                              "envelope.mensagem_cifrada")
    if not criptograma or len(criptograma) % TAMANHO_BLOCO:
        raise ErroEnvelope(
            "O criptograma AES-CBC deve ter tamanho múltiplo de 16 bytes, "
            f"mas tem {len(criptograma)}.",
            dica="O campo 'envelope.mensagem_cifrada' está truncado ou corrompido.",
        )

    decodificar(campos["chave_sessao"], codificacao, "envelope.chave_sessao")
    decodificar(campos["assinatura"], codificacao, "envelope.assinatura")

    return normalizados, campos


# ---------------------------------------------------------------------------
# Arquivos e chaves
# ---------------------------------------------------------------------------

def ler_bytes(caminho, descricao):
    try:
        with open(caminho, "rb") as arquivo:
            return arquivo.read()
    except FileNotFoundError:
        raise ErroEnvelope(
            f"Arquivo não encontrado ({descricao}): {caminho or '(vazio)'}",
            dica=f"Confira o nome e o caminho. Caminhos relativos partem de: {os.getcwd()}",
        ) from None
    except IsADirectoryError:
        raise ErroEnvelope(
            f"O caminho informado para {descricao} é uma pasta: {caminho}",
            dica="Informe o caminho do arquivo, não da pasta.",
        ) from None
    except PermissionError:
        raise ErroEnvelope(
            f"Sem permissão para ler {descricao}: {caminho}",
            dica="Confira as permissões do arquivo.",
        ) from None
    except OSError as erro:
        raise ErroEnvelope(f"Não foi possível ler {descricao}: {caminho}",
                           detalhe=descrever(erro)) from erro


def ler_mensagem(caminho):
    """Lê o texto em claro (UTF-8) sem espaços/quebras de linha no final."""
    conteudo = ler_bytes(caminho, "mensagem em claro")
    try:
        texto = conteudo.decode("utf-8-sig")  # -sig descarta o BOM do Bloco de Notas
    except UnicodeDecodeError as erro:
        raise ErroEnvelope(
            f"A mensagem não está em UTF-8 (byte inválido na posição {erro.start}): "
            f"{caminho}",
            dica="Salve o arquivo com a codificação UTF-8 e tente novamente.",
        ) from erro

    # Um Enter ou espaço no final passaria a fazer parte do dado cifrado,
    # divergindo do texto que se cola no Input do CyberChef.
    limpo = texto.rstrip()
    if not limpo:
        raise ErroEnvelope(f"O arquivo de mensagem está vazio: {caminho}",
                           dica="Escreva no arquivo o texto a ser protegido.")

    if limpo != texto:
        avisar(
            f"Removido(s) {len(texto) - len(limpo)} caractere(s) de espaço/quebra "
            "de linha do final da mensagem (compatibilidade com o CyberChef)."
        )

    return limpo


def validar_chave_pem(caminho, publica, descricao):
    """Confere a chave PEM antes do uso, com mensagens claras; devolve os bits."""
    conteudo = ler_bytes(caminho, descricao)

    if b"-----BEGIN" not in conteudo:
        raise ErroEnvelope(f"A {descricao} não está no formato PEM: {caminho}",
                           dica=DICA_PEM)

    eh_privada = b"PRIVATE KEY" in conteudo
    if publica and eh_privada:
        raise ErroEnvelope(
            f"Foi informada uma chave PRIVADA no lugar da {descricao}: {caminho}",
            dica="Use o arquivo *_public.pem correspondente.",
        )
    if not publica and not eh_privada:
        raise ErroEnvelope(
            f"O arquivo informado não é uma chave PRIVADA ({descricao}): {caminho}",
            dica="Use o arquivo *_private.pem correspondente.",
        )

    try:
        if publica:
            chave = serialization.load_pem_public_key(conteudo)
        else:
            chave = serialization.load_pem_private_key(conteudo, password=None)
    except TypeError as erro:  # chave privada cifrada com senha
        raise ErroEnvelope(
            f"A {descricao} está protegida por senha: {caminho}",
            dica="O protocolo usa chave sem senha (no CyberChef, 'Key Password' "
                 "vazio). Remova a senha com: openssl pkey -in chave.pem "
                 "-out chave_sem_senha.pem",
        ) from erro
    except (ValueError, UnsupportedAlgorithm) as erro:
        raise ErroEnvelope(
            f"A {descricao} está corrompida ou não é um PEM válido: {caminho}",
            detalhe=descrever(erro),
            dica=DICA_CERTIFICADO if b"CERTIFICATE" in conteudo else DICA_PEM,
        ) from erro

    tipo = rsa.RSAPublicKey if publica else rsa.RSAPrivateKey
    if not isinstance(chave, tipo):
        raise ErroEnvelope(f"A {descricao} não é uma chave RSA: {caminho}",
                           dica=DICA_PEM)

    return chave.key_size


def preparar_saida(caminho, entradas, sobrescrever):
    """Valida o arquivo de saída antes de processar: em erro, nada é gravado."""
    if not caminho:
        raise ErroEnvelope("Nenhum arquivo de saída foi informado.")

    if os.path.isdir(caminho):
        raise ErroEnvelope(f"O caminho de saída é uma pasta: {caminho}",
                           dica="Informe também o nome do arquivo a ser gerado.")

    pasta = os.path.dirname(os.path.abspath(caminho))
    if not os.path.isdir(pasta):
        raise ErroEnvelope(f"A pasta de destino não existe: {pasta}",
                           dica="Crie a pasta ou escolha outro caminho de saída.")

    if not os.path.exists(caminho):
        return

    if any(os.path.exists(e) and os.path.samefile(caminho, e) for e in entradas):
        raise ErroEnvelope(
            f"O arquivo de saída é um dos arquivos de entrada: {caminho}",
            dica="Escolha outro nome para não destruir a entrada.",
        )

    if not sobrescrever:
        raise ErroEnvelope(f"O arquivo de saída já existe: {caminho}",
                           dica="Use --sobrescrever (-f) ou escolha outro nome.")


def gravar_arquivo(caminho, conteudo, descricao):
    """Grava texto UTF-8 exatamente como está (sem conversão de fim de linha)."""
    try:
        with open(caminho, "w", encoding="utf-8", newline="") as arquivo:
            arquivo.write(conteudo)
    except OSError as erro:
        raise ErroEnvelope(f"Não foi possível gravar {descricao} em: {caminho}",
                           detalhe=descrever(erro),
                           dica="Confira as permissões da pasta de destino.") from erro


# ---------------------------------------------------------------------------
# Fluxo de cifragem (Encrypt-then-Sign)
# ---------------------------------------------------------------------------

def criar_envelope(caminho_mensagem, caminho_publica_destinatario,
                   caminho_privada_remetente, caminho_saida,
                   hash_oaep="SHA-256", hash_assinatura="SHA-256",
                   codificacao="Base64", sobrescrever=False):
    """Cria o envelope digital e grava o JSON em caminho_saida."""
    hash_oaep = normalizar_opcao(hash_oaep, HASHES, "o hash do OAEP")
    hash_assinatura = normalizar_opcao(hash_assinatura, HASHES,
                                       "o hash da assinatura")
    codificacao = normalizar_opcao(codificacao, CODIFICACOES, "a codificação")

    # Todas as entradas são validadas antes de gerar qualquer segredo.
    texto = ler_mensagem(caminho_mensagem)
    bits_destinatario = validar_chave_pem(caminho_publica_destinatario, True,
                                          "chave pública do destinatário")
    validar_chave_pem(caminho_privada_remetente, False,
                      "chave privada do remetente")
    preparar_saida(caminho_saida,
                   [caminho_mensagem, caminho_publica_destinatario,
                    caminho_privada_remetente],
                   sobrescrever)
    parametros = montar_parametros(hash_oaep, hash_assinatura, codificacao)

    print(f"\nCriando envelope: RSA-OAEP/{hash_oaep}, assinatura RSA/"
          f"{hash_assinatura}, codificação {codificacao}")

    with etapa(1, 6, "Gerando chave de sessão AES-256 e IV aleatórios",
               "Falha ao gerar a chave de sessão e o IV."):
        chave, iv = gerar_chave_iv()
        exigir_bytes(chave, TAMANHO_CHAVE, "chave de sessão")
        exigir_bytes(iv, TAMANHO_IV, "IV")

    with etapa(2, 6, f"Codificando chave e IV em {codificacao}",
               "Falha ao codificar a chave de sessão e o IV."):
        chave_txt = codificar(chave, codificacao)
        iv_txt = codificar(iv, codificacao)

    exigir_capacidade_oaep(bits_destinatario, hash_oaep, len(chave_txt),
                           codificacao)

    with etapa(3, 6, f"Cifrando a chave de sessão com RSA-OAEP/{hash_oaep}",
               "Falha ao cifrar a chave de sessão com a chave pública do "
               "destinatário.",
               dica="Confira a chave pública do destinatário (RSA, 2048 bits "
                    "ou mais)."):
        # Pelo protocolo (e no CyberChef) o RSA cifra o TEXTO codificado da
        # chave de sessão, não os 32 bytes brutos.
        chave_sessao = texto_codificado(
            cifrar_chave_sessao(chave_txt.encode("ascii"),
                                caminho_publica_destinatario, hash_oaep,
                                codificacao),
            "chave_sessao", codificacao,
        )

    with etapa(4, 6, "Cifrando a mensagem com AES-256-CBC (PKCS#7)",
               "Falha ao cifrar a mensagem com AES-256-CBC."):
        mensagem_cifrada = texto_codificado(
            cifrar_aes(texto, chave, iv, codificacao),
            "mensagem_cifrada", codificacao,
        )

    with etapa(5, 6, f"Assinando o criptograma com RSA/{hash_assinatura}",
               "Falha ao assinar o criptograma com a chave privada do remetente.",
               dica="Confira a chave privada do remetente (RSA sem senha)."):
        # Encrypt-then-Sign: assina o texto codificado exatamente como vai no JSON.
        assinatura = texto_codificado(
            assinar(mensagem_cifrada, caminho_privada_remetente,
                    hash_assinatura, codificacao=codificacao),
            "assinatura", codificacao,
        )

    with etapa(6, 6, "Montando o envelope JSON",
               "Falha ao montar o envelope JSON.",
               dica="Confira envelope_builder.montar_envelope (Integrante 2)."):
        envelope = montar_envelope(parametros, iv_txt, chave_sessao,
                                   mensagem_cifrada, assinatura)
        esperado = {
            "iv": iv_txt,
            "chave_sessao": chave_sessao,
            "mensagem_cifrada": mensagem_cifrada,
            "assinatura": assinatura,
        }
        if validar_envelope(envelope) != (parametros, esperado):
            raise ErroEnvelope(
                "O envelope montado não corresponde aos dados cifrados e assinados.",
                dica="montar_envelope não deve alterar os valores recebidos "
                     "(envelope_builder.py, Integrante 2).",
            )

    gravar_arquivo(caminho_saida, json.dumps(envelope, indent=4, ensure_ascii=False),
                   "o envelope")
    print(f"\n[OK] Envelope criado com sucesso: {caminho_saida}")
    return envelope


# ---------------------------------------------------------------------------
# Fluxo de decifragem
# ---------------------------------------------------------------------------

def carregar_envelope(caminho):
    """Lê o JSON com ler_envelope (Integrante 2) e valida todos os campos."""
    try:
        dados = ler_envelope(caminho)
    except json.JSONDecodeError as erro:
        raise ErroEnvelope(
            f"O arquivo não é um JSON válido: {erro.msg} "
            f"(linha {erro.lineno}, coluna {erro.colno}).",
            dica="Confira aspas, vírgulas e chaves { } do arquivo.",
        ) from erro
    except UnicodeDecodeError as erro:
        raise ErroEnvelope("O envelope não está codificado em UTF-8.",
                           detalhe=descrever(erro),
                           dica="Salve o arquivo JSON em UTF-8.") from erro
    except KeyError as erro:
        raise ErroEnvelope(f"Campo obrigatório ausente no JSON: {erro}.",
                           dica=DICA_ESTRUTURA) from erro
    except ValueError as erro:
        raise ErroEnvelope(f"Envelope inválido: {erro}",
                           dica=DICA_ESTRUTURA) from erro

    return validar_envelope(dados)


def dica_integridade(campos, hash_assinatura):
    causas = [
        "o criptograma ou a assinatura foram alterados depois de assinados;",
        "a chave pública informada não é a do remetente que assinou;",
        f"o remetente assinou com hash diferente de {hash_assinatura} ou com "
        "esquema PSS (o protocolo usa PKCS#1 v1.5);",
        "a assinatura foi feita sobre os bytes do criptograma, e não sobre o "
        "texto codificado.",
    ]
    if campos["mensagem_cifrada"] != sem_espacos(campos["mensagem_cifrada"]):
        causas.insert(0, "o campo 'mensagem_cifrada' contém espaço ou quebra de "
                         "linha, que passa a fazer parte do dado assinado;")

    return ("A abertura foi interrompida: nada foi decifrado nem gravado.\n"
            "Possíveis causas:\n" + "\n".join(f"  - {c}" for c in causas))


def recuperar_chave_aes(texto_chave, codificacao):
    """Converte o texto da chave devolvido pelo RSA nos 32 bytes da chave AES."""
    if isinstance(texto_chave, bytes):
        texto_chave = texto_chave.decode("ascii", errors="replace")

    try:
        chave = decodificar(texto_chave, codificacao, "chave de sessão decifrada")
    except ErroEnvelope:
        chave = b""

    if len(chave) != TAMANHO_CHAVE:
        raise ErroEnvelope(
            f"A chave de sessão decifrada não é um texto {codificacao} de 32 bytes.",
            dica="Pelo protocolo, o RSA-OAEP cifra o TEXTO codificado da chave "
                 "(44 caracteres em Base64 ou 64 em Hex), não os bytes brutos. "
                 "O envelope foi gerado fora do padrão ou com outra codificação.",
        )

    return chave


def abrir_envelope(caminho_envelope, caminho_privada_destinatario,
                   caminho_publica_remetente, caminho_saida, sobrescrever=False):
    """Abre o envelope: verifica a assinatura ANTES de decifrar qualquer coisa."""
    ler_bytes(caminho_envelope, "envelope JSON")
    validar_chave_pem(caminho_privada_destinatario, False,
                      "chave privada do destinatário")
    validar_chave_pem(caminho_publica_remetente, True,
                      "chave pública do remetente")
    preparar_saida(caminho_saida,
                   [caminho_envelope, caminho_privada_destinatario,
                    caminho_publica_remetente],
                   sobrescrever)

    print(f"\nAbrindo envelope: {caminho_envelope}")

    with etapa(1, 4, "Lendo e validando o envelope JSON",
               "Não foi possível ler o envelope JSON.", dica=DICA_ESTRUTURA):
        parametros, campos = carregar_envelope(caminho_envelope)
    codificacao = parametros["codificacao"]
    hash_assinatura = parametros["hash_assinatura"]

    with etapa(2, 4, f"Verificando a assinatura RSA/{hash_assinatura}",
               "Falha ao verificar a assinatura digital."):
        # Verifica sobre o texto exato do campo, como o RSA Verify do CyberChef.
        valida = verificar_assinatura(campos["mensagem_cifrada"],
                                      sem_espacos(campos["assinatura"]),
                                      caminho_publica_remetente, hash_assinatura,
                                      codificacao=codificacao)
        if not valida:
            raise IntegridadeViolada(
                "assinatura digital INVÁLIDA",
                dica=dica_integridade(campos, hash_assinatura),
            )

    with etapa(3, 4, f"Decifrando a chave de sessão com RSA-OAEP/"
                     f"{parametros['hash_oaep']}",
               "Não foi possível decifrar a chave de sessão com a chave privada "
               "do destinatário.",
               dica="Confira se a chave privada é a do DESTINATÁRIO (par da chave "
                    "pública usada na cifragem) e se 'hash_oaep' no JSON é o "
                    "mesmo usado na cifragem."):
        texto_chave = decifrar_chave_sessao(sem_espacos(campos["chave_sessao"]),
                                            caminho_privada_destinatario,
                                            parametros["hash_oaep"], codificacao)
        chave = recuperar_chave_aes(texto_chave, codificacao)
        iv = decodificar(campos["iv"], codificacao, "envelope.iv")

    with etapa(4, 4, "Decifrando a mensagem com AES-256-CBC (PKCS#7)",
               "Não foi possível decifrar a mensagem com a chave de sessão e o IV.",
               dica="A assinatura é válida, então o criptograma está íntegro: "
                    "confira o campo 'iv' (ele não é coberto pela assinatura)."):
        texto = decifrar_aes(sem_espacos(campos["mensagem_cifrada"]), chave, iv,
                             codificacao)
        if isinstance(texto, bytes):
            texto = texto.decode("utf-8")

    gravar_arquivo(caminho_saida, texto, "a mensagem decifrada")
    print(f"\n[OK] Assinatura válida. Mensagem decifrada em: {caminho_saida}")
    print("-" * 62)
    print(texto if len(texto) <= 1000 else texto[:1000] + "\n[... prévia truncada]")
    print("-" * 62)
    return texto


# ---------------------------------------------------------------------------
# Interface: menu interativo e linha de comando
# ---------------------------------------------------------------------------

def executar(operacao, *args, **kwargs):
    """Executa uma operação sem deixar escapar exceções; devolve o código de saída."""
    try:
        operacao(*args, **kwargs)
        return SAIDA_OK
    except IntegridadeViolada as erro:
        exibir_alerta_integridade(erro)
        return SAIDA_INTEGRIDADE
    except ErroEnvelope as erro:
        exibir_erro(erro)
        return SAIDA_ERRO
    except (KeyboardInterrupt, EOFError):
        print("\nOperação cancelada pelo usuário.")
        return SAIDA_CANCELADA
    except Exception as erro:  # rede de segurança: nunca encerra com traceback
        exibir_erro(ErroEnvelope(
            "Erro inesperado durante a operação.",
            detalhe=descrever(erro),
            dica="Confira as entradas; se persistir, informe o detalhe à equipe.",
        ))
        return SAIDA_ERRO


def caminho_padrao(*partes):
    """Caminho dentro do projeto, exibido relativo à pasta atual quando possível."""
    caminho = os.path.join(DIR_BASE, *partes)
    try:
        relativo = os.path.relpath(caminho)
    except ValueError:  # Windows: unidade de disco diferente
        return caminho
    return caminho if relativo.startswith(os.pardir) else relativo


def limpar_caminho(caminho):
    """Aceita caminhos colados ou arrastados para o terminal (aspas, '\\ ', '~')."""
    caminho = caminho.strip()
    if len(caminho) >= 2 and caminho[0] == caminho[-1] and caminho[0] in "'\"":
        caminho = caminho[1:-1]
    elif os.sep == "/":
        caminho = caminho.replace("\\ ", " ")
    return os.path.expanduser(caminho)


def perguntar(pergunta, padrao=None):
    sufixo = f" [{padrao}]" if padrao else ""
    return input(f"{pergunta}{sufixo}: ").strip() or padrao or ""


def perguntar_caminho(pergunta, padrao=None):
    return limpar_caminho(perguntar(pergunta, padrao))


def perguntar_saida(pergunta, padrao):
    """Pede o arquivo de saída e confirma antes de sobrescrever."""
    while True:
        caminho = perguntar_caminho(pergunta, padrao)
        if not os.path.isfile(caminho):
            return caminho
        resposta = perguntar(f"  '{caminho}' já existe. Sobrescrever? (s/N)")
        if resposta.lower() in ("s", "sim"):
            return caminho


def escolher(pergunta, opcoes):
    """Lê uma opção pelo número ou pelo nome; a primeira é o padrão."""
    menu = ", ".join(f"{i}={opcao}" for i, opcao in enumerate(opcoes, 1))
    while True:
        resposta = perguntar(f"{pergunta} ({menu})", "1")
        if resposta.isdigit() and 1 <= int(resposta) <= len(opcoes):
            return opcoes[int(resposta) - 1]
        try:
            return normalizar_opcao(resposta, opcoes, pergunta)
        except ErroEnvelope:
            print(f"  Opção inválida: digite um número de 1 a {len(opcoes)}.")


def criar_envelope_interativo():
    print("\n--- Criar envelope (cifrar e assinar) ---")
    mensagem = perguntar_caminho("Mensagem em claro (arquivo UTF-8)",
                                 caminho_padrao("dados", "mensagem.txt"))
    publica = perguntar_caminho("Chave PÚBLICA do destinatário (PEM)",
                                caminho_padrao("chaves", "destinatario_public.pem"))
    privada = perguntar_caminho("Chave PRIVADA do remetente (PEM)",
                                caminho_padrao("chaves", "remetente_private.pem"))
    hash_oaep = escolher("Hash do RSA-OAEP", HASHES)
    hash_assinatura = escolher("Hash da assinatura", HASHES)
    codificacao = escolher("Codificação", CODIFICACOES)
    saida = perguntar_saida("Arquivo do envelope a gerar (JSON)",
                            caminho_padrao("dados", "envelope.json"))

    criar_envelope(mensagem, publica, privada, saida, hash_oaep,
                   hash_assinatura, codificacao, sobrescrever=True)


def abrir_envelope_interativo():
    print("\n--- Abrir envelope (verificar e decifrar) ---")
    envelope = perguntar_caminho("Envelope (JSON)",
                                 caminho_padrao("dados", "envelope.json"))
    privada = perguntar_caminho("Chave PRIVADA do destinatário (PEM)",
                                caminho_padrao("chaves", "destinatario_private.pem"))
    publica = perguntar_caminho("Chave PÚBLICA do remetente (PEM)",
                                caminho_padrao("chaves", "remetente_public.pem"))
    saida = perguntar_saida("Arquivo da mensagem decifrada",
                            caminho_padrao("dados", "mensagem_decifrada.txt"))

    abrir_envelope(envelope, privada, publica, saida, sobrescrever=True)


def menu_interativo():
    print(BANNER)
    avisar_stubs()

    while True:
        print("\n  1) Criar envelope  (cifrar e assinar)"
              "\n  2) Abrir envelope  (verificar assinatura e decifrar)"
              "\n  0) Sair")
        try:
            opcao = perguntar("Opção")
        except (EOFError, KeyboardInterrupt):
            opcao = "0"
            print()

        if opcao == "1":
            executar(criar_envelope_interativo)
        elif opcao == "2":
            executar(abrir_envelope_interativo)
        elif opcao in ("0", "sair"):
            print("Até logo!")
            return SAIDA_OK
        else:
            print("Opção inválida: digite 1, 2 ou 0.")


def criar_parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Envelope Digital Assinado (Encrypt-then-Sign): AES-256-CBC, "
                    "RSA-OAEP e assinatura RSA. Sem argumentos, abre o menu "
                    "interativo.",
    )
    comandos = parser.add_subparsers(dest="comando", metavar="{cifrar,decifrar}")

    cifrar = comandos.add_parser(
        "cifrar", help="cria o envelope JSON (cifra e assina)",
        description="Cria o envelope digital a partir de um texto em claro.",
    )
    cifrar.add_argument("-m", "--mensagem", required=True, metavar="TXT",
                        help="arquivo de texto em claro (UTF-8)")
    cifrar.add_argument("-d", "--chave-publica-destinatario", required=True,
                        metavar="PEM", help="chave pública do destinatário")
    cifrar.add_argument("-r", "--chave-privada-remetente", required=True,
                        metavar="PEM", help="chave privada do remetente")
    cifrar.add_argument("-o", "--saida", required=True, metavar="JSON",
                        help="arquivo do envelope a gerar")
    cifrar.add_argument("--hash-oaep", choices=HASHES, default="SHA-256",
                        help="hash do RSA-OAEP e da MGF1 (padrão: %(default)s)")
    cifrar.add_argument("--hash-assinatura", choices=HASHES, default="SHA-256",
                        help="hash da assinatura RSA (padrão: %(default)s)")
    cifrar.add_argument("--codificacao", choices=CODIFICACOES, default="Base64",
                        help="codificação de todos os campos (padrão: %(default)s)")
    cifrar.add_argument("-f", "--sobrescrever", action="store_true",
                        help="substitui o arquivo de saída se ele já existir")

    decifrar = comandos.add_parser(
        "decifrar", help="abre o envelope JSON (verifica e decifra)",
        description="Verifica a assinatura e recupera o texto original.",
    )
    decifrar.add_argument("-e", "--envelope", required=True, metavar="JSON",
                          help="arquivo do envelope")
    decifrar.add_argument("-d", "--chave-privada-destinatario", required=True,
                          metavar="PEM", help="chave privada do destinatário")
    decifrar.add_argument("-r", "--chave-publica-remetente", required=True,
                          metavar="PEM", help="chave pública do remetente")
    decifrar.add_argument("-o", "--saida", required=True, metavar="TXT",
                          help="arquivo da mensagem decifrada")
    decifrar.add_argument("-f", "--sobrescrever", action="store_true",
                          help="substitui o arquivo de saída se ele já existir")

    return parser


def main(argv=None):
    # Evita falha ao exibir caracteres que o terminal não suporta.
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(errors="replace")

    args = criar_parser().parse_args(argv)

    if args.comando is None:
        return menu_interativo()

    avisar_stubs()

    if args.comando == "cifrar":
        return executar(criar_envelope, args.mensagem,
                        args.chave_publica_destinatario,
                        args.chave_privada_remetente, args.saida,
                        args.hash_oaep, args.hash_assinatura, args.codificacao,
                        args.sobrescrever)

    return executar(abrir_envelope, args.envelope,
                    args.chave_privada_destinatario,
                    args.chave_publica_remetente, args.saida,
                    args.sobrescrever)


if __name__ == "__main__":
    sys.exit(main())
