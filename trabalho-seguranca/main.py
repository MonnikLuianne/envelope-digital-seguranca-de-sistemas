"""
main.py — Interface, integração e tratamento de erros (Integrante 3).

Envelope Digital Assinado (Encrypt-then-Sign), usando os módulos da equipe:
    rsa_utils.py         (Integrante 1) RSA-OAEP e assinatura RSA
    aes_utils.py         (Integrante 2) AES-256-CBC
    envelope_builder.py  (Integrante 2) montagem e leitura do JSON

Execute a partir da pasta trabalho-seguranca:  python main.py
"""

import sys

try:
    from aes_utils import (ErroAES, cifrar_aes, codificar_chave, decifrar_aes,
                           decodificar, decodificar_chave, gerar_chave_iv)
    from envelope_builder import (ErroEnvelope, criar_parametros, ler_envelope,
                                  montar_envelope, salvar_envelope)
    from rsa_utils import (assinar, cifrar_chave_sessao, decifrar_chave_sessao,
                           verificar_assinatura)
except ModuleNotFoundError:
    sys.exit("[ERRO] Biblioteca 'cryptography' não instalada. "
             "Execute: pip install -r requirements.txt")


class IntegridadeViolada(Exception):
    """A assinatura do envelope não confere."""


def criar_envelope(caminho_mensagem, pub_destinatario, priv_remetente,
                   caminho_saida, hash_oaep, hash_assinatura, codificacao):
    with open(caminho_mensagem, "r", encoding="utf-8") as arquivo:
        # Um Enter ou espaço no final passaria a fazer parte do dado cifrado.
        texto = arquivo.read().rstrip()

    if not texto:
        raise ValueError("O arquivo da mensagem está vazio.")

    # 1. Gera a chave AES-256 e o IV.
    chave, iv = gerar_chave_iv()

    # 2 e 3. Cifra a chave CODIFICADA (Base64/Hex) com RSA-OAEP.
    chave_sessao = cifrar_chave_sessao(codificar_chave(chave, codificacao),
                                       pub_destinatario, hash_oaep, codificacao)

    # 4. Cifra a mensagem com AES-256-CBC.
    mensagem_cifrada = cifrar_aes(texto, chave, iv, codificacao)

    # 5. Encrypt-then-Sign: assina o criptograma codificado.
    assinatura = assinar(mensagem_cifrada, priv_remetente, hash_assinatura,
                         codificacao=codificacao)

    # 6. Monta e grava o envelope JSON.
    parametros = criar_parametros(hash_oaep, hash_assinatura, codificacao)
    envelope = montar_envelope(parametros, iv, chave_sessao,
                               mensagem_cifrada, assinatura)
    salvar_envelope(envelope, caminho_saida)


def abrir_envelope(caminho_envelope, priv_destinatario, pub_remetente,
                   caminho_saida):
    # 1. Lê e valida o JSON.
    dados = ler_envelope(caminho_envelope)
    parametros = dados["parametros"]
    envelope = dados["envelope"]
    codificacao = parametros["codificacao"]

    # 2. Verifica a assinatura ANTES de decifrar qualquer coisa.
    if not verificar_assinatura(envelope["mensagem_cifrada"],
                                envelope["assinatura"], pub_remetente,
                                parametros["hash_assinatura"],
                                codificacao=codificacao):
        raise IntegridadeViolada()

    # 3. Recupera a chave de sessão com a chave privada do destinatário.
    chave_codificada = decifrar_chave_sessao(envelope["chave_sessao"],
                                             priv_destinatario,
                                             parametros["hash_oaep"], codificacao)
    chave = decodificar_chave(chave_codificada, codificacao)
    iv = decodificar(envelope["iv"], codificacao, campo="iv")

    # 4. Decifra a mensagem e grava o resultado.
    texto = decifrar_aes(envelope["mensagem_cifrada"], chave, iv, codificacao)

    with open(caminho_saida, "w", encoding="utf-8", newline="") as arquivo:
        arquivo.write(texto)

    return texto


def perguntar(pergunta, padrao):
    # strip das aspas: aceita caminhos arrastados para o terminal.
    resposta = input(f"{pergunta} [{padrao}]: ").strip().strip("'\"")
    return resposta or padrao


def escolher(pergunta, opcoes):
    while True:
        resposta = perguntar(f"{pergunta} ({' / '.join(opcoes)})", opcoes[0])
        if resposta in opcoes:
            return resposta
        print(f"  Opção inválida. Digite {' ou '.join(opcoes)}.")


def menu_cifrar():
    mensagem = perguntar("Mensagem em claro (UTF-8)", "dados/mensagem.txt")
    pub = perguntar("Chave PÚBLICA do destinatário", "chaves/destinatario_public.pem")
    priv = perguntar("Chave PRIVADA do remetente", "chaves/remetente_private.pem")
    hash_oaep = escolher("Hash do RSA-OAEP", ["SHA-256", "SHA-512"])
    hash_assinatura = escolher("Hash da assinatura", ["SHA-256", "SHA-512"])
    codificacao = escolher("Codificação", ["Base64", "Hex"])
    saida = perguntar("Arquivo do envelope a gerar", "dados/envelope.json")

    criar_envelope(mensagem, pub, priv, saida, hash_oaep, hash_assinatura,
                   codificacao)
    print(f"\n[OK] Envelope criado em: {saida}")


def menu_decifrar():
    envelope = perguntar("Envelope JSON", "dados/envelope.json")
    priv = perguntar("Chave PRIVADA do destinatário", "chaves/destinatario_private.pem")
    pub = perguntar("Chave PÚBLICA do remetente", "chaves/remetente_public.pem")
    saida = perguntar("Arquivo da mensagem decifrada", "dados/mensagem_decifrada.txt")

    texto = abrir_envelope(envelope, priv, pub, saida)
    print(f"\n[OK] Assinatura válida. Mensagem salva em: {saida}")
    print(f"Mensagem: {texto}")


def executar(operacao):
    """Roda uma operação e transforma qualquer falha em mensagem para o usuário."""
    try:
        operacao()
    except IntegridadeViolada:
        print("\n!!! ALERTA DE INTEGRIDADE: assinatura digital INVÁLIDA !!!\n"
              "O envelope foi alterado ou a chave pública não é a do remetente.\n"
              "A abertura foi interrompida e nada foi decifrado.")
    except (ErroAES, ErroEnvelope) as erro:
        print(f"\n[ERRO] {erro}")
    except FileNotFoundError as erro:
        print(f"\n[ERRO] Arquivo não encontrado: {erro.filename}\n"
              "Confira o caminho (relativo à pasta trabalho-seguranca).")
    except UnicodeDecodeError:
        print("\n[ERRO] O arquivo da mensagem não está em UTF-8.")
    except TypeError:
        print("\n[ERRO] A chave privada está protegida por senha. Use uma chave sem senha.")
    except ValueError as erro:
        print(f"\n[ERRO] Chave ou dado inválido: {erro}\n"
              "Confira se as chaves estão em PEM e se não foram trocadas "
              "(pública x privada, remetente x destinatário).")
    except (KeyboardInterrupt, EOFError):
        print("\nOperação cancelada.")
    except Exception as erro:  # nenhuma exceção pode encerrar o programa
        print(f"\n[ERRO] Erro inesperado: {type(erro).__name__}: {erro}")


def main():
    print("=== Envelope Digital Assinado (Encrypt-then-Sign) ===")

    while True:
        print("\n1) Criar envelope (cifrar e assinar)")
        print("2) Abrir envelope (verificar e decifrar)")
        print("0) Sair")
        try:
            opcao = input("Opção: ").strip()
        except (KeyboardInterrupt, EOFError):
            opcao = "0"

        if opcao == "1":
            executar(menu_cifrar)
        elif opcao == "2":
            executar(menu_decifrar)
        elif opcao == "0":
            print("Até logo!")
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    main()
