from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64


def carregar_chave_publica(caminho):
    with open(caminho, "rb") as arquivo:
        return serialization.load_pem_public_key(arquivo.read())


def carregar_chave_privada(caminho):
    with open(caminho, "rb") as arquivo:
        return serialization.load_pem_private_key(
            arquivo.read(),
            password=None
        )


def obter_hash(hash_func):
    if hash_func.upper() == "SHA-256":
        return hashes.SHA256()

    if hash_func.upper() == "SHA-512":
        return hashes.SHA512()

    raise ValueError("Hash não suportado. Use SHA-256 ou SHA-512.")


def codificar(dados, codificacao):
    if codificacao.upper() == "BASE64":
        return base64.b64encode(dados).decode("utf-8")

    if codificacao.upper() == "HEX":
        return dados.hex()

    raise ValueError("Codificação não suportada. Use Base64 ou Hex.")


def decodificar(dados, codificacao):
    if codificacao.upper() == "BASE64":
        return base64.b64decode(dados)

    if codificacao.upper() == "HEX":
        return bytes.fromhex(dados)

    raise ValueError("Codificação não suportada. Use Base64 ou Hex.")


def cifrar_chave_sessao(
    chave_bytes,
    pub_key_pem,
    hash_func,
    codificacao
):
    chave_publica = carregar_chave_publica(pub_key_pem)
    algoritmo_hash = obter_hash(hash_func)

    chave_cifrada = chave_publica.encrypt(
        chave_bytes,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=algoritmo_hash
            ),
            algorithm=algoritmo_hash,
            label=None
        )
    )

    return codificar(chave_cifrada, codificacao)


def decifrar_chave_sessao(
    chave_cifrada_str,
    priv_key_pem,
    hash_func,
    codificacao
):
    chave_privada = carregar_chave_privada(priv_key_pem)
    algoritmo_hash = obter_hash(hash_func)

    chave_cifrada = decodificar(
        chave_cifrada_str,
        codificacao
    )

    chave = chave_privada.decrypt(
        chave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=algoritmo_hash
            ),
            algorithm=algoritmo_hash,
            label=None
        )
    )

    return chave


def assinar(
    ciphertext_str,
    priv_key_pem,
    hash_func,
    codificacao="Base64"
):
    chave_privada = carregar_chave_privada(priv_key_pem)
    algoritmo_hash = obter_hash(hash_func)

    assinatura = chave_privada.sign(
        ciphertext_str.encode("utf-8"),
        padding.PKCS1v15(),
        algoritmo_hash
    )

    return codificar(assinatura, codificacao)


def verificar_assinatura(
    ciphertext_str,
    assinatura_str,
    pub_key_pem,
    hash_func,
    codificacao="Base64"
):
    chave_publica = carregar_chave_publica(pub_key_pem)
    algoritmo_hash = obter_hash(hash_func)

    assinatura = decodificar(
        assinatura_str,
        codificacao
    )

    try:
        chave_publica.verify(
            assinatura,
            ciphertext_str.encode("utf-8"),
            padding.PKCS1v15(),
            algoritmo_hash
        )

        return True

    except Exception:
        return False