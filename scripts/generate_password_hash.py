import argparse
import base64
import hashlib
import os


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_hash(password, iterations=200000):
    salt = b64url(os.urandom(16))
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${b64url(digest)}"


def main():
    parser = argparse.ArgumentParser(description="Gera hash PBKDF2 para SENTINELA_USERS_JSON.")
    parser.add_argument("password", help="Senha em texto claro. Nao compartilhe nem commite este valor.")
    parser.add_argument("--iterations", type=int, default=200000)
    args = parser.parse_args()
    print(generate_hash(args.password, args.iterations))


if __name__ == "__main__":
    main()
