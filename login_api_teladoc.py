#!/usr/bin/env python3
import requests
import json
from requests.auth import HTTPBasicAuth

# Desabilitar warnings SSL
import urllib3
urllib3.disable_warnings()

print("[!] TESTANDO API REAL: api.homolodoc.com.br")
print("="*50)

# 1. Teste de login direto na API
login_data = {
    "email": "medico_pentest@teladoc.com",
    "password": "T3l@doc!25"
}

# Variações de campos possíveis
login_variations = [
    {"email": "medico_pentest@teladoc.com", "password": "T3l@doc!25"},
    {"username": "medico_pentest@teladoc.com", "password": "T3l@doc!25"},
    {"user": "medico_pentest@teladoc.com", "pass": "T3l@doc!25"},
    {"login": "medico_pentest@teladoc.com", "senha": "T3l@doc!25"}
]

session = requests.Session()

for data in login_variations:
    print(f"\n[*] Tentando com campos: {list(data.keys())}")
    
    # POST direto na API
    r = session.post(
        "https://api.homolodoc.com.br/Auth/login",
        json=data,
        verify=False
    )
    
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        print(f"[!] LOGIN SUCESSO!")
        print(f"Response: {r.text[:500]}")
        print(f"Cookies: {session.cookies.get_dict()}")
        break
    elif r.status_code != 404:
        print(f"Response: {r.text[:200]}")
