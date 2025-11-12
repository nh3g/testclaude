#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import re
import json

# Script para fazer login completo
session = requests.Session()

# 1. Basic Auth
print("[+] Fazendo Basic Auth...")
r = session.get("https://homolodoc.com.br", 
                auth=HTTPBasicAuth('morandin', 'devops'), 
                verify=False)
print(f"Status: {r.status_code}")

# 2. Analisar o HTML/JS para encontrar endpoint de login
print("\n[+] Procurando endpoint de login no JS...")
r = session.get("https://homolodoc.com.br/js/app.faa9c175.js",
                auth=HTTPBasicAuth('morandin', 'devops'),
                verify=False)

# Procurar por rotas de login
login_patterns = [
    r'["\'](/api/login)["\']',
    r'["\'](/auth/login)["\']',
    r'["\'](/login)["\']',
    r'["\'](/api/auth)["\']'
]

for pattern in login_patterns:
    matches = re.findall(pattern, r.text)
    if matches:
        print(f"Endpoint encontrado: {matches}")

# 3. Tentar login na aplicação
login_endpoints = [
    '/api/login',
    '/api/auth/login',
    '/auth/login',
    '/login',
    '/api/authenticate'
]

login_data = {
    'email': 'medico_pentest@teladoc.com',
    'senha': 'T3l@doc!25'
}

# Tente também com diferentes nomes de campos
login_variations = [
    {'email': 'medico_pentest@teladoc.com', 'senha': 'T3l@doc!25'},
    {'email': 'medico_pentest@teladoc.com', 'password': 'T3l@doc!25'},
    {'username': 'medico_pentest@teladoc.com', 'password': 'T3l@doc!25'},
    {'user': 'medico_pentest@teladoc.com', 'pass': 'T3l@doc!25'}
]

for endpoint in login_endpoints:
    for data in login_variations:
        print(f"\n[*] Tentando {endpoint} com {list(data.keys())}...")
        try:
            # Tente POST
            r = session.post(f"https://homolodoc.com.br{endpoint}",
                           json=data,
                           auth=HTTPBasicAuth('morandin', 'devops'),
                           verify=False)
            print(f"POST Status: {r.status_code}")
            if r.status_code == 200:
                print(f"[!] SUCESSO! Endpoint: {endpoint}")
                print(f"Response: {r.text[:200]}")
                break
        except:
            pass
