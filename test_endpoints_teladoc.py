#!/usr/bin/env python3
# Teste quais endpoints funcionam sem auth
import requests

# Endpoints que geralmente são públicos
public_endpoints = [
    "/state/list",
    "/civilStates",
    "/scholarships", 
    "/themes",
    "/deficiencies",
    "/diseases/list",
    "/get/settings",
    "/professional/council/list"
]

base_url = "https://api.homolodoc.com.br"

for endpoint in public_endpoints:
    r = requests.get(base_url + endpoint, verify=False)
    if r.status_code == 200:
        print(f"[!] PÚBLICO: {endpoint}")
        print(f"Data: {r.text[:200]}\n")
