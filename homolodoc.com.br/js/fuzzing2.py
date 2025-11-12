# Script para testar endpoints baseado na aplicação médica
import requests
from requests.auth import HTTPBasicAuth

base_url = "https://homolodoc.com.br"
auth = HTTPBasicAuth('morandin', 'devops')

# Endpoints médicos prováveis
medical_endpoints = [
    '/api/pacientes',
    '/api/paciente',
    '/api/consultas',
    '/api/consulta',
    '/api/medicos',
    '/api/medico',
    '/api/documentos',
    '/api/documento',
    '/api/atendimentos',
    '/api/atendimento',
    '/api/prontuarios',
    '/api/prontuario',
    '/api/exames',
    '/api/receitas',
    '/api/laudos',
    '/api/agenda',
    '/api/fila',
    '/api/dashboard',
    '/api/relatorios',
    '/api/config',
    '/api/users',
    '/api/user/profile'
]

for endpoint in medical_endpoints:
    r = requests.get(f"{base_url}{endpoint}", auth=auth, verify=False)
    if r.status_code != 404:
        print(f"[!] {endpoint}: {r.status_code}")
