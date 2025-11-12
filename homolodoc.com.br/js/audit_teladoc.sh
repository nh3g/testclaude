#!/usr/bin/env bash
# audit_teladoc.sh — executa todas as coletas e consolida em dump_js_teladoc.txt

set -Eeuo pipefail

# === Config ===
BASE_DIR="$HOME/teladoc/homolodoc.com.br/js/homolodoc.com.br/js"
JSFILE="app.faa9c175.js"
DOMAIN="homolodoc.com.br"
CREDS="morandin:devops"
OUT="dump_js_teladoc.txt"

# === Helpers ===
: > "$OUT"
hdr(){ echo -e "\n===== $* =====" | tee -a "$OUT"; }
run(){
  echo -e "\n$ $*" | tee -a "$OUT"
  bash -lc "$*" 2>&1 | tee -a "$OUT"
}

hdr "Contexto"
run "date -Is"
run "echo BASE_DIR=$BASE_DIR"
run "echo JSFILE=$JSFILE"
run "echo DOMAIN=$DOMAIN"
run "echo CREDS='(definido)'"

hdr "Entrando no diretório dos JS baixados"
run "cd \"$BASE_DIR\" && pwd"
[[ -f "$BASE_DIR/$JSFILE" ]] || { echo "ERRO: $JSFILE não encontrado." | tee -a "$OUT"; exit 1; }

hdr "Procura por endpoints de API"
run "grep -oE 'api/[a-zA-Z0-9/_-]+' '$JSFILE' | sort -u || true"
run "grep -oE '/api/[a-zA-Z0-9/_-]+' '$JSFILE' | sort -u || true"
run "grep -oE \"fetch\\(['\\\"]([^'\\\"]+)\" '$JSFILE' | sort -u || true"
run "grep -oE \"axios\\.[a-z]+\\(['\\\"]([^'\\\"]+)\" '$JSFILE' | sort -u || true"

hdr "Procura por credenciais e tokens"
run "grep -ni 'password' '$JSFILE' || true"
run "grep -ni 'secret'   '$JSFILE' || true"
run "grep -ni 'token'    '$JSFILE' || true"
run "grep -ni 'api_key'  '$JSFILE' || true"
run "grep -ni 'apikey'   '$JSFILE' || true"

hdr "Procura por URLs e endpoints"
run "grep -oE 'https?://[a-zA-Z0-9./?=_-]*' '$JSFILE' | sort -u || true"

hdr "Instalação/checagem do js-beautify (se necessário)"
if ! command -v js-beautify >/dev/null 2>&1; then
  run "npm -v || (apt update && apt install -y npm)"
  run "npm install -g js-beautify"
fi
run "js-beautify --version || true"

hdr "Beautify do JavaScript"
run "js-beautify '$JSFILE' > app_beautified.js && ls -lh app_beautified.js"

hdr "Testes (Nikto) - HEAD nos arquivos apontados"
for file in dump.cer homolodoc.pem backup.tar database.tgz; do
  echo -e "\n-- Testing: $file" | tee -a "$OUT"
  run "curl -sS -u \"$CREDS\" -I \"https://$DOMAIN/$file\" || true"
done

hdr "Testes específicos para arquivos de backup"
run "curl -sS -u \"$CREDS\" -fL \"https://$DOMAIN/backup.tar\"   -o backup.tar   || true"
run "curl -sS -u \"$CREDS\" -fL \"https://$DOMAIN/database.tgz\" -o database.tgz || true"
run "curl -sS -u \"$CREDS\" -I  \"https://$DOMAIN/.git/HEAD\" || true"
run "curl -sS -u \"$CREDS\" -I  \"https://$DOMAIN/.env\"      || true"
run "ls -lh backup.tar database.tgz 2>/dev/null || true"

hdr "Rotas do Vue Router e componentes"
run "grep -o 'path:\"[^\"]*\"' '$JSFILE' | sort -u || true"
run "grep -o 'component:' '$JSFILE' | sort -u || true"

hdr "Beautify e análise (garantia)"
run "cd \"$BASE_DIR\" && npm install -g js-beautify >/dev/null 2>&1 || true"
run "js-beautify '$JSFILE' > app_beautified.js"

hdr "Strings interessantes"
run "strings '$JSFILE' | grep -E '(api|endpoint|url|http|token|auth|login|admin)' | sort -u > interesting_strings.txt"
run "wc -l interesting_strings.txt && head -n 25 interesting_strings.txt"

hdr "Comentários deixados pelos devs"
run "grep -E '//|/\\*' app_beautified.js > comments.txt || true"
run "wc -l comments.txt && head -n 25 comments.txt || true"

hdr "Chamadas HTTP e uso de localStorage"
run "grep -o '\\$http\\.' '$JSFILE' | sort -u || true"
run "grep -o 'localStorage\\.' '$JSFILE' | sort -u || true"

hdr "Concluído"
run "echo 'Saída consolidada em: $(realpath \"$OUT\")'"
