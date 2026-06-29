#!/usr/bin/env python3
"""
VM11 - Gerenciador Web de Firewall (nftables)
Interface gráfica para adicionar, remover e visualizar regras nftables.
Autenticação via LDAP; acesso somente-leitura para visitantes.
"""

import subprocess
import json
import re
import os
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError, LDAPException

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "troque-esta-chave-em-producao")

# ==============================================================================
# CONFIGURAÇÃO
# ==============================================================================

NFTABLES_CONF = "/etc/nftables.conf"

# Configurações gerais do LDAP
LDAP_SERVER   = os.environ.get("LDAP_SERVER",  "ldap://10.0.10.10:389")
LDAP_BASE_DN  = os.environ.get("LDAP_BASE_DN", "dc=labredes,dc=local")
LDAP_OU_USERS = os.environ.get("LDAP_OU_USERS", "ou=Users")
LDAP_OU_GROUPS = os.environ.get("LDAP_OU_GROUPS", "ou=Groups")

# Credenciais administrativas para busca de grupos (trazidas do main.py)
LDAP_ADMIN_DN = os.environ.get(
    "LDAP_ADMIN_DN", 
    "cn=admin,dc=labredes,dc=local"
)
LDAP_ADMIN_PASSWORD = os.environ.get(
    "LDAP_ADMIN_PASSWORD", 
    "admin123"
)

VLANS = {
    "MGMT":    {"subnet": "10.0.10.0/24", "vlan": 10, "cor": "#3b82f6"},
    "SERVER":  {"subnet": "10.0.20.0/24", "vlan": 20, "cor": "#10b981"},
    "DMZ":     {"subnet": "10.0.30.0/24", "vlan": 30, "cor": "#f59e0b"},
    "MONITOR": {"subnet": "10.0.40.0/24", "vlan": 40, "cor": "#8b5cf6"},
    "NETDEV":  {"subnet": "10.0.50.0/24", "vlan": 50, "cor": "#ec4899"},
    "USERS":   {"subnet": "10.0.60.0/24", "vlan": 60, "cor": "#06b6d4"},
}

# ==============================================================================
# AUTENTICAÇÃO (LÓGICA DO MAIN.PY ATUALIZADA)
# ==============================================================================

def ldap_authenticate(username, password):
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        user_dn = f"cn={username},{LDAP_OU_USERS},{LDAP_BASE_DN}"

        # STEP 1: Autentica o usuário verificando a senha (User Bind)
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()  # Desconecta após validar com sucesso

        # STEP 2: Conecta com a conta Admin para buscar os grupos (Admin Bind)
        admin_conn = Connection(server, user=LDAP_ADMIN_DN, password=LDAP_ADMIN_PASSWORD, auto_bind=True)
        
        groups_base = f"{LDAP_OU_GROUPS},{LDAP_BASE_DN}"
        admin_conn.search(
            search_base=groups_base,
            search_filter=f"(member={user_dn})",
            attributes=["cn"]
        )

        # Extrai os nomes limpos dos grupos (ex: ["Administradores", "Usuarios"])
        groups = [entry.cn.value for entry in admin_conn.entries]
        admin_conn.unbind()
        
        return True, groups

    except LDAPBindError:
        return False, "Usuário ou senha incorretos"
    except Exception as e:
        return False, f"Erro no LDAP: {str(e)}"


def is_authenticated() -> bool:
    """Retorna True se o usuário for um administrador (LDAP)."""
    return session.get("role") == "Administradores"


def is_logged_in() -> bool:
    """Retorna True para qualquer sessão ativa."""
    return session.get("role") in ("Administradores", "Usuarios", "visitor", "guest")


def require_auth(f):
    """Decorador: exige administrador. Visitantes ou usuários comuns recebem 403."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_authenticated():
            return jsonify({"ok": False, "error": "Acesso negado. Requer privilégios de Administrador."}), 403
        return f(*args, **kwargs)
    return decorated


def require_login(f):
    """Decorador: exige qualquer sessão ativa (admin ou visitante)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ==============================================================================
# HELPERS nftables
# ==============================================================================

def run_cmd(cmd: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return True, r.stdout.strip()
        return False, r.stderr.strip()
    except FileNotFoundError:
        return False, f"Comando não encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Timeout ao executar comando"


def get_rules_from_nft() -> list[dict]:
    ok, output = run_cmd(["nft", "-a", "list", "chain", "inet", "filter", "forward"])
    if not ok:
        return []

    rules = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("type ") or line.startswith("{") or line.startswith("}"):
            continue

        handle = None
        handle_match = re.search(r"# handle (\d+)", line)
        if handle_match:
            handle = int(handle_match.group(1))
            line_clean = re.sub(r"\s*# handle \d+", "", line).strip()
        else:
            line_clean = line

        rules.append({
            "handle":  handle,
            "raw":     line_clean,
            "comment": _parse_comment(line_clean),
        })

    return rules


def _parse_comment(rule: str) -> str:
    if "counter accept" in rule and "saddr" in rule and "daddr" in rule:
        src   = re.search(r"saddr (\S+)", rule)
        dst   = re.search(r"daddr (\S+)", rule)
        port  = re.search(r"dport \{?([^}]+)\}?", rule)
        proto = "TCP" if "tcp" in rule else "UDP" if "udp" in rule else ""
        parts = []
        if src:
            parts.append(f"{_subnet_to_name(src.group(1))} → {_subnet_to_name(dst.group(1)) if dst else '?'}")
        if proto and port:
            parts.append(f"{proto}/{port.group(1).strip()}")
        parts.append("✅ ACEITO")
        return " | ".join(parts)
    if "counter log" in rule and "drop" in rule:
        src = re.search(r"saddr (\S+)", rule)
        dst = re.search(r"daddr (\S+)", rule)
        if src and dst:
            return f"{_subnet_to_name(src.group(1))} → {_subnet_to_name(dst.group(1))} | ❌ BLOQUEADO"
        return "❌ BLOQUEADO (log)"
    if "ct state established,related accept" in rule:
        return "🔄 Conexões estabelecidas (stateful)"
    if "ip protocol icmp accept" in rule:
        return "🏓 ICMP/Ping liberado"
    if "policy drop" in rule:
        return "🔒 Política padrão: DROP"
    if "counter log" in rule and "DROP_DEFAULT" in rule:
        return "📋 Log de pacotes bloqueados"
    return rule


def _subnet_to_name(subnet: str) -> str:
    for name, data in VLANS.items():
        if subnet == data["subnet"] or subnet.startswith(data["subnet"].split("/")[0].rsplit(".", 1)[0]):
            return name
    return subnet


def build_nft_rule(src: str, dst: str, proto: str, ports: str, action: str) -> str:
    parts = []
    if src:
        parts.append(f"ip saddr {src}")
    if dst:
        parts.append(f"ip daddr {dst}")
    if proto and ports:
        port_list = [p.strip() for p in ports.split(",")]
        port_str  = f"{{ {', '.join(port_list)} }}" if len(port_list) > 1 else port_list[0]
        parts.append(f"{proto} dport {port_str}")
    parts.append("counter")
    if action == "accept":
        parts.append("accept")
    elif action == "drop":
        parts.append('log prefix "DROP_CUSTOM: " drop')
    elif action == "log":
        parts.append('log prefix "LOG_CUSTOM: "')
    return " ".join(parts)


def apply_rule(rule_str: str) -> tuple[bool, str]:
    ok, output = run_cmd(["nft", "-a", "list", "chain", "inet", "filter", "forward"])
    if not ok:
        return False, "Não foi possível listar regras atuais"

    last_drop_handle = None
    for line in output.splitlines():
        if "DROP_DEFAULT" in line or (line.strip().endswith("drop") and "handle" in line):
            m = re.search(r"# handle (\d+)", line)
            if m:
                last_drop_handle = m.group(1)

    if last_drop_handle:
        cmd = ["nft", "insert", "rule", "inet", "filter", "forward",
               "position", last_drop_handle] + rule_str.split()
    else:
        cmd = ["nft", "add", "rule", "inet", "filter", "forward"] + rule_str.split()

    ok, out = run_cmd(cmd)
    if ok:
        save_ruleset()
    return ok, out


def delete_rule(handle: int) -> tuple[bool, str]:
    ok, out = run_cmd(["nft", "delete", "rule", "inet", "filter", "forward", "handle", str(handle)])
    if ok:
        save_ruleset()
    return ok, out


def save_ruleset():
    ok, out = run_cmd(["nft", "list", "ruleset"])
    if ok:
        try:
            with open(NFTABLES_CONF, "w") as f:
                f.write("#!/usr/sbin/nft -f\n\n")
                f.write("flush ruleset\n\n")
                f.write(out)
        except PermissionError:
            pass


def get_counters() -> dict:
    ok, output = run_cmd(["nft", "-a", "list", "chain", "inet", "filter", "forward"])
    if not ok:
        return {}
    counters = {}
    for line in output.splitlines():
        if "counter" in line:
            h    = re.search(r"# handle (\d+)", line)
            pkts = re.search(r"counter packets (\d+) bytes (\d+)", line)
            if h and pkts:
                counters[int(h.group(1))] = {
                    "packets": int(pkts.group(1)),
                    "bytes":   int(pkts.group(2)),
                }
    return counters


# ==============================================================================
# ROTAS DE AUTENTICAÇÃO
# ==============================================================================

@app.route("/login", methods=["GET"])
def login_page():
    if is_logged_in():
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    data     = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username and not password:
        # Entrada como visitante anônimo externo
        session["role"]     = "visitor"
        session["username"] = "visitante"
        return jsonify({"ok": True, "role": "visitor"})

    if not username or not password:
        return jsonify({"ok": False, "error": "Informe usuário e senha."}), 400

    ok, result = ldap_authenticate(username, password)

    if ok:
        groups = result
        print("Grupos obtidos do LDAP para o usuário:", groups)  # Debug útil

        # Validação idêntica ao main.py: busca direta no array de strings puras
        if "Administradores" in groups:
            session["role"] = "Administradores"
        elif "Usuarios" in groups:
            session["role"] = "Usuarios"
        else:
            session["role"] = "guest"

        session["username"] = username
        return jsonify({"ok": True, "role": session["role"]})

    return jsonify({"ok": False, "error": result}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/session", methods=["GET"])
def api_session():
    """Retorna o papel da sessão atual."""
    return jsonify({
        "logged_in": is_logged_in(),
        "role":      session.get("role", "none"),
        "username":  session.get("username", ""),
    })


# ==============================================================================
# ROTAS DA API
# ==============================================================================

@app.route("/api/rules", methods=["GET"])
@require_login
def api_get_rules():
    rules    = get_rules_from_nft()
    counters = get_counters()
    for r in rules:
        if r["handle"] in counters:
            r["packets"] = counters[r["handle"]]["packets"]
            r["bytes"]   = counters[r["handle"]]["bytes"]
        else:
            r["packets"] = None
            r["bytes"]   = None
    return jsonify({"ok": True, "rules": rules})


@app.route("/api/rules", methods=["POST"])
@require_auth
def api_add_rule():
    data   = request.get_json()
    src    = data.get("src", "")
    dst    = data.get("dst", "")
    proto  = data.get("proto", "")
    ports  = data.get("ports", "")
    action = data.get("action", "accept")

    if not src and not dst:
        return jsonify({"ok": False, "error": "Informe pelo menos origem ou destino."}), 400

    rule_str = build_nft_rule(src, dst, proto, ports, action)
    ok, out  = apply_rule(rule_str)
    if ok:
        return jsonify({"ok": True, "rule": rule_str})
    return jsonify({"ok": False, "error": out}), 500


@app.route("/api/rules/<int:handle>", methods=["DELETE"])
@require_auth
def api_delete_rule(handle):
    ok, out = delete_rule(handle)
    if ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": out}), 500


@app.route("/api/vlans", methods=["GET"])
@require_login
def api_get_vlans():
    return jsonify(VLANS)


@app.route("/api/raw", methods=["GET"])
@require_login
def api_raw():
    ok, out = run_cmd(["nft", "list", "ruleset"])
    return jsonify({"ok": ok, "raw": out if ok else ""})


@app.route("/api/status", methods=["GET"])
@require_login
def api_status():
    ok, _  = run_cmd(["nft", "list", "ruleset"])
    rules  = get_rules_from_nft()
    return jsonify({
        "ok":           ok,
        "nft_available": ok,
        "total_rules":  len(rules),
        "timestamp":    datetime.now().isoformat(),
    })


# ==============================================================================
# ROTA PRINCIPAL
# ==============================================================================

@app.route("/")
@require_login
def index():
    role = session.get("role")

    # Apenas o grupo Administradores vê a dashboard de edição completa (index.html)
    if role == "Administradores":
        return render_template("index.html")
    # Membros de "Usuarios" ou outros caem na view de visitante (visitor.html)
    else:
        return render_template("visitor.html")


# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("WEB_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
