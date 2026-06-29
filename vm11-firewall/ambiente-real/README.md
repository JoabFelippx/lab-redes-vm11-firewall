# VM11 — Firewall Manager

Gerenciador web de regras **nftables** com autenticação LDAP, interface dark-theme e suporte a VLANs por subinterface. Implantado via Docker com `network_mode: host`.

---

## Sumário

1. [Visão geral](#visão-geral)
2. [Pré-requisitos](#pré-requisitos)
3. [Configuração das VLANs](#configuração-das-vlans)
4. [Configuração do nftables](#configuração-do-nftables)
5. [Deploy com Docker](#deploy-com-docker)
6. [Verificação](#verificação)
7. [Acesso e autenticação](#acesso-e-autenticação)
8. [Dependências externas](#dependências-externas)
9. [Estrutura dos arquivos](#estrutura-dos-arquivos)
10. [Variáveis de ambiente](#variáveis-de-ambiente)

---

## Visão geral

```
┌─────────────────────────────────────────────────────┐
│                   VM11 (Ubuntu 22.04)               │
│                                                     │
│  ens7 ──┬── ens7.10  (MGMT    10.0.10.1/24)        │
│          ├── ens7.20  (SERVER  10.0.20.1/24)        │
│          ├── ens7.30  (DMZ     10.0.30.1/24)        │
│          ├── ens7.40  (MONITOR 10.0.40.1/24)        │
│          ├── ens7.50  (NETDEV  10.0.50.1/24)        │
│          └── ens7.60  (USERS   10.0.60.1/24)        │
│                                                     │
│  ┌──────────────────────────────────┐               │
│  │  Docker (network_mode: host)     │               │
│  │  container: vm11-firewall        │               │
│  │  Flask :5000  +  nftables (nft)  │               │
│  └──────────────────────────────────┘               │
└─────────────────────────────────────────────────────┘
```

O container compartilha as interfaces e o netfilter do host via `network_mode: host` e `privileged: true`, permitindo executar comandos `nft` diretamente no kernel da VM.

---

## Pré-requisitos

- Ubuntu 22.04 (limpo)
- Acesso root / sudo
- Interface física `ens7` disponível
- Conectividade com o servidor LDAP em `10.0.10.10:389` (para login com usuário/senha)

---

## Configuração das VLANs
```bash
sudo nano /etc/netplan/99-vlans.yaml
```

```yaml
network:
  version: 2
  ethernets:
    ens7:
      dhcp4: false
  vlans:
    ens7.10:
      id: 10
      link: ens7
      addresses: [10.0.10.1/24]
    ens7.20:
      id: 20
      link: ens7
      addresses: [10.0.20.1/24]
    ens7.30:
      id: 30
      link: ens7
      addresses: [10.0.30.1/24]
    ens7.40:
      id: 40
      link: ens7
      addresses: [10.0.40.1/24]
    ens7.50:
      id: 50
      link: ens7
      addresses: [10.0.50.1/24]
    ens7.60:
      id: 60
      link: ens7
      addresses: [10.0.60.1/24]
```
```bash
sudo netplan apply
```


# Habilita IP forwarding
```bash
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
```

---

## Configuração do nftables

O container faz bind mount de `/etc/nftables.conf`. O arquivo precisa existir no host antes do `docker compose up`.

```bash
sudo nano /etc/nftables.conf
```

Conteúdo:

```
#!/usr/sbin/nft -f

# Cria as tabelas se não existirem, depois limpa só elas
# (preserva tabelas de outros serviços, ex: Docker)
table inet filter { }
flush table inet filter
table ip nat_custom { }
flush table ip nat_custom

# 1. TABELA DE FILTRAGEM (FORWARD)
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Mantém conexões já estabelecidas ativas
        ct state established,related accept
        ip protocol icmp accept

        # Permite tráfego dos containers Docker
        iifname "docker0" accept
        iifname "br-*" accept

        # VLANs (ens7.*) podem sair pela interface de internet (ens3)
        iifname "ens7*" oifname "ens3" accept

        # Exemplos de regras internas
        ip daddr 10.0.20.0/24 tcp dport { 80, 443 } counter accept
        ip daddr 10.0.10.10   tcp dport { 389, 636 } counter accept

        counter log prefix "DROP_DEFAULT: " drop
    }

    chain input  { type filter hook input  priority 0; policy accept; }
    chain output { type filter hook output priority 0; policy accept; }
}

# 2. TABELA DE NAT CUSTOMIZADA (MASCARAMENTO)
table ip nat_custom {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        # Mascaramento: tudo que sai pela ens3 usa o IP da VM
        oifname "ens3" masquerade
    }
}
```


Aplique e verifique:

```bash
sudo nft -f /etc/nftables.conf
sudo nft list ruleset   # deve mostrar inet filter e ip nat_custom
```

---

## Deploy com Docker

### 1. Instalar Docker

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

### 2. Preparar o diretório do projeto

```bash
mkdir ~/vm11 && cd ~/vm11
# Copie o docker-compose.yaml para este diretório
```

`docker-compose.yaml`:

```yaml
version: '3.8'
services:
  firewall:
    image: joabfsl/firewall-vm11-tralho:v1
    container_name: vm11-firewall
    network_mode: host
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped
    volumes:
      - /etc/nftables.conf:/etc/nftables.conf
    environment:
      - LDAP_SERVER=ldap://10.0.10.10:389
      - LDAP_BASE_DN=dc=labredes,dc=local
      - LDAP_OU_USERS=ou=Users
      - LDAP_OU_GROUPS=ou=Groups
      - LDAP_ADMIN_DN=cn=admin,dc=labredes,dc=local
      - LDAP_ADMIN_PASSWORD=admin123
      - SECRET_KEY=troque-esta-chave-em-producao
      - WEB_PORT=5000
```

### 3. Subir o container

```bash
docker compose up -d
```

> Em ambientes com docker-compose v1 (legado), use `docker-compose up -d` com hífen.

---

## Verificação

```bash
# Container rodando?
docker ps

# Logs do container
docker logs vm11-firewall

# Interface web respondendo?
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/login
# Esperado: 200

# nftables acessível de dentro do container?
docker exec vm11-firewall nft list ruleset
```

---

## Acesso e autenticação

Acesse pelo navegador: `http://<IP-DA-VM>:5000`

| Perfil | Como entrar | Permissões |
|---|---|---|
| **Administradores** | Usuário LDAP no grupo `Administradores` | Adicionar, remover e visualizar regras |
| **Usuarios** | Usuário LDAP no grupo `Usuarios` | Somente visualização (visitor.html) |
| **Visitante** | Botão "Entrar como visitante" (sem credenciais) | Somente visualização (visitor.html) |

O login autentica em duas etapas:
1. **User bind** — valida usuário/senha no LDAP
2. **Admin bind** — busca os grupos do usuário para determinar o papel

---

## Dependências externas

| Serviço | Endereço | Impacto se indisponível |
|---|---|---|
| Servidor LDAP | `ldap://10.0.10.10:389` | Login com usuário/senha falha; acesso visitante continua funcionando |
| nftables (kernel) | Host da VM | Já presente no Ubuntu 22.04; necessário para gerenciar regras |

---

## Estrutura dos arquivos

```
vm11/
├── docker-compose.yaml   # definição do serviço Docker
├── setup_vlans.sh        # cria subinterfaces VLAN e habilita forwarding
└── README.md             # este arquivo

# Dentro da imagem joabfsl/firewall-vm11-tralho:v1:
/app/
├── app.py                # backend Flask (autenticação LDAP + API nftables)
└── templates/
    ├── login.html        # tela de login
    ├── index.html        # dashboard admin (adicionar/remover regras)
    └── visitor.html      # dashboard somente-leitura
```

---

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `LDAP_SERVER` | `ldap://10.0.10.10:389` | Endereço do servidor LDAP |
| `LDAP_BASE_DN` | `dc=labredes,dc=local` | Base DN do diretório |
| `LDAP_OU_USERS` | `ou=Users` | OU onde os usuários estão |
| `LDAP_OU_GROUPS` | `ou=Groups` | OU onde os grupos estão |
| `LDAP_ADMIN_DN` | `cn=admin,dc=labredes,dc=local` | DN da conta de serviço para busca de grupos |
| `LDAP_ADMIN_PASSWORD` | `admin123` | Senha da conta de serviço |
| `SECRET_KEY` | `troque-esta-chave-em-producao` | Chave de sessão Flask |
| `WEB_PORT` | `5000` | Porta HTTP da aplicação |

---
