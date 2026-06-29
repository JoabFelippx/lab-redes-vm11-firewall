# Ambiente de Teste — VM11 Firewall

Ambiente isolado, construído inteiramente com **Docker**, usado para validar o roteamento entre VLANs e a aplicação das regras de firewall **antes** da implantação na infraestrutura real do laboratório.

As 6 VLANs exigidas pela especificação do trabalho são simuladas por redes virtuais Docker, e cada aluno do grupo é representado por um container cliente isolado. Não há switches nesta etapa — essa camada foi abstraída para simplificar a topologia de testes.

---

## Topologia

```
                         ┌────────────┐
                         │  FIREWALL  │
                         └─────┬──────┘
        ┌──────────┬──────────┼──────────┬──────────┬──────────┐
        │          │          │          │          │          │
   cliente     cliente     cliente    cliente     cliente     cliente
    mgmt        server       dmz       monitor      netdev      users
```

O container `vm11-firewall` está conectado a **todas as redes**, com um IP distinto em cada uma. Os demais containers (`nicolaka/netshoot`) representam os módulos dos outros alunos, cada um isolado na sua própria rede Docker.

| Container       | Nome            | Rede             | IP               |
|------------------|-----------------|------------------|------------------|
| `cvm-firewall`   | vm11-firewall   | Todas as redes   | `172.16.X.254`   |
| `cvm-mgmt`       | client-mgmt     | `172.16.10.0/24` | `172.16.10.10`   |
| `cvm-server`     | client-server   | `172.16.20.0/24` | `172.16.20.10`   |
| `cvm-dmz`        | client-dmz      | `172.16.30.0/24` | `172.16.30.10`   |
| `cvm-monitor`    | client-monitor  | `172.16.40.0/24` | `172.16.40.10`   |
| `cvm-netdev`     | client-netdev   | `172.16.50.0/24` | `172.16.50.10`   |
| `cvm-users`      | client-users    | `172.16.60.0/24` | `172.16.60.10`   |

As redes virtuais usam a faixa `172.16.0.0/12`, compatível com o intervalo padrão do Docker para redes bridge. O terceiro octeto de cada rede corresponde ao identificador da VLAN simulada (ex.: `172.16.10.0/24` = VLAN 10 / MGMT).

---

## Pré-requisitos

- Docker + Docker Compose instalados
- Nenhuma dependência externa (LDAP, switches, etc.) — este ambiente é 100% autocontido

---

## Estrutura de arquivos

```
ambiente-teste/
├── docker-compose.yaml
└── firewall/
    ├── Dockerfile          # base ubuntu:22.04 + nftables, tcpdump, netcat, python3/flask
    ├── nftables.conf       # regras de teste, carregadas no CMD do container
    ├── app.py              # backend Flask
    └── templates/
        ├── login.html
        ├── index.html
        └── visitor.html
```

> Diferente do ambiente real, aqui o container `vm11-firewall` é **autossuficiente**: ele mesmo instala o `nftables` e carrega o `/etc/nftables.conf` via `CMD` do Dockerfile, já que não há um host físico com `nft` disponível por fora do container.

---

## Subindo o ambiente

```bash
cd ambiente-teste
docker compose up -d --build
```

> Em ambientes com docker-compose v1 (legado), use `docker-compose up -d --build` com hífen.

Verifique se os 7 containers subiram:

```bash
docker ps
```

---

## Regras de firewall (teste)

A política padrão é **DROP** — todo tráfego não explicitamente autorizado é descartado. Regras iniciais:

- **Conexões estabelecidas**: `ct state established,related accept` (stateful bidirecional)
- **ICMP**: liberado em todas as direções (ping para diagnóstico)
- **USERS → SERVER** (TCP 80/443): `172.16.60.0/24` → `172.16.20.0/24`
- **USERS → MGMT** (bloqueado, com log): tentativas de `172.16.60.0/24` → `172.16.10.0/24` são registradas com o prefixo `DROP_USERS_MGMT:` e descartadas
- **DMZ → SERVER** (TCP 443 apenas): `172.16.30.0/24` → `172.16.20.0/24`
- **MONITOR → NETDEV** (UDP 161 / SNMP): `172.16.40.0/24` → `172.16.50.0/24`
- **MGMT → SERVER** (TCP 22 / SSH): `172.16.10.0/24` → `172.16.20.0/24`
- **Regra padrão**: todo o restante é registrado com o prefixo `DROP_DEFAULT:` e descartado

---

## Roteiro de testes

### 1. Verificar roteamento no container firewall

```bash
docker exec vm11-firewall ip route show
```

Saída esperada: rotas para as 6 redes (`172.16.10.0/24` a `172.16.60.0/24`), cada uma associada a uma interface bridge distinta.

### 2. Listar regras com handles

```bash
docker exec vm11-firewall nft -a list chain inet filter forward
```

Os `handles` exibidos são os identificadores numéricos usados pela interface web para remoção individual de regras.

### 3. Teste de conectividade (ICMP)

```bash
docker exec client-users ping -c 3 172.16.20.10
```

Esperado: 3 pacotes transmitidos e recebidos, sem perdas.

### 4. Teste de porta permitida (USERS → SERVER, TCP 80)

```bash
docker exec client-users nc -zv 172.16.20.10 80
```

Esperado: conexão bem-sucedida (`succeeded!`).

### 5. Teste de porta bloqueada (USERS → MGMT) com visibilidade do contador

Em um terminal, monitore o contador da regra de DROP em tempo real:

```bash
watch -n1 "docker exec vm11-firewall nft list chain inet filter forward | grep DROP_USERS_MGMT"
```

Em outro terminal, dispare a tentativa bloqueada:

```bash
docker exec client-users nc -zv 172.16.10.10 80
```

Esperado: `nc` retorna imediatamente sem conectar, e o contador da regra `DROP_USERS_MGMT` incrementa.

### 6. Captura de pacotes com tcpdump

```bash
docker exec vm11-firewall tcpdump -i any -n host 172.16.60.10
```

Gere tráfego de teste a partir de `client-users` em outro terminal e observe os pacotes capturados (SYN / SYN-ACK no caso de tráfego permitido).

### 7. Monitoramento geral dos contadores

```bash
watch -n 1 "docker exec vm11-firewall nft list chain inet filter forward"
```

---

## Interface web

Acesse: `http://localhost:5000`

Neste ambiente, a interface não está integrada a um servidor LDAP real — use o modo **"Entrar como visitante"** para acesso de leitura, ou ajuste `app.py` caso queira simular autenticação local.

### Funcionalidades

- Listagem de regras ativas (cadeia `forward`, com contadores de pacotes/bytes)
- Adição de regras (origem, destino, protocolo, porta, ação)
- Remoção de regras pelo `handle`
- Visualização do ruleset completo (`nft list ruleset`)
- Indicador de status (disponibilidade do nftables, atualizado a cada 10s)

### Endpoints da API REST

| Método | Rota                  | Descrição                       |
|--------|-----------------------|----------------------------------|
| GET    | `/api/rules`          | Lista regras com contadores     |
| POST   | `/api/rules`          | Adiciona nova regra             |
| DELETE | `/api/rules/<handle>` | Remove regra pelo handle        |
| GET    | `/api/vlans`          | Lista as VLANs configuradas     |
| GET    | `/api/raw`            | Exibe o ruleset completo        |
| GET    | `/api/status`         | Verifica status do nftables     |

---

## Diferenças em relação ao ambiente real

| Aspecto              | Ambiente de teste                          | Ambiente real (`../ambiente-real`)         |
|-----------------------|---------------------------------------------|---------------------------------------------|
| Infraestrutura        | Containers Docker simulando VLANs           | VM OpenStack + VLANs reais via netplan      |
| `nftables`             | Instalado **dentro** do container           | Usa o `nft` do **host** (kernel da VM)      |
| `network_mode`         | Bridge (padrão Docker)                      | `host` + `privileged: true`                 |
| Autenticação           | Não integrada a LDAP                        | Integrada ao LDAP (`10.0.10.10:389`)        |
| Proteção contra flood  | Não aplicável                                | Rate limit no log + logrotate/journald      |

Veja `../ambiente-real/README.md` para os detalhes do deploy em produção.