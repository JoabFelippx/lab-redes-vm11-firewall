# VM11 — Firewall, Roteamento e Auditoria

Módulo de firewall inter-VLAN, roteamento e auditoria da Plataforma Distribuída de Gerenciamento, Monitoramento, Observabilidade e Segurança de Redes — Laboratório de Redes, IFES Campus Guarapari.

Implementado com **nftables** + **Flask** + **Docker**, com autenticação LDAP e interface web de gerenciamento dinâmico de regras.

---

## Estrutura do repositório

```
vm11-firewall/
├── ambiente-teste/   # Ambiente isolado em Docker para validação das regras
├── ambiente-real/    # Deploy na VM OpenStack com subinterfaces VLAN via netplan
├── docs/             # Relatório técnico e roteiro do trabalho
└── README.md
```

## Ambientes

| Ambiente | Descrição | README |
|---|---|---|
| **Teste** | 7 containers simulando as 6 VLANs; nftables dentro do container | [ambiente-teste/README.md](./vm11-firewall/ambiente-teste/README.md) |
| **Real** | VM OpenStack, `network_mode: host`, VLAN via netplan, LDAP integrado | [ambiente-real/README.md](.vm11-firewall/ambiente-real/README.md) |

---

## Políticas de acesso implementadas no ambiente de teste

| Origem | Destino | Política |
|---|---|---|
| USERS | SERVER | HTTP/HTTPS permitido |
| USERS | MGMT | Bloqueado (com log) |
| DMZ | SERVER | HTTPS permitido |
| MONITOR | NETDEV | SNMP permitido |
| MGMT | SERVER | SSH permitido |
| * | * | DROP (padrão) |

## Documentação

| Arquivo | Descrição |
|---|---|
| [docs/relatorio.pdf](./docs/relatorio.pdf) | Relatório técnico individual |
| [docs/trabalho.pdf](./docs/trabalho.pdf) | Descrição do trabalho fornecido pelo professor da matéria |

---

> Trabalho desenvolvido por **Joab Felippe de Souza Lima** — Aluno 11.
