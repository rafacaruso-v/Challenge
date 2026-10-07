# ASPM Platform

Plataforma de **Application Security Posture Management (ASPM)** que centraliza
a descoberta de ativos, a execução de scanners de segurança (SAST, DAST, SCA,
IaC, CSPM, Secrets, DLP) e a análise dos achados por IA (Google Gemini),
consolidando tudo em um único painel de risco por aplicação/negócio.

Membros do grupo:

RM571380 = Rafael Caruso Vasconcellos
RM573671 = Guilherme Isidoro Da Silva Monteiro
RM570214 = João Pedro Marin de Oliveira


## Índice

- [Conceito central: Ativos e Componentes](#conceito-central-ativos-e-componentes)
- [Principais capacidades](#principais-capacidades)
- [Arquitetura e fluxo de uma análise](#arquitetura-e-fluxo-de-uma-análise)
- [Infraestrutura (Docker)](#infraestrutura-docker)
- [Segurança da própria plataforma](#segurança-da-própria-plataforma)
- [Stack técnica](#stack-técnica)
- [Estrutura de pastas e arquivos](#estrutura-de-pastas-e-arquivos)

---

## Conceito central: Ativos e Componentes

O sistema organiza tudo em torno de duas entidades:

- **Ativo**: representa a aplicação/negócio (ex: "App de Pagamentos").
- **Componente**: cada fonte de análise vinculada a um Ativo — um
  **Repositório** de código, uma **API** ou **Aplicação** em execução, ou uma
  conta **Cloud** (AWS).

Um Ativo pode ter vários Componentes. Isso permite que achados de fontes
diferentes (o código-fonte, a infraestrutura AWS que o hospeda, a API exposta)
fiquem correlacionados sob o mesmo contexto de negócio. O score de risco do
Ativo segue a regra **"highest watermark"**: reflete sempre o componente mais
crítico, nunca uma média otimista — porque um atacante só precisa de um ponto
fraco para comprometer a aplicação inteira.

## Principais capacidades

### Scanners de segurança
- **SAST** — Semgrep, com ruleset customizado (`Regras/regras_semgrep.yaml`,
  8 regras próprias desenhadas para reduzir falso positivo específico do
  stack Flask) combinado com rulesets públicos (OWASP Top 10, CWE Top 25,
  Python, Flask, Java, JavaScript, secrets).
- **DAST** — OWASP ZAP, com Spider + Ajax Spider (para JavaScript) + Active
  Scan para tipo "Aplicação"; importação automática de especificação
  OpenAPI/Swagger para tipo "API".
- **SCA** — Trivy, escaneando vulnerabilidades de dependências, segredos e
  misconfigurações do filesystem do repositório.
- **IaC** — Checkov, com detecção automática de Terraform e/ou CloudFormation
  no repositório.
- **Secrets** — Gitleaks, sempre retornando o segredo já mascarado (nunca o
  valor real, em nenhum relatório ou log).
- **DLP** — scanner próprio (CPF, CNPJ, cartão de crédito, e-mail), com
  validação matemática real (dígito verificador de CPF/CNPJ, algoritmo de
  Luhn para cartão) para reduzir drasticamente falsos positivos em
  comparação com um regex ingênuo.
- **CSPM** — descoberta e checks de postura AWS (S3, IAM, Security Groups,
  política de senha e MFA da conta root) via AssumeRole.

### Inventário automatizado de Cloud
Além dos achados de segurança, a plataforma lista **todos** os recursos
existentes na conta AWS conectada (não só os com problema) — buckets S3,
usuários IAM, Security Groups, instâncias EC2 — reaproveitando a mesma sessão
AssumeRole usada pelo CSPM.

### Análise por IA (Google Gemini)
Um único prompt consolidado recebe os achados de todos os scanners
aplicáveis ao tipo de componente, e:
- Classifica cada achado por criticidade usando a matriz CVSS v3.1 como
  referência.
- Aplica uma **regra de consolidação semântica**: se dois scanners
  diferentes (ex: Semgrep e Gitleaks) detectam a mesma causa raiz, reporta
  uma única vez na categoria mais específica, evitando inflar a contagem
  de risco artificialmente.
- Tem **proteção ativa contra prompt injection**: um filtro de regex
  sanitiza o texto dos achados antes de entrar no prompt, e o próprio
  prompt instrui o modelo a tratar os dados dos scanners como dado puro,
  nunca como instrução — mesmo que o conteúdo pareça conter comandos.
- Gera o relatório executivo (análise + plano de ação) em português.

### Redução de falsos positivos por Machine Learning
Modelos próprios (`scikit-learn`, treinados em dataset sintético — entropia
de token, palavras que indicam ambiente de teste/produção, segmentos de
caminho) filtram achados de alta probabilidade de falso positivo em SAST,
SCA, DAST, CSPM e IaC **antes** de chegarem à IA. Secrets e DLP ficam
deliberadamente fora desse filtro — a sensibilidade desses dados torna
arriscado descartar automaticamente um achado real por engano. Todo achado
descartado continua visível (nunca é apagado silenciosamente): aparece na
aba "Falsos Positivos" com a probabilidade calculada, para auditoria.

### Sugestão de agrupamento de Ativos por IA
A cada re-scan, uma segunda chamada ao Gemini analisa os identificadores de
todos os componentes Repositório/Cloud do usuário (URL do repositório, Role
ARN) e identifica quais provavelmente pertencem à mesma aplicação — por
semelhança de nome específica, não por termos genéricos como "prod" ou
"api". As sugestões ficam pendentes no banco e aparecem como um banner no
Dashboard; **nenhuma ação é aplicada automaticamente**, sempre exige
confirmação manual. Ao aceitar, Ativos de origem que ficam sem nenhum
componente são removidos automaticamente.

### Detecção de anomalias
Monitora a evolução do score de cada componente ao longo do tempo usando
Isolation Forest (com regra simples de fallback quando ainda não há
histórico suficiente), alertando sobre variações de risco fora do padrão
esperado.

### Chatbot de segurança
Assistente conversacional embarcado, que responde sobre ativos, alertas,
CVEs recentes (consultando a API pública da NVD) e gera resumos executivos
sob demanda — sempre fundamentado nos dados reais da plataforma, nunca
inventando informação. Suporta anexos (imagem, PDF, texto, código).

### Integração CI/CD
Dois fluxos de GitHub Actions:
- **Em Pull Requests**: roda Semgrep, Trivy e Checkov contra o repositório,
  gera um resumo executivo via Gemini e posta um comentário formatado no
  PR — com gate de bloqueio de merge se houver achado Crítico/Alto.
- **Ao mergear na main**: roda os mesmos scanners mais Gitleaks e o
  scanner de DLP e envia tudo para o endpoint `/webhook/pr-scan`, que cria ou
  atualiza o componente automaticamente — sem depender do Gemini, em um
  fluxo determinístico de bucketização por severidade.


### Relatórios executivos em PDF
Capa com metadados e ferramentas utilizadas, seção de vulnerabilidades
separada por categoria, relatório narrativo da IA, e uma declaração de
conformidade calculada a partir do estado **real** da própria plataforma
— mapeada para controles SOC2 e ISO 27001.

### Re-scan automático agendado
Thread em background dispara a reanálise de todos os componentes no
intervalo configurado (30 minutos a 24 horas), consolidando os resultados
em um único alerta resumido por ciclo, verificando disponibilidade e
anomalias, e disparando a geração de sugestões de agrupamento ao final.

---

## Arquitetura e fluxo de uma análise

```
Usuário → Nginx (proxy reverso) → Streamlit (app.py)
                                        │
                   ┌────────────────────┼────────────────────┐
                   ▼                    ▼                    ▼
             Scanners/*          CloudAws/cspm.py      MachineLearning/
         (Semgrep, Trivy,       (AssumeRole via hub,    false_positive.py
          Checkov, Gitleaks,     checks S3/IAM/EC2,     (filtra achados
          DLP, ZAP)              inventário completo)    de baixa confiança)
                   │                    │                    │
                   └────────────────────┼────────────────────┘
                                        ▼
                              LLMs/gemini.py
                    (classifica, consolida, gera relatório)
                                        │
                                        ▼
                              Database/db.py (SQLite)
                                        │
                   ┌────────────────────┼────────────────────┐
                   ▼                    ▼                    ▼
          gerar_pdf.py           LLMs/sugestoes.py     Monitoring/monitor.py
        (relatório PDF)       (agrupamento por IA)      (re-scan agendado)
```

O fluxo de CI/CD (`.github/`) é paralelo a esse: roda **fora** da
plataforma, no runner do GitHub Actions, e só se conecta a ela no final,
via o webhook (`API/webhook.py`), que grava direto no mesmo banco SQLite.

---

## Infraestrutura (Docker)

A plataforma roda inteiramente via Docker Compose, com 5 serviços:

| Serviço | Função |
|---|---|
| `aspm` | Interface Streamlit (`app.py`), inicia também o webhook e o túnel ngrok em background |
| `webhook` | API FastAPI (`API/webhook.py`), recebe os resultados do fluxo de CI/CD |
| `zap` | Daemon do OWASP ZAP, usado pelo scanner DAST |
| `ngrok` | Túnel com domínio fixo, expõe o webhook para o GitHub Actions conseguir alcançá-lo |
| `nginx` | Proxy reverso, único ponto de entrada externo da interface |

O Streamlit **nunca é exposto diretamente** — sua porta (`8501`) só existe
dentro da rede Docker interna (`aspm-network`); todo acesso externo passa
obrigatoriamente pelo Nginx.

O banco SQLite (`aspm.db`) é montado como volume e compartilhado entre
`aspm` e `webhook`, garantindo que os dois leiam e escrevam no mesmo estado.


## Segurança da própria plataforma

Além de ser uma ferramenta de segurança, o projeto aplica boas práticas de
segurança em si mesmo:

- **Autenticação em duas etapas**: senha (hash bcrypt) + código MFA de 6
  dígitos enviado por e-mail, com expiração de 10 minutos e limite de
  tentativas.
- **Sessão via cookie assinado** com HMAC-SHA256 (não depende de biblioteca
  JWT externa).
- **RBAC simples**: roles `admin`/`usuario`, com proteção para nunca
  remover o último administrador da plataforma.
- **Nginx com CSP restritivo**, headers de segurança completos
  (`X-Frame-Options`, `X-Content-Type-Options`, `Cross-Origin-*-Policy`,
  `Referrer-Policy`), rate limiting por IP, limite de tamanho de upload
  configurado explicitamente, e ocultação da versão do servidor
  (`server_tokens off` + remoção do header `Server`).
- **AssumeRole com ExternalId** para acesso à conta AWS do cliente — nunca
  armazena credencial permanente, apenas assume uma Role temporária
  validando um ExternalId compartilhado (proteção contra o ataque de
  "confused deputy").
- **Mascaramento obrigatório** de qualquer credencial ou dado sensível
  encontrado (Secrets, DLP) antes de aparecer em qualquer relatório, log
  ou prompt enviado à IA.
- **Checksum SHA256** na instalação de binários externos (Gitleaks) tanto
  localmente quanto nos workflows de CI/CD, evitando instalação via
  `curl | sh` sem verificação.

---

## Stack técnica

Streamlit (interface) · FastAPI (webhook) · SQLite (banco) · scikit-learn
(modelos de ML) · Google Gemini (análise por IA) · boto3 (AWS) · Docker
Compose (orquestração) · Nginx (proxy reverso) · OWASP ZAP, Semgrep, Trivy,
Checkov, Gitleaks (scanners externos).

---

## Estrutura de pastas e arquivos

```
Challenge/
├── .github/
├── .streamlit/
├── .zap/
├── API/
├── Auth/
├── CloudAws/
├── Compliance/
├── Database/
├── LLMs/
├── MachineLearning/
├── Monitoring/
├── NLP/
├── Regras/
├── Scanners/
├── app.py
├── gerar_pdf.py
├── proxy.conf
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

### `.github/`
Pipeline de integração contínua e o fluxo de CI/CD do produto.

- **`scripts/aspm_pr_scan.py`** — roda a cada Pull Request: Semgrep, Trivy,
  Checkov, resumo via Gemini e comentário no PR. Falha o job (exit code 1)
  se houver achado Crítico/Alto, funcionando como gate de merge.
- **`scripts/aspm_ps_scan.py`** — roda ao mergear na main: reaproveita as
  funções de scan acima, adiciona Gitleaks e DLP próprios (self-contidos,
  sem acesso aos pacotes internos da plataforma), e envia tudo para o
  webhook.
- **`workflows/aspm_pr_scan.yaml`** / **`workflows/aspm_ps_scan.yml`** —
  definições do GitHub Actions para os dois scripts acima.
- **`workflows/security.yml`** — pipeline de segurança do próprio
  repositório: SAST, Secrets Scan, análise de segurança do próprio
  pipeline (Zizmor), SCA com gate HIGH/CRITICAL, SBOM, scan de imagem
  Docker, DAST contra a aplicação rodando atrás do Nginx, e um resumo
  final consolidado.
- **`dependabot.yml`** — atualização semanal de dependências (GitHub
  Actions e Docker), agrupada por ecossistema.

### `.streamlit/`
- **`config.toml`** — desativa telemetria de uso do Streamlit.

### `.zap/`
- **`rules.tsv`** — exceções documentadas do ZAP Baseline Scan usado no
  CI/CD (CSP com `unsafe-inline` exigido pelo Streamlit, HTML dinâmico não
  cacheável por design, alerta informativo de SPA).

### `API/`
- **`webhook.py`** — servidor FastAPI (`/webhook/pr-scan`, `/health`).
  Autentica por API Key, bucketiza achados por criticidade, calcula score e
  atualiza o componente — fluxo determinístico, sem IA.

### `Auth/`
- **`auth.py`** — cadastro, login em duas etapas (senha + MFA por e-mail),
  sessão via cookie assinado, logout.
- **`crypto.py`** — utilitário de criptografia simétrica (Fernet) para
  valores sensíveis; disponível para uso futuro.
- **`email_service.py`** — envio do código MFA via Gmail SMTP.

### `CloudAws/`
Integração com AWS via AssumeRole em modelo hub-and-spoke.

- **`account_checks.py`** — política de senha da conta e MFA da conta root.
- **`client.py`** — `get_session_via_role()`: abre sessão com credencial
  fixa do hub, assume a Role do cliente validando o ExternalId.
- **`cspm.py`** — `run_cspm_scan()`: orquestra todos os checks e o
  inventário, retorna `(achados, inventario)`.
- **`ec2_checks.py`** — Security Groups liberando portas administrativas
  para `0.0.0.0/0`.
- **`iam_checks.py`** — políticas excessivamente permissivas, MFA ausente,
  access keys sem rotação.
- **`inventory.py`** — `descobrir_inventario()`: lista todos os recursos
  existentes na conta.
- **`s3_checks.py`** — bucket público, sem criptografia, sem versionamento.
- **`aspm-cspm-role.yaml`** — template CloudFormation que o cliente sobe
  na própria conta para criar a Role de leitura necessária.

### `Compliance/`
- **`avaliador.py`** — `avaliar_plataforma()`: calcula conformidade real
  da plataforma (acesso lógico/MFA/RBAC, cobertura de scanners incluindo
  Secrets/DLP por componente, audit trail, avaliação de riscos) mapeada
  para SOC2 e ISO 27001.

### `Database/`
- **`db.py`** — schema completo e todas as funções de CRUD. Inclui
  migração automática do schema legado (Ativo único) para o modelo atual
  (Ativo + Componentes), e a tabela `uploads_componentes` para persistir
  uploads de repositório como BLOB.

### `LLMs/`
- **`gemini.py`** — `analisar_vulnerabilidades()`: monta o prompt protegido
  contra prompt injection, classifica e consolida achados, gera o
  relatório executivo.
- **`sugestoes.py`** — `gerar_sugestoes_ia()`: correlaciona componentes por
  semelhança de identificador e grava sugestões de agrupamento pendentes.

### `MachineLearning/`
- **`anomaly_detector.py`** — Isolation Forest sobre o histórico de score.
- **`false_positive.py`** — RandomForestClassifier para filtrar achados de
  baixa confiança (SAST, SCA, DAST, CSPM, IaC — nunca Secrets/DLP).
- **`risk_score_model.py`** — RandomForestRegressor que calcula o score de
  risco (0–100) a partir da contagem de achados por criticidade e ambiente.

### `Monitoring/`
- **`monitor.py`** — `rescan_automatico()`: reexecuta todos os scanners
  aplicáveis, verifica disponibilidade e anomalias, consolida alerta
  resumido, dispara geração de sugestões ao final.
- **`scheduler.py`** — thread em background que dispara o re-scan no
  intervalo configurado.
- **`threat_intelligence.py`** — `buscar_cves_recentes()`: consulta a API
  pública da NVD por CVEs recentes, usado pelo chatbot.

### `NLP/`
- **`assistant.py`** — `preparar_prompt()`: roteia a pergunta do usuário
  por palavra-chave e injeta os dados reais correspondentes no contexto.
- **`nlp.py`** — `tela_chatbot()`: interface do chat, com suporte a
  anexos e tratamento de erro de cota da API.

### `Regras/`
- **`regras_semgrep.yaml`** — 8 regras customizadas que refinam o
  comportamento padrão do Semgrep para o stack Flask da plataforma (XSS
  real, Open Redirect real, Command Injection real, Hardcoded Secret real,
  Desserialização insegura real, `yaml.load()` sem SafeLoader, CSRF via
  `@csrf.exempt`, Broken Access Control).

### `Scanners/`
Wrappers de execução de cada ferramenta de scan.

- **`checkov.py`** — detecta Terraform/CloudFormation automaticamente;
  retorna achados sem severidade pré-atribuída (classificação fica a
  cargo do Gemini, evitando dependência da API paga do Bridgecrew).
- **`dlp.py`** — scanner próprio de DLP com validação matemática real.
- **`gitleaks.py`** — roda o binário via relatório em arquivo temporário
  multiplataforma, sempre retorna o segredo mascarado.
- **`owaspzap.py`** — orquestra Spider, Ajax Spider e Active Scan; detecta
  especificação OpenAPI automaticamente para tipo "API".
- **`repo_utils.py`** — `preparar_repositorio()` (clone git) e
  `preparar_pasta_de_bytes()`/`preparar_repositorio_upload()` (upload via
  bytes em memória ou recuperado do banco), com proteção contra Zip Slip.
- **`semgrep.py`** — roda com ruleset customizado + públicos; extrai o
  snippet do bloco de função inteiro ao redor de cada achado (via AST
  nativo ou tree-sitter), dando mais contexto à IA do que só a linha
  isolada.
- **`trivy.py`** — vulnerabilidades, segredos e misconfigurações do
  filesystem, normalizados em formato único.

### Arquivos na raiz

- **`app.py`** — ponto de entrada da interface Streamlit: todas as telas
  (Dashboard, Análises, Ativos, Vulnerabilidades, Relatórios, Logs,
  Chatbot, Painel Admin, Configurações) e a orquestração central dos
  scanners.
- **`gerar_pdf.py`** — geração do relatório executivo em PDF (ReportLab).
- **`proxy.conf`** — configuração do Nginx: CSP, headers de segurança,
  rate limiting, suporte a WebSocket para o Streamlit.
- **`docker-compose.yml`** — orquestração dos 5 containers do projeto.
- **`Dockerfile`** — build multi-stage da imagem da plataforma.
- **`requirements.txt`** — dependências Python.
- **`.env`** (não versionado) — chaves de API, credenciais AWS do hub,
  credenciais de admin padrão e de e-mail, chave de criptografia.

---

## License

Este projeto está licenciado sob a **GNU General Public License v3.0 ou posterior (GPL-3.0-or-later)**.

Consulte o texto completo da licença em [LICENSE.md](LICENSE.md).

**SPDX-License-Identifier:** `GPL-3.0-or-later`

