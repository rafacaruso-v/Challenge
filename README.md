# ASPM Platform

Plataforma de **Application Security Posture Management (ASPM)** — centraliza a
descoberta de ativos, a execução de scanners de segurança (SAST, DAST, SCA,
IaC, CSPM, Secrets, DLP) e a análise dos achados por IA (Gemini), consolidando
tudo em um único painel de risco por aplicação/negócio.

O sistema organiza tudo em torno do conceito de **Ativo** (a aplicação/negócio,
ex: "App de Pagamentos") e **Componentes** vinculados a ele (repositório de
código, instâncias de API/Aplicação, conta Cloud) — assim, achados de fontes
diferentes ficam correlacionados sob o mesmo contexto de negócio.

## Principais capacidades

- **Orquestração de scanners**: Semgrep (SAST), OWASP ZAP (DAST), Trivy (SCA),
  Checkov (IaC), Gitleaks (Secrets) e um scanner próprio de DLP (CPF, CNPJ,
  cartão de crédito, e-mail).

- **CSPM + Inventário automatizado**: descoberta completa de recursos AWS
  (S3, IAM, Security Groups, EC2) via AssumeRole (modelo hub-and-spoke, com
  `ExternalId` protegendo contra confused deputy), com achados de postura de
  segurança classificados por criticidade.

- **Análise por IA (Gemini)**: prioriza, classifica e explica os
  achados de todos os scanners em um único relatório executivo, com proteção
  ativa contra prompt injection.

- **Redução de falsos positivos por Machine Learning**: modelos próprios
  (scikit-learn) filtram achados de baixa confiança em SAST/SCA/DAST/CSPM/IaC
  antes de chegar à IA, mantendo total transparência (nada é descartado sem
  aparecer na aba "Falsos Positivos").

- **Sugestão de agrupamento de Ativos por IA**: a cada re-scan, a IA analisa
  os componentes cadastrados e sugere vincular/criar Ativos quando identifica
  que pertencem à mesma aplicação — sempre com confirmação manual do usuário.

- **Detecção de anomalias**: monitora a evolução do score de cada componente
  ao longo do tempo e alerta sobre variações fora do padrão (Isolation Forest).

- **Chatbot de segurança**: assistente conversacional embarcado na plataforma,
  que responde sobre ativos, alertas, CVEs recentes (via NVD) e gera resumos
  executivos, com suporte a anexos (imagem, PDF, texto).

- **Integração CI/CD completa**: pipeline de GitHub Actions com SAST, Secrets
  Scan, análise de segurança do próprio pipeline (Zizmor), SCA, SBOM, scan de
  imagem Docker e DAST, comentando os resultados diretamente no Pull Request;
  e um segundo fluxo que, ao mergear na main, envia os achados para a ASPM
  Platform via webhook, criando ou atualizando o componente automaticamente.
  
- **Relatórios executivos em PDF**, com seção de conformidade SOC2 / ISO
  27001 calculada a partir do estado real da plataforma.

- **Re-scan automático agendado**, com alertas de disponibilidade, anomalia
  e conclusão de scan.


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
Pipeline de integração contínua e o fluxo de CI/CD do produto (detecção de
vulnerabilidades em Pull Requests e envio de resultados para a própria
plataforma quando o código é mergeado na main).

- **`scripts/aspm_pr_scan.py`** — roda a cada Pull Request: executa Semgrep,
  Trivy e Checkov contra o repositório inteiro, gera um resumo executivo de
  até 3 frases via Gemini (com sanitização anti-prompt-injection própria,
  independente da de `LLMs/gemini.py`) e posta um comentário formatado em
  Markdown no PR, com contagem por severidade e detalhes recolhíveis por
  scanner. Encerra com exit code 1 (falha o job) se houver achado
  Crítico/Alto, funcionando como gate de bloqueio de merge.

- **`scripts/aspm_ps_scan.py`** — roda quando o código é mergeado na main
  (evento push): reaproveita as funções de scan de `aspm_pr_scan.py` e
  adiciona Gitleaks e um scanner de DLP próprios, reescritos de forma
  self-contida (não importam de `Scanners/` ou `MachineLearning/`, já que
  este script roda no repositório do cliente, sem acesso ao pacote da
  plataforma) — inclui a mesma lógica de validação matemática de
  CPF/CNPJ/Luhn usada em `Scanners/dlp.py`. Ao final, envia todos os
  achados para o endpoint `/webhook/pr-scan` da ASPM Platform.

- **`workflows/aspm_pr_scan.yaml`** — workflow do GitHub Actions disparado
  em Pull Requests: instala Semgrep, Checkov, Trivy e roda `aspm_pr_scan.py`,
  autenticando no GitHub via `GITHUB_TOKEN` para comentar no PR.

- **`workflows/aspm_ps_scan.yml`** — workflow disparado em push para a
  main: mesma instalação de ferramentas do workflow acima, mais o binário
  do Gitleaks e roda `aspm_ps_scan.py`, enviando o resultado para a ASPM
  Platform.

- **`workflows/security.yml`** — pipeline de segurança mais amplo do
  próprio repositório da plataforma, com jobs independentes: SAST
  (Semgrep), Secrets Scan (Gitleaks Action oficial), análise de segurança
  do próprio pipeline de CI/CD (Zizmor), Dependency Scan (Trivy, com gate
  de severidade HIGH/CRITICAL), geração de SBOM (Trivy CycloneDX), scan da
  imagem Docker após build, DAST (OWASP ZAP Baseline contra a aplicação
  rodando atrás do Nginx) e um job final que consolida o resultado de
  todos os checks em um único comentário-resumo no PR.

- **`dependabot.yml`** — atualização automática semanal de dependências de
  GitHub Actions e imagens Docker, agrupadas por ecossistema, com período
  de espera de 7 dias antes de abrir o PR de atualização.

### `.streamlit/`
- **`config.toml`** — configuração da interface Streamlit; desativa o envio
  de estatísticas de uso (telemetria) para os servidores do Streamlit.

### `.zap/`
- **`rules.tsv`** — lista de exceções do OWASP ZAP Baseline Scan usado no
  workflow de CI/CD, cada uma documentada com a justificativa técnica: CSP
  com `unsafe-inline`/`unsafe-eval` (exigência do próprio framework
  Streamlit para renderizar), Non-Storable Content (HTML dinâmico por
  design) e Modern Web Application (alerta informativo sobre SPA, sem
  risco associado).

### `API/`
API do webhook que recebe resultados de scan vindos do fluxo de CI/CD.

- **`webhook.py`** — servidor FastAPI (`/webhook/pr-scan`, `/health`).
  Autentica por API Key, busca ou cria o Ativo/Componente correspondente ao
  repositório, bucketiza os achados recebidos (Semgrep, Trivy, Checkov,
  Gitleaks, DLP) por criticidade, calcula o score via `MachineLearning` e
  atualiza o componente — sem depender do Gemini (fluxo determinístico).

### `Auth/`
Autenticação e gestão de sessão dos usuários da plataforma.

- **`auth.py`** — cadastro (com validação de usuário/e-mail/senha), login
  em duas etapas (senha + MFA por e-mail, código de 6 dígitos com
  expiração de 10 minutos e limite de tentativas), sessão via cookie
  assinado com HMAC-SHA256, e logout.

- **`crypto.py`** — utilitário de criptografia simétrica (Fernet) para
  valores sensíveis (`encrypt_value` / `decrypt_value`), usando uma chave
  definida em `CREDENTIALS_ENCRYPTION_KEY` no `.env`.

- **`email_service.py`** — envio do código MFA por e-mail via Gmail SMTP
  (SSL, porta 465), com corpo em texto simples e HTML.

### `CloudAws/`
Toda a integração com AWS: descoberta de inventário e checks de postura de
segurança (CSPM). O acesso à conta do cliente é feito via AssumeRole em
modelo hub-and-spoke: a plataforma usa uma credencial fixa própria
para assumir a Role que o cliente cria na própria conta.

- **`account_checks.py`** — checks de nível de conta: política de senha da
  conta (tamanho mínimo, exigência de símbolos/números/maiúsculas,
  expiração) e se a conta root possui MFA habilitado (acionado como
  Crítico se não tiver).

- **`client.py`** — `get_session_via_role()`: abre uma sessão boto3 com a
  credencial fixa do hub, chama `sts.assume_role()` na Role do cliente com
  o `ExternalId`, e retorna uma nova sessão boto3 com as credenciais
  temporárias obtidas — nenhuma credencial do cliente fica armazenada.

- **`cspm.py`** — `run_cspm_scan()`: ponto de entrada do CSPM. Obtém a
  sessão via `client.py` e roda em sequência os checks de S3, IAM,
  Security Groups, política de senha e MFA da conta root, além de
  `descobrir_inventario()`; retorna a tupla `(achados, inventario)`.

- **`ec2_checks.py`** — `check_security_groups()`: verifica Security
  Groups que liberam portas administrativas (SSH/RDP) ou de banco de
  dados (MySQL/PostgreSQL) para qualquer IP (`0.0.0.0/0`), classificando
  como Crítico as portas sensíveis e Alto as demais.

- **`iam_checks.py`** — `check_iam()`: por usuário IAM, verifica política
  `AdministratorAccess` anexada diretamente, ausência de MFA
  e access keys ativas há mais de 90 dias sem rotação.

- **`inventory.py`** — `descobrir_inventario()`: lista TODOS os recursos
  existentes na conta (não só os com problema de segurança) reaproveitando
  a mesma sessão AssumeRole do CSPM — buckets S3, usuários IAM, Security
  Groups e instâncias EC2.

- **`s3_checks.py`** — `check_s3()`: por bucket, verifica bucket policy e
  ACL permitindo acesso público, ausência de criptografia em
  repouso e ausência de versionamento.

- **`aspm-cspm-role.yaml`** — template CloudFormation que o cliente sobe
  na própria conta AWS para criar a IAM Role de leitura (policy gerenciada
  `SecurityAudit`), com trust policy restrita à conta da ASPM Platform e
  validação por `ExternalId`.
  
### `Compliance/`
Avaliação do nível de conformidade da própria plataforma (não do ativo
analisado), usada na declaração de compliance dos relatórios PDF.

- **`avaliador.py`** — `avaliar_plataforma()`: calcula 4 critérios (acesso
  lógico/MFA/RBAC, mitigação de vulnerabilidades — incluindo cobertura
  real de Secrets/DLP por componente, rastreabilidade/audit trail,
  avaliação de riscos) mapeados para controles SOC2 e ISO 27001.

### `Database/`
Camada de acesso a dados (SQLite).

- **`db.py`** — schema completo (usuários, ativos, componentes, histórico,
  alertas, logs, API keys, sugestões de agrupamento) e todas as funções de
  CRUD usadas pelo resto do sistema.

### `LLMs/`
Toda a integração com modelos de linguagem (Gemini).

- **`gemini.py`** — `analisar_vulnerabilidades()`: monta o prompt (com
  proteção anti-prompt injection via sanitização de texto e delimitadores
  explícitos), classifica achados de todos os scanners por criticidade
  (CVSS), aplica a regra de consolidação semântica (evita duplicar o mesmo
  achado reportado por scanners diferentes) e gera o relatório executivo.
  Também contém as funções `formatar_achados_*` (CSPM, IaC, Secrets, DLP)
  e `deduplicate_sast` (agrupamento de achados SAST por proximidade de
  linha).

- **`sugestoes.py`** — `gerar_sugestoes_ia()`: ao final de cada re-scan,
  envia todos os componentes do ativo do usuário para o Gemini,
  que identifica quais provavelmente pertencem à mesma aplicação (por
  semelhança de identificador) e grava sugestões de agrupamento como
  "pendente" no banco, para confirmação manual no Dashboard.

### `MachineLearning/`
Modelos próprios de Machine Learning (scikit-learn), independentes do
Gemini.

- **`anomaly_detector.py`** — `verificar_anomalia_ml()`: usa Isolation
  Forest sobre o histórico de score de cada componente para detectar
  variações fora do padrão; cai para uma regra simples (diferença de
  score) quando não há histórico suficiente.

- **`false_positive.py`** — `RandomForestClassifier` treinado em dataset
  sintético (entropia de token, palavras que indicam teste/produção,
  segmentos de caminho) para filtrar achados de alta probabilidade de
  falso positivo em SAST, SCA, DAST, CSPM e IaC. Secrets e DLP ficam
  deliberadamente fora deste filtro, por sensibilidade do dado.

- **`risk_score_model.py`** — `RandomForestRegressor` que calcula o score
  de risco (0–100) do componente a partir da contagem de achados por
  criticidade e do ambiente (Produção eleva o score).

### `Monitoring/`
Agendamento e execução do re-scan automático, e enriquecimento com
inteligência de ameaças.

- **`monitor.py`** — `rescan_automatico()` / `_rescan_usuario()`:
  re-executa todos os scanners aplicáveis para cada componente do usuário,
  verifica disponibilidade e anomalias, atualiza o histórico, consolida um
  único alerta resumido por ciclo de re-scan, e dispara
  `gerar_sugestoes_ia()` ao final.

- **`scheduler.py`** — `iniciar_scheduler()` / `reiniciar_scheduler()`:
  thread em background que dispara `rescan_automatico()` no intervalo
  configurado em Configurações (30min a 24h).

- **`threat_intelligence.py`** — `buscar_cves_recentes()`: consulta a API
  pública da NVD (National Vulnerability Database) por CVEs publicadas
  nos últimos dias, extraindo score/severidade CVSS e produtos afetados.
  Usado pelo chatbot para responder perguntas sobre ameaças/CVEs recentes.

### `NLP/`
Assistente conversacional da plataforma.

- **`assistant.py`** — `preparar_prompt()`: monta o prompt enviado ao
  Gemini roteando por palavra-chave da pergunta do usuário (identidade do
  assistente, ativos/score/vulnerabilidade, alertas/anomalia, CVE/threat
  intelligence, relatório/resumo), injetando os dados reais
  correspondentes (ativos, alertas, CVEs).

  `Monitoring/threat_intelligence.py`: diretamente no contexto — nunca
  deixando o modelo inventar informação.

- **`nlp.py`** — `tela_chatbot()`: interface do chat no Streamlit, com
  mensagem de boas-vindas estática, suporte a anexos (imagem, PDF, txt, py, csv, json)
  e tratamento de erro de cota da API.

### `Regras/`
- **`regras_semgrep.yaml`** — regras customizadas do Semgrep que
  substituem/refinam o comportamento do ruleset padrão para reduzir falso
  positivo específico do stack da plataforma.

### `Scanners/`
Wrappers de execução de cada ferramenta de scan, usados pelo fluxo
principal da plataforma (`app.py` e `Monitoring/monitor.py`).

- **`checkov.py`** — `rodar_checkov()`: detecta automaticamente se o
  repositório contém Terraform e/ou CloudFormation (por extensão de
  arquivo e por marcadores de conteúdo, no caso do CloudFormation) e roda
  o runner do Checkov correspondente. Retorna os achados SEM severidade
  pré-atribuída — essa classificação fica a cargo do Gemini
  (`LLMs/gemini.py`). Cada achado carrega um bloco de contexto (categoria do check,
  guideline, arquivo/linhas) que ajuda a IA a classificar com mais
  precisão.

- **`dlp.py`** — `rodar_dlp_scan()`: scanner próprio de DLP. Detecta
  CPF, CNPJ, cartão de crédito e e-mail. Reduz a confiança do achado para "média"
  quando o arquivo parece ser de teste/fixture/mock, e máscara todo valor
  sensível antes de retornar (nunca expõe o dado real).

- **`gitleaks.py`** — `rodar_gitleaks()`: roda o binário do Gitleaks
  (`detect --no-git`) contra um caminho local, escrevendo o relatório
  JSON em um arquivo temporário multiplataforma e sempre retornando
  o segredo já mascarado.
  
- **`owaspzap.py`** — `rodar_zap()`: orquestra o OWASP ZAP para varredura
  DAST. Para tipo "API", tenta localizar automaticamente a especificação
  OpenAPI/Swagger em caminhos comuns antes de importar os endpoints, para
  "Aplicação", roda Spider tradicional + Ajax Spider antes do Active Scan.
  
- **`repo_utils.py`** — `preparar_repositorio()` / `limpar_repositorio()`:
  resolve um único caminho local para o repositório (clonando apenas se
  for uma URL remota), compartilhado entre SAST, SCA e IaC na mesma
  análise — evita 3 clones separados do mesmo repositório.

- **`semgrep.py`** — `rodar_semgrep()`: roda o Semgrep com o ruleset
  customizado de `Regras/` mais vários rulesets públicos. Para cada
  achado, extrai o snippet de código do bloco de função inteiro ao redor
  da linha (via AST nativo do Python, ou tree-sitter para outras
  linguagens como JS/TS/Java/PHP/Go/Ruby/C/C++/C#), dando ao Gemini o
  contexto completo da função em vez de só a linha isolada.

- **`trivy.py`** — `rodar_trivy()`: roda o Trivy (scanners de
  vulnerabilidade, secret e misconfig) contra o filesystem do repositório,
  normalizando o resultado em um formato único (CVE, segredo exposto ou
  misconfiguração) com severidade, arquivo e recomendação de correção.

### Arquivos na raiz

- **`app.py`** — ponto de entrada da interface Streamlit. Define todas as
  telas (Dashboard, Análises, Ativos, Vulnerabilidades, Relatórios, Logs,
  Chatbot, Configurações), inicia o webhook e o túnel ngrok
  em background.
  
- **`gerar_pdf.py`** — geração do relatório executivo em PDF:
  capa com metadados e ferramentas utilizadas, seção de vulnerabilidades
  separada por categoria (SAST/DAST, SCA, CSPM, IaC, Secrets, DLP),
  relatório narrativo da IA e declaração de conformidade SOC2/ISO 27001.

- **`proxy.conf`** — configuração do Nginx usado como proxy reverso
  (definida no `docker-compose.yml`): cabeçalhos de segurança e
  Content-Security-Policy ajustados para permitir o funcionamento do
  Streamlit.

- **`docker-compose.yml`** — orquestra os containers do projeto: `aspm`
  (Streamlit), `webhook` (FastAPI, mesmo `aspm.db` do app), `zap` (OWASP
  ZAP daemon), `ngrok` (túnel fixo para o webhook), `nginx` (proxy reverso
  na porta 80, usando `proxy.conf`).

- **`Dockerfile`** — build multi-stage da imagem da plataforma.

- **`requirements.txt`** — dependências Python do projeto.
