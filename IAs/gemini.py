import google.generativeai as genai
from pydantic import BaseModel, Field
import json
from google.api_core import exceptions
import re

# =====================================
# CONFIGURAÇÃO DE ROTAÇÃO DE CHAVES
# =====================================
CHAVES_API = [
    "AIzaSyCnvG-RvQGHa77qbVGEioe19ith0Z6TuJE", 
    "AIzaSyDhRFCWG4mFzovOXsKzNRrk4ZiRWjaujMQ",
    "AIzaSyDIQDBB2NCo3eKAFfLwhyYG309mChcgTSw"
]

class AnaliseVulnerabilidadeSchema(BaseModel):
    criticidade: str = Field(description="Deve ser: Baixa, Média, Alta ou Crítica")
    score: int = Field(description="Pontuação de risco de 0 a 100")


    criticos_sast_dast: list[str] = Field(
        description="Vulnerabilidades Críticas originadas do SAST (Semgrep) ou DAST (ZAP). "
                    "Formato: 'arquivo/endpoint: tipo (check_id ou regra)'. Lista vazia se não houver."
    )
    altos_sast_dast: list[str] = Field(
        description="Vulnerabilidades Altas originadas do SAST (Semgrep) ou DAST (ZAP). "
                    "Formato: 'arquivo/endpoint: tipo (check_id ou regra)'. Lista vazia se não houver."
    )
    medios_sast_dast: list[str] = Field(
        description="Vulnerabilidades Médias originadas do SAST (Semgrep) ou DAST (ZAP). "
                    "Formato: 'arquivo/endpoint: tipo (check_id ou regra)'. Lista vazia se não houver."
    )
    baixos_sast_dast: list[str] = Field(
        description="Vulnerabilidades Baixas originadas do SAST (Semgrep) ou DAST (ZAP). "
                    "Formato: 'arquivo/endpoint: tipo (check_id ou regra)'. Lista vazia se não houver."
    )
    criticos_sca: list[str] = Field(
        description="Vulnerabilidades Críticas originadas do SCA (Trivy/CVEs em dependências). "
                    "Formato: 'Biblioteca: tipo (CVE-XXXX)'. Lista vazia se não houver."
    )
    altos_sca: list[str] = Field(
        description="Vulnerabilidades Altas originadas do SCA (Trivy/CVEs em dependências). "
                    "Formato: 'Biblioteca: tipo (CVE-XXXX)'. Lista vazia se não houver."
    )
    medios_sca: list[str] = Field(
        description="Vulnerabilidades Médias originadas do SCA (Trivy/CVEs em dependências). "
                    "Formato: 'Biblioteca: tipo (CVE-XXXX)'. Lista vazia se não houver."
    )
    baixos_sca: list[str] = Field(
        description="Vulnerabilidades Baixas originadas do SCA (Trivy/CVEs em dependências). "
                    "Formato: 'Biblioteca: tipo (CVE-XXXX)'. Lista vazia se não houver."
    )

    explicacao_executiva: str = Field(description="Análise de postura de segurança macro e descritiva para o relatório executivo.")
    recomendacoes: str = Field(description="Passos para correção ou melhorias (Plano de Ação)")

def _montar_bloco_vulns(criticos, altos, medios, baixos):
    """Recebe as 4 listas de uma ferramenta e retorna o bloco markdown formatado."""
    bloco = ""
    if criticos:
        bloco += "🔴 **Crítico**\n"
        for item in criticos:
            bloco += f"- {item}\n"
        bloco += "\n"
    if altos:
        bloco += "🟠 **Alto**\n"
        for item in altos:
            bloco += f"- {item}\n"
        bloco += "\n"
    if medios:
        bloco += "🟡 **Médio**\n"
        for item in medios:
            bloco += f"- {item}\n"
        bloco += "\n"
    if baixos:
        bloco += "🟢 **Baixo**\n"
        for item in baixos:
            bloco += f"- {item}\n"
        bloco += "\n"
    if not any([criticos, altos, medios, baixos]):
        bloco += "✅ Nenhuma vulnerabilidade encontrada.\n\n"
    return bloco

def analisar_vulnerabilidades(tipo, url, ambiente, resultado_sast, resultado_dast, resultado_sca=""):
    
    e_url = url.startswith("http://") or url.startswith("https://")
    
    if e_url:
        sast_final = "IGNORADO (O ativo é uma URL/Runtime, análise de código não aplicável)"
        sca_final  = "IGNORADO (O ativo é uma URL/Runtime, análise de dependências não aplicável)"
    else:
        sast_final = resultado_sast if (resultado_sast and resultado_sast != "[]") else "LIMPO"
        sca_final  = resultado_sca  if (resultado_sca  and resultado_sca  != "[]") else "LIMPO"

    dast_final = resultado_dast if (resultado_dast and resultado_dast != "[]") else "LIMPO"

    prompt = f"""
Você é um Especialista Sênior em AppSec. Analise os resultados para o ativo: {tipo}.
URL/Caminho: {url}

==================================================
RESULTADOS DOS SCANNERS
==================================================
SAST (Estático - Semgrep):   {sast_final}
SCA  (Dependências - Trivy): {sca_final}
DAST (Dinâmico - ZAP):       {dast_final}

==================================================
REGRA CRÍTICA DE SEPARAÇÃO POR ORIGEM
==================================================
O schema JSON possui campos SEPARADOS por ferramenta de origem. Você DEVE obedecer rigorosamente:

- Campos `criticos_sast_dast`, `altos_sast_dast`, `medios_sast_dast`, `baixos_sast_dast`:
  Preencha APENAS com achados do SAST (Semgrep) ou do DAST (ZAP).
  Formato de cada item: 'arquivo/endpoint: tipo do problema (check_id ou regra)'
  Exemplo: 'app.py: SQL Injection (semgrep: sql-injection-db-cursor-execute)'

- Campos `criticos_sca`, `altos_sca`, `medios_sca`, `baixos_sca`:
  Preencha APENAS com achados do SCA (Trivy) — CVEs em bibliotecas/dependências.
  Formato de cada item: 'NomeBiblioteca: tipo do problema (CVE-XXXX, CVE-YYYY)'
  Exemplo: 'Django: SQL Injection (CVE-2019-14234, CVE-2020-7471)'

NUNCA misture achados do SAST/DAST nos campos SCA, nem vice-versa.
Se uma ferramenta estiver como 'IGNORADO' ou 'LIMPO', retorne lista vazia nos campos correspondentes.

==================================================
MATRIZ DE CRITICIDADE E SCORE (REGRA DE OURO)
==================================================
Você deve definir o campo 'criticidade' e o 'score' (0 a 100) com base no achado mais grave encontrado, seguindo esta régua:

1. 🔴 Crítica (Score 90-100): Se houver falhas como SQL Injection (SQLi), Execução Remota de Código (RCE), Quebra de Controle de Acesso (Broken Access Control), vazamento exposto de credenciais em runtime, ou Modo Debug Ativado/Exposto em ambiente de PRODUÇÃO. Para SCA, somente eleve para Crítica se o CVE tiver severidade CRITICAL no Trivy E possuir exploit público confirmado com impacto de RCE ou controle total do sistema.
2. 🟠 Alta (Score 70-89): Se houver Falhas de Autenticação (senhas fracas/criptografia falha), SSRF (Server-Side Request Forgery), Cross-Site Scripting (XSS), ou CVEs com severidade CRITICAL/HIGH no Trivy com exploit público conhecido mas sem RCE confirmado.
3. 🟡 Média (Score 40-69): Se houver Content Security Policy (CSP) ausente, Configurações Incorretas (Security Misconfiguration como Modo Debug ativo em Homologação/Desenvolvimento), uso de Componentes/Bibliotecas Desatualizadas com CVEs de severidade MEDIUM no Trivy ou CVEs HIGH sem exploit público confirmado. DoS, vazamento de informações e misconfigurations se enquadram aqui.
4. 🟢 Baixa (Score 1-39): Se houver APENAS Divulgação de Informações passivas (vazamento de versão de servidor/tecnologias), Ausência de Cabeçalhos de Segurança puramente de configuração (HTTP Security Headers como HSTS, Clickjacking, X-Content-Type), Gerenciamento de Sessão Fraco sem exploração ativa, CVEs de severidade LOW no Trivy, ou comportamentos inesperados sem impacto direto de segurança.
5. ⚪ Limpo (Score 0): Caso não existam vulnerabilidades reais reportadas ou todos os scanners aplicáveis estejam "LIMPO". Defina a 'criticidade' como "Baixa".

==================================================
REGRA DE CÁLCULO DE CRITICIDADE E SCORE (CONDIÇÕES)
==================================================
1. Teto Máximo (Highest Watermark): O score e a criticidade GERAL do ativo são definidos pela vulnerabilidade de maior severidade encontrada.
2. Diferença entre "Cabeçalhos Ausentes" e "Falhas Ativas": O rebaixamento para categoria Baixa SÓ deve ser aplicado se os únicos achados do relatório forem cabeçalhos de proteção ausentes (ex: falta de CSP, falta de HSTS, falta de X-Frame-Options). Se houver QUALQUER falha de comportamento do servidor, exposição de páginas de erro internas, caminhos administrativos ou Modo Debug ativo, o ativo DEVE ser mantido no mínimo como Média.
3. Fator Ambiente: Avalie o contexto informado no prompt. Se uma falha de configuração perigosa (como Modo Debug) for encontrada em ambiente de "Produção", mude o teto da falha para Crítica. Se for em "Desenvolvimento" ou "Homologação", mantenha como Média.

==================================================
REGRAS DE NEGÓCIO
==================================================
1. Se SAST estiver como 'IGNORADO', foque sua análise nos resultados do DAST e SCA. Retorne listas vazias nos campos `_sast_dast` se o DAST também estiver IGNORADO.
2. Se DAST estiver como 'IGNORADO', foque sua análise nos resultados do SAST e SCA.
3. Somente indique sistema seguro (Score 0) se TODOS os scanners aplicáveis retornarem 'LIMPO' ou 'IGNORADO'.
4. SQL Injection e XSS Crítico = Score 90-100, SOMENTE se reportados pelo SAST. Nunca infira essas falhas a partir de resultados do SCA.
5. SCA detecta APENAS CVEs em bibliotecas/dependências. Mesmo que o nome do CVE contenha termos como "SQL Injection", "XSS" ou "RCE", ele deve ser classificado pela severidade real do CVE no Trivy (CRITICAL, HIGH, MEDIUM, LOW), nunca elevado para Score 90-100 por inferência do nome do ataque.
6. CVEs com severidade CRITICAL ou HIGH no SCA com exploit público confirmado = Alta (70-89). Somente eleve para Crítica (90-100) se o CVE permitir RCE ou controle total do sistema com exploit público ativo.
7. CVEs com severidade MEDIUM no SCA sem exploit público = mínimo Média (40-69).
8. Classifique cada CVE nos campos SCA de acordo com sua severidade INDIVIDUAL. Agrupe CVEs da mesma biblioteca e mesmo tipo em um único item da lista.
9. PROIBIDO classificar tudo como Crítico. Se o score geral é 95 mas um CVE causa apenas DoS, ele pertence ao campo `medios_sca`, não `criticos_sca`.

CONTEXTO: Ambiente de {ambiente}.
Retorne SOMENTE JSON seguindo estritamente o schema fornecido.
"""

    ultimo_erro = "Erro desconhecido."
    for chave in CHAVES_API:
        try:
            genai.configure(api_key=chave)
            
            modelo = genai.GenerativeModel("gemini-2.5-flash")

            resposta = modelo.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    response_mime_type="application/json",
                    response_schema=AnaliseVulnerabilidadeSchema,
                    temperature=0.1
                )
            )

            dados_json = json.loads(resposta.text)

            # ── Monta bloco SAST/DAST ─────────────────────────────────────
            bloco_sast_dast = "## 🔍 Vulnerabilidades Encontradas\n\n---\n\n"
            bloco_sast_dast += _montar_bloco_vulns(
                dados_json.get("criticos_sast_dast", []),
                dados_json.get("altos_sast_dast",    []),
                dados_json.get("medios_sast_dast",   []),
                dados_json.get("baixos_sast_dast",   []),
            )

            # ── Monta bloco SCA ───────────────────────────────────────────
            bloco_sca = "## 🔍 Vulnerabilidades Encontradas\n\n---\n\n"
            bloco_sca += _montar_bloco_vulns(
                dados_json.get("criticos_sca", []),
                dados_json.get("altos_sca",    []),
                dados_json.get("medios_sca",   []),
                dados_json.get("baixos_sca",   []),
            )

            texto_formatado = f"""---VULNS_SAST_DAST---
{bloco_sast_dast.strip()}
---VULNS_SCA---
{bloco_sca.strip()}
---RELATORIO---
### 📝 Análise de Postura de Segurança
{dados_json.get('explicacao_executiva')}

### 🚀 Plano de Ação Recomendado
{re.sub(r'(\d+\.\s)', r'\n\n\1', dados_json.get('recomendacoes', '')).strip()}
"""
            return dados_json.get("criticidade"), dados_json.get("score"), texto_formatado

        except exceptions.ResourceExhausted:
            ultimo_erro = "Cota excedida."
            continue
        except Exception as e:
            ultimo_erro = str(e)
            continue

    return "Erro", 0, f"Erro na análise da IA: {ultimo_erro}"