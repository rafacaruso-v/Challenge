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

# Estrutura para extrair o Nome e o Impacto isolados
class ItemVulnerabilidade(BaseModel):
    nome: str = Field(description="Nome claro da vulnerabilidade encontrada (ex: Content Security Policy (CSP) Inadequada, SQL Injection)")
    impacto: str = Field(description="O que essa vulnerabilidade pode causar e o que um atacante pode fazer explorando ela.")

class AnaliseVulnerabilidadeSchema(BaseModel):
    criticidade: str = Field(description="Deve ser: Baixa, Média, Alta ou Crítica")
    score: int = Field(description="Pontuação de risco de 0 a 100")
    vulnerabilidades_encontradas: list[ItemVulnerabilidade] = Field(description="Lista contendo cada uma das vulnerabilidades achadas e seus respectivos impactos.")
    explicacao_executiva: str = Field(description="Análise de postura de segurança macro e descritiva para o relatório executivo.")
    recomendacoes: str = Field(description="Passos para correção ou melhorias (Plano de Ação)")

def analisar_vulnerabilidades(tipo, url, ambiente, resultado_sast, resultado_dast):
    
    e_url = url.startswith("http://") or url.startswith("https://")
    
    if e_url:
        sast_final = "IGNORADO (O ativo é uma URL/Runtime, análise de código não aplicável)"
    else:
        sast_final = resultado_sast if (resultado_sast and resultado_sast != "[]") else "LIMPO"

    dast_final = resultado_dast if (resultado_dast and resultado_dast != "[]") else "LIMPO"

    prompt = f"""
Você é um Especialista Sênior em AppSec. Analise os resultados para o ativo: {tipo}.
URL/Caminho: {url}

==================================================
RESULTADOS DOS SCANNERS
==================================================
SAST (Estático): {sast_final}
DAST (Dinâmico): {dast_final}

==================================================
MATRIZ DE CRITICIDADE E SCORE (REGRA DE OURO)
==================================================
Você deve definir o campo 'criticidade' e o 'score' (0 a 100) com base no achado mais grave encontrado, seguindo esta régua:

1. 🔴 Crítica (Score 90-100): Se houver falhas como SQL Injection (SQLi), Execução Remota de Código (RCE), Quebra de Controle de Acesso (Broken Access Control) ou vazamento exposto de credenciais/dados sensíveis em runtime.
2. 🟠 Alta (Score 70-89): Se houver Falhas de Autenticação (senhas fracas/criptografia falha), Desserialização Insegura ou SSRF (Server-Side Request Forgery).
3. 🟡 Média (Score 40-69): Se houver Cross-Site Scripting (XSS), Configurações Incorretas (Security Misconfiguration) ou uso de Componentes/Bibliotecas Desatualizadas com CVEs conhecidas.
4. 🟢 Baixa (Score 1-39): Se houver apenas Divulgação de Informações (Information Disclosure de versão de servidor), Ausência de Cabeçalhos de Segurança (HTTP Security Headers) ou Gerenciamento de Sessão Fraco.
5. ⚪ Limpo (Score 0): Caso não existam vulnerabilidades reais reportadas ou ambos os scanners estejam "LIMPO". Defina a 'criticidade' como "Baixa".

OBS: Caso tiver uma de cada criticidade, sempre priorizar o score com base na que tem o risco maior.

==================================================
REGRAS DE NEGÓCIO
==================================================
1. Se SAST estiver como 'IGNORADO', foque sua análise 100% nos resultados do DAST.
2. Se o scanner DAST retornar 'LIMPO' e o SAST for 'IGNORADO', popule o JSON indicando sistema seguro e sem vulnerabilidades.
3. SQL Injection, XSS Crítico e Exposição de Dados Sensíveis = Score 90-100.
4. Mapeie cada falha encontrada na lista de 'vulnerabilidades_encontradas' detalhando o nome exato e o que ela pode causar.

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
            
            bloco_vulns = ""
            for v in dados_json.get("vulnerabilidades_encontradas", []):
                bloco_vulns += f"### 🔴 {v.get('nome')}\n**O que pode causar:** {v.get('impacto')}\n\n"
                
            # 2. Monta o bloco estruturado que vai para a aba Relatórios
            texto_formatado = f"""---VULNS---
{bloco_vulns.strip()}
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
