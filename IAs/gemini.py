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
    explicacao: str = Field(description="Análise detalhada dos achados.")
    recomendacoes: str = Field(description="Passos para correção ou melhorias")

def analisar_vulnerabilidades(tipo, url, ambiente, resultado_sast, resultado_dast):
    # Lógica para ignorar SAST se for URL
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
REGRAS DE NEGÓCIO
==================================================
1. Se SAST estiver como 'IGNORADO', foque sua análise 100% nos resultados do DAST.
2. Se o scanner DAST retornar 'LIMPO' e o SAST for 'IGNORADO', parabenize o usuário pela segurança da URL.
3. SQL Injection, XSS Crítico e Exposição de Dados Sensíveis = Score 90-100.
4. Ignore falhas de leitura. Se o resultado for 'LIMPO', considere o sistema seguro.

CONTEXTO: Ambiente de {ambiente}.
Retorne SOMENTE JSON.
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
            
            texto_formatado = f"""
### 📝 Análise de Postura de Segurança
{dados_json.get('explicacao')}

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
