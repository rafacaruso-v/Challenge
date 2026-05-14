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
    "AIzaSyCnvG-RvQGHa77qbVGEioe19ith0Z6TuJE",
    "AIzaSyDIQDBB2NCo3eKAFfLwhyYG309mChcgTSw"
]

class AnaliseVulnerabilidadeSchema(BaseModel):
    criticidade: str = Field(description="Deve ser: Baixa, Média, Alta ou Crítica")
    score: int = Field(description="Pontuação de risco de 0 a 100")
    explicacao: str = Field(description="Análise detalhada dos achados. Se vazio, parabenize pela segurança.")
    recomendacoes: str = Field(description="Passos para correção ou melhorias contínuas")

def analisar_vulnerabilidades(tipo, ambiente, resultado_sast, resultado_dast):
    

    dast_esperado = tipo.lower() in ["api", "aplicação web", "web app"]
    
    prompt = f"""
Você é um Especialista Sênior em AppSec. Sua missão é analisar resultados de segurança para o ativo: {tipo}.

==================================================
RESULTADOS DOS SCANNERS
==================================================
SAST (Código): {resultado_sast if (resultado_sast and resultado_sast != "[]") else "LIMPO" if resultado_sast == "[]" else "FALHA"}
DAST (Runtime): {resultado_dast if (resultado_dast and resultado_dast != "[]") else "LIMPO" if resultado_dast == "[]" else "FALHA"}

==================================================
LOGICA DE ANALISE POR TIPO DE ATIVO
==================================================
1. SE o tipo for "Repositório":
   - Ignore completamente o estado do DAST. Foque apenas no SAST.
   - Se o SAST estiver "LIMPO", o ativo está seguro.

2. SE o tipo for "API" ou "Aplicação Web":
   - O DAST é importante. Se o DAST estiver como "FALHA", mencione que a análise dinâmica não foi realizada.
   - O SAST continua sendo essencial para o código dessas aplicações.

3. REGRAS GERAIS:
   - Se SAST e DAST (quando aplicável) estiverem "LIMPO", parabenize o desenvolvedor sem mencionar falhas de leitura.
   - SQL Injection e Secrets = Score 90-100 (Crítico).
   - Não mencione "Falha na leitura" se o scanner simplesmente não encontrou nada (LIMPO).

==================================================
CONTEXTO: Ambiente {ambiente}
==================================================
Retorne SOMENTE JSON.
"""
    ultimo_erro = "Nenhuma chave de API configurada."
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
            
            # Formatação profissional
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
