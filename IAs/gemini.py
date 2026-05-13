import google.generativeai as genai
from pydantic import BaseModel, Field
import json
from google.api_core import exceptions

# =====================================
# CONFIGURAÇÃO DE ROTAÇÃO DE CHAVES
# =====================================
# Adicione aqui suas chaves de contas diferentes
CHAVES_API = [
    "AIzaSyCnvG-RvQGHa77qbVGEioe19ith0Z6TuJE", 
    "AIzaSyDhRFCWG4mFzovOXsKzNRrk4ZiRWjaujMQ",
    "AIzaSyCnvG-RvQGHa77qbVGEioe19ith0Z6TuJE"
]

class AnaliseVulnerabilidadeSchema(BaseModel):
    criticidade: str = Field(description="Deve ser: Baixa, Média, Alta ou Crítica")
    score: int = Field(description="Pontuação de risco de 0 a 100")
    explicacao: str = Field(description="Análise detalhada dos achados em português. Seja cético com falsos positivos.")
    recomendacoes: str = Field(description="Passos práticos para correção em português")

def analisar_vulnerabilidades(tipo, ambiente, resultado_sast, resultado_dast):
    
    prompt = f"""
    Você é um Auditor Sênior de Segurança de Aplicações (AppSec). Sua missão é realizar uma triagem técnica dos resultados de scan (SAST e DAST) para o ativos que podem ser classificados como {tipo} (Aplicação/API/Repositório) e operando em ambiente de {ambiente}.

    PRIORIDADES DE ANÁLISE (Ponderação Dinâmica):
    Se o ativo for uma API:
    Ignore vulnerabilidades de UI (como XSS em páginas estáticas ou falta de cookies de sessão).
    Priorize: Broken Object Level Authorization (BOLA), exposição de dados no JSON, métodos HTTP inseguros e falhas de autenticação (JWT/API Keys).

    Se o ativo for uma APLICAÇÃO WEB:
    Priorize: Cross-Site Scripting (XSS), CSRF, Segurança de Cookies e cabeçalhos de proteção do navegador (CSP, HSTS).

    Contexto de Ambiente ({ambiente}):
    PRODUÇÃO: Rigor máximo. Falhas de infraestrutura, cabeçalhos ausentes e chaves expostas devem elevar o Risk Score imediatamente.
    DESENVOLVIMENTO: Foco em Remediação Educativa. Priorize erros de lógica no SAST e ajude o desenvolvedor a entender a correção antes do deploy.

    DIRETRIZES RÍGIDAS DE AUDITORIA:
    Diferenciação de Riscos: Não confunda "Melhores Práticas" (ex: falta de X-Frame-Options) com "Vulnerabilidades Críticas" (ex: SQL Injection). Cabeçalhos ausentes em sites sem autenticação não devem ultrapassar o nível BAIXO.

    Protocolo de Dados Vazios: Se os campos SAST ou DAST estiverem vazios ou [], ESTÁ PROIBIDO declarar o ativo como "Seguro". Você deve reportar explicitamente: "Falha na coleta de dados: os scanners não retornaram telemetria válida para análise."

    Falsos Positivos de CDN: Erros de configuração de cache ou headers em CDNs (Cloudflare, Akamai) devem ser validados com ceticismo.

    FORMATO DA RESPOSTA:
    Resumo Executivo: (Máximo 3 linhas).
    Quadro de Criticidade: (Baixa, Média, Alta, Crítica) + Risk Score (0-100).
    Principais Achados: Liste apenas o que for explorável no contexto de {tipo}.
    Plano de Remediação: Ações práticas separadas por prioridade.

    Toda a sua resposta DEVE ser em Português do Brasil.

    DADOS DO ATIVO:
    - Tipo de Ativo: {tipo}
    - Ambiente: {ambiente}
    - Resultados SAST (Código): {resultado_sast if resultado_sast else "[]"}
    - Resultados DAST (Dinâmico): {resultado_dast if resultado_dast else "[]"}
    """

    # Variável para armazenar o último erro caso todas as chaves falhem
    ultimo_erro = "Nenhuma chave de API configurada."

    # Tenta cada chave na lista
    for chave in CHAVES_API:
        try:
            genai.configure(api_key=chave)
            
            # Nota: Recomendo usar "gemini-1.5-flash" se o 2.5 ainda estiver com cotas baixas
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
            criticidade = dados_json.get("criticidade", "Baixa")
            score = dados_json.get("score", 0)

            texto_formatado = f"""
### Criticidade: {criticidade} | Score: {score}

**Explicação Técnica:**
{dados_json.get('explicacao')}

**Plano de Remediação:**
{dados_json.get('recomendacoes')}
            """
            return criticidade, score, texto_formatado

        except exceptions.ResourceExhausted:
            ultimo_erro = "Limite de cota excedido em todas as chaves configuradas."
            continue # Tenta a próxima chave
        
        except Exception as e:
            ultimo_erro = e
            continue # Tenta a próxima chave se houver outro erro técnico

    # Se o loop terminar sem retornar um resultado, aciona a sua mensagem de erro original
    return "Erro", 0, f"Erro na análise da IA: {ultimo_erro}"
