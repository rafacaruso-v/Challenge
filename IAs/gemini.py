import google.generativeai as genai
from pydantic import BaseModel, Field
import json
from google.api_core import exceptions

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
    explicacao: str = Field(description="Análise detalhada dos achados em português. Seja cético com falsos positivos.")
    recomendacoes: str = Field(description="Passos práticos para correção em português")

def analisar_vulnerabilidades(tipo, ambiente, resultado_sast, resultado_dast):
    
    prompt = f"""
Você é um Especialista Sênior em Application Security (AppSec) e Risk Assessment.

Sua tarefa é analisar resultados de scanners SAST e DAST para calcular o risco REAL do ativo, reduzindo falsos positivos e evitando superestimar problemas de baixa criticidade.

==================================================
CONTEXTO DO ATIVO
==================================================

Tipo do ativo:
{tipo}

Ambiente:
{ambiente}

==================================================
REGRAS DE ANÁLISE
==================================================

1. DIFERENCIAÇÃO DE ATIVOS

Se o ativo for uma API:
- Priorize:
  - Broken Access Control
  - Broken Object Level Authorization (BOLA)
  - Exposição de dados sensíveis
  - JWT inseguro
  - Falhas de autenticação
  - Métodos HTTP inseguros
  - Rate limiting ausente
- Ignore problemas puramente visuais/UI.

Se o ativo for uma Aplicação Web:
- Priorize:
  - XSS
  - CSRF
  - SQL Injection
  - Upload inseguro
  - Session Hijacking
  - Segurança de cookies
  - CSP/HSTS
  - Clickjacking

Se o ativo for um Repositório:
- Priorize:
  - Secrets hardcoded
  - Credenciais expostas
  - Código inseguro
  - Execução de comandos
  - SQL Injection
  - Dependências vulneráveis
  - Código com risco crítico

==================================================
CONTEXTO DO AMBIENTE
==================================================

Produção:
- Seja rigoroso.
- Vulnerabilidades exploráveis devem aumentar bastante o score.
- Vazamento de dados ou falhas críticas devem elevar criticidade rapidamente.

Homologação:
- Considere risco moderado.
- Valorize problemas críticos mas reduza impacto operacional.

Desenvolvimento:
- Foque em orientação técnica e melhoria do código.
- Não supervalorize headers ausentes ou configurações temporárias.

==================================================
REGRAS IMPORTANTES
==================================================

- NÃO considere headers ausentes como vulnerabilidade crítica.
- NÃO trate falta de CSP/HSTS sozinha como risco alto.
- NÃO marque o ativo como seguro caso os scanners retornem vazio.
- Se os dados estiverem vazios, informe:
  "Falha na coleta de dados dos scanners."

- Seja cético com falsos positivos.
- Diferencie:
  - boas práticas
  - vulnerabilidades realmente exploráveis

- Vulnerabilidades críticas reais:
  - SQL Injection
  - RCE
  - Broken Authentication
  - Hardcoded Secrets
  - Path Traversal
  - SSRF
  - Deserialization
  - Access Control

==================================================
RESULTADOS DOS SCANNERS
==================================================

Resultado SAST:
{resultado_sast if resultado_sast else "Nenhum resultado"}

Resultado DAST:
{resultado_dast if resultado_dast else "Nenhum resultado"}

==================================================
FORMATO OBRIGATÓRIO
==================================================

Retorne SOMENTE JSON válido no schema solicitado.

NÃO exiba:
- score
- criticidade
- nível de risco

Esses dados serão exibidos separadamente pela aplicação.

A explicação deve:
- ser objetiva
- explicar os riscos encontrados
- citar apenas riscos relevantes
- evitar repetir informações desnecessárias

As recomendações devem:
- ser práticas
- priorizadas
- focadas em remediação real
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
            
            rec_raw = dados_json.get('recomendacoes', '')

            import re
            recomendacoes_limpas = re.sub(r'(\d+\.\s)', r'\n\n\1', rec_raw).strip()

            
            texto_formatado = f"""
**Explicação Técnica:**
{dados_json.get('explicacao')}

**Plano de Remediação:**
{recomendacoes_limpas}
"""
            return criticidade, score, texto_formatado

        except exceptions.ResourceExhausted:
            ultimo_erro = "Limite de cota excedido em todas as chaves configuradas."
            continue # Tenta a próxima chave
        
        except Exception as e:
            ultimo_erro = e
            continue

    # Se o loop terminar sem retornar um resultado, aciona a sua mensagem de erro original
    return "Erro", 0, f"Erro na análise da IA: {ultimo_erro}"
