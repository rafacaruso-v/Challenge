import google.generativeai as genai
from pydantic import BaseModel, Field
import json

# =====================================
# CONFIG API
# =====================================
genai.configure(
    api_key="AIzaSyCnvG-RvQGHa77qbVGEioe19ith0Z6TuJE"
)

# Schema com descrições em português para orientar melhor a IA
class AnaliseVulnerabilidadeSchema(BaseModel):
    criticidade: str = Field(description="Deve ser: Baixa, Média, Alta ou Crítica")
    score: int = Field(description="Pontuação de risco de 0 a 100")
    explicacao: str = Field(description="Análise detalhada dos achados em português. Seja cético com falsos positivos.")
    recomendacoes: str = Field(description="Passos práticos para correção em português")

modelo = genai.GenerativeModel("gemini-2.5-flash") 

def analisar_vulnerabilidades(tipo, ambiente, resultado_sast, resultado_dast):
    
    prompt = f"""
    Você é um Auditor Sênior de Segurança de Aplicações (AppSec).
    Analise os dados de scan abaixo para um ativo no ambiente de {ambiente}.

    DIRETRIZES RÍGIDAS PARA EVITAR FALSOS POSITIVOS:
    1. Diferencie 'Ausência de Cabeçalhos de Segurança' de 'Vulnerabilidades Exploráveis'.
       - Se apenas cabeçalhos estiverem faltando em um site público/estático, classifique como BAIXA/MÉDIA.
    2. Contextualize o Ambiente: Vulnerabilidades em 'Produção' têm peso maior que em 'Desenvolvimento'.
    3. Resultados Vazios: Se o SAST ou DAST estiverem vazios ou "[]", NÃO invente riscos. Classifique como 'Baixa' ou 'Informativa'.
    4. Validação DAST: Falsos positivos comuns incluem erros de configuração (CWE-16) em CDNs de larga escala. Seja crítico.
    5. Toda a sua resposta DEVE ser em Português do Brasil.

    DADOS DO ATIVO:
    - Tipo de Ativo: {tipo}
    - Ambiente: {ambiente}
    - Resultados SAST (Código): {resultado_sast if resultado_sast else "Nenhum achado encontrado"}
    - Resultados DAST (Dinâmico): {resultado_dast if resultado_dast else "Nenhum achado encontrado"}
    """

    try:
        resposta = modelo.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                response_schema=AnaliseVulnerabilidadeSchema,
                temperature=0.1
            )
        )

        dados_json = json.loads(resposta.text)

        # Mapeia para garantir que o retorno interno também siga o padrão
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

    except Exception as erro:
        return "Erro", 0, f"Erro na análise da IA: {erro}"
