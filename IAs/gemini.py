import google.generativeai as genai
from pydantic import BaseModel, Field

# =====================================
# CONFIG API
# =====================================
genai.configure(
    api_key="AIzaSyCnvG-RvQGHa77qbVGEioe19ith0Z6TuJE"
)

class AnaliseVulnerabilidadeSchema(BaseModel):
    criticidade: str = Field(description="Must be: Low, Medium, High or Critical")
    score: int = Field(description="Risk score from 0 to 100")
    explicacao: str = Field(description="Possible impacts and contextualization")
    recomendacoes: str = Field(description="Correction recommendations")


modelo = genai.GenerativeModel(
    "gemini-2.5-flash"
)

def analisar_vulnerabilidades(tipo, ambiente, resultado_sast, resultado_dast):
    prompt = f"""
    You are an Application Security expert.
    Analyze the asset data to fill in the report fields.

    Asset type: {tipo}
    Environment: {ambiente}
    SAST result: {resultado_sast}
    DAST result: {resultado_dast}
    """

    try:
    
        resposta = modelo.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                response_schema=AnaliseVulnerabilidadeSchema
            )
        )

        
        import json
        dados_json = json.loads(resposta.text)

        criticidade = dados_json.get("criticidade", "Baixa")
        score = dados_json.get("score", 0)

        
        texto_formatado = f"""
Criticidade: {criticidade}
Score: {score}

Explicação:
{dados_json.get('explicacao')}

Recomendações:
{dados_json.get('recomendacoes')}
        """

        return criticidade, score, texto_formatado

    except Exception as erro:
        return "Erro", 0, f"Erro IA: {erro}"

