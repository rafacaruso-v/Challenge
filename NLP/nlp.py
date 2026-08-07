import os
import streamlit as st
from dotenv import load_dotenv
from google import genai
from google.genai import types
from PIL import Image

from NLP.assistant import preparar_prompt, obter_nome_usuario


load_dotenv()

CHAVES_API = [
    os.getenv("GEMINI_KEY_NPL"),
    os.getenv("GEMINI_KEY_NPL_2"),
    os.getenv("GEMINI_KEY_NPL_3"),
]

CHAVES_API = [c for c in CHAVES_API if c]

if not CHAVES_API:
    st.error("Nenhuma chave da API encontrada no .env")
    st.stop()


@st.cache_resource
def inicializar_cliente():
    return genai.Client(api_key=CHAVES_API[0])


def _mensagem_de_boas_vindas(usuario_id) -> str:
    """Mensagem inicial estática (sem custo de chamada à API) exibida quando
    o usuário abre o chat pela primeira vez na sessão."""
    nome_usuario = obter_nome_usuario(usuario_id)
    return f"""Olá, {nome_usuario}! 👋 Eu sou o assistente de IA da **ASPM Platform**.

Posso te ajudar a entender a postura de segurança dos seus ativos, direto por aqui, em linguagem natural. Alguns exemplos do que você pode me perguntar:

- 🛡️ **Ativos e vulnerabilidades** — "Quais ativos estão com criticidade Alta?", "Qual o score do meu repositório X?"
- 🔔 **Alertas e anomalias** — "Tem algum ativo offline?", "Quais alertas têm maior prioridade?"
- 🌐 **Threat Intelligence** — "Quais CVEs críticas saíram essa semana?"
- 📊 **Relatórios executivos** — "Me dá um resumo geral da minha postura de segurança"

Você também pode anexar imagens, PDFs ou arquivos de texto usando o botão de anexo. Como posso te ajudar hoje?"""


def tela_chatbot(usuario_id):

    st.markdown("<h1>CHATBOT</h1>", unsafe_allow_html=True)
    st.write(
        "Envie mensagens e utilize o botão de anexo para enviar imagens, PDFs ou arquivos de texto."
    )

    if "chat" not in st.session_state:
        client = inicializar_cliente()
        st.session_state.chat = client.chats.create(
            model="gemini-3.6-flash"
        )

    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": _mensagem_de_boas_vindas(usuario_id),
            }
        ]

    for mensagem in st.session_state.messages:
        with st.chat_message(mensagem["role"]):
            st.markdown(mensagem["content"])

    entrada = st.chat_input(
        "Digite sua mensagem...",
        accept_file=True,
        file_type=[
            "png",
            "jpg",
            "jpeg",
            "webp",
            "pdf",
            "txt",
            "py",
            "csv",
            "json"
        ]
    )

    if entrada:

        prompt = entrada.text or ""

        arquivos = entrada.files if hasattr(entrada, "files") else []

        texto_usuario = prompt

        if arquivos:
            texto_usuario += f"\n\n📎 {len(arquivos)} arquivo(s) anexado(s)"

        st.session_state.messages.append(
            {
                "role": "user",
                "content": texto_usuario
            }
        )

        with st.chat_message("user"):
            st.markdown(texto_usuario)

        conteudo = []

        for arquivo in arquivos:

            tipo_arquivo = arquivo.type or ""

            if tipo_arquivo.startswith("image"):
                imagem = Image.open(arquivo)
                conteudo.append(imagem)

            else:
                conteudo.append(
                    types.Part.from_bytes(
                        data=arquivo.getvalue(),
                        mime_type=tipo_arquivo or "application/octet-stream"
                    )
                )

        prompt_final = preparar_prompt(
            usuario_id=usuario_id,
            pergunta=prompt
        )

        conteudo.append(prompt_final)

        with st.chat_message("assistant"):
            with st.spinner("Pensando..."):
                try:
                    resposta = st.session_state.chat.send_message(conteudo)
                    resposta_texto = resposta.text

                    st.markdown(resposta_texto)
                    st.session_state.messages.append(
                        {
                            "role": "assistant",
                            "content": resposta_texto
                        }
                    )

                except Exception as e:
                    erro_str = str(e)
                    if "429" in erro_str or "RESOURCE_EXHAUSTED" in erro_str.upper():
                        st.error(
                            "Cota da API excedida no momento. "
                            "Tente novamente em alguns instantes."
                        )
                    else:
                        st.error(f"Erro ao comunicar com a API:\n\n{erro_str}")