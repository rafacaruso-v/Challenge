import os
import streamlit as st
from dotenv import load_dotenv
from google import genai
from google.genai import types
from PIL import Image

from NLP.assistant import preparar_prompt


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


client = inicializar_cliente()


def tela_chatbot():

    st.markdown("<h1>CHATBOT</h1>", unsafe_allow_html=True)
    st.write(
        "Envie mensagens e utilize o botão de anexo para enviar imagens, PDFs ou arquivos de texto."
    )

    if "chat" not in st.session_state:
        st.session_state.chat = client.chats.create(
            model="models/gemini-3.6-flash"
        )

    if "messages" not in st.session_state:
        st.session_state.messages = []

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

            if arquivo.type.startswith("image"):
                imagem = Image.open(arquivo)
                conteudo.append(imagem)

            else:
                conteudo.append(
                    types.Part.from_bytes(
                        data=arquivo.getvalue(),
                        mime_type=arquivo.type
                    )
                )

        usuario_id = st.session_state.get("usuario_id")

        prompt_final = preparar_prompt(
            usuario_id=usuario_id,
            pergunta=prompt
        )

        conteudo.append(prompt_final)

        with st.chat_message("assistant"):
            with st.spinner("Pensando..."):

                try:

                    resposta = st.session_state.chat.send_message(
                        conteudo
                    )

                    resposta_texto = resposta.text

                    st.markdown(resposta_texto)

                    st.session_state.messages.append(
                        {
                            "role": "assistant",
                            "content": resposta_texto
                        }
                    )

                except Exception as e:
                    st.error(f"Erro ao comunicar com a API:\n\n{e}")