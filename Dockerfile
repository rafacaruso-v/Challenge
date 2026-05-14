# Usa uma imagem oficial do Python, versão leve
FROM python:3.10-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Instala dependências do sistema operacional necessárias para o Semgrep e compilação
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copia o arquivo de requisitos para o container
COPY requirements.txt .

# Instala as bibliotecas do Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o código do projeto para dentro do container
COPY . .

# Expõe a porta padrão do Streamlit
EXPOSE 8501

# Comando para rodar a aplicação quando o container iniciar
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]