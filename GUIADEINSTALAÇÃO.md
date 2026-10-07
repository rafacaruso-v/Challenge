# Guia de instalação — ASPM Platform

> Atenção: o .env so não acompanha junto ao github.

## Clonar o repositório

```bash
git clone <URL-DO-REPOSITORIO>
cd Challenge
```

## Método 1 — Python

Requer Python 3.12 ou superior.

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

Acesse: **http://localhost:8501**

## Método 2 — Docker Compose

Requer Docker com Compose instalado.

```bash
docker compose up --build
```

Acesse: **http://localhost**