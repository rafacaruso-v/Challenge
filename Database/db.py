import sqlite3
from datetime import datetime

def conectar():
    conexao = sqlite3.connect(
        "aspm.db",
        check_same_thread=False
    )
    return conexao

def criar_tabela():
    conexao = conectar()
    cursor = conexao.cursor()
    
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ativos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            tipo TEXT,
            url TEXT,
            ambiente TEXT,
            criticidade TEXT,
            score INTEGER,
            analise TEXT,
            ultima_analise TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ativo_nome TEXT,
            tipo TEXT,
            mensagem TEXT,
            data TEXT,
            resolvido INTEGER DEFAULT 0
        )
        """
    )

    # Adiciona coluna ultima_analise se banco já existir sem ela
    try:
        cursor.execute("ALTER TABLE ativos ADD COLUMN ultima_analise TEXT")
    except Exception:
        pass

    conexao.commit()

def salvar_ativo(nome, tipo, url, ambiente, criticidade, score, analise):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        INSERT INTO ativos (
            nome, tipo, url, ambiente, criticidade, score, analise, ultima_analise
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (nome, tipo, url, ambiente, criticidade, score, analise,
         datetime.now().strftime("%d/%m/%Y %H:%M"))
    )
    conexao.commit()

def atualizar_ativo(nome, url, criticidade, score, analise):
    """Atualiza o ativo existente ao invés de criar duplicata."""
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        UPDATE ativos 
        SET criticidade = ?, score = ?, analise = ?, ultima_analise = ?
        WHERE nome = ? AND url = ?
        """,
        (criticidade, score, analise,
         datetime.now().strftime("%d/%m/%Y %H:%M"),
         nome, url)
    )
    conexao.commit()

def listar_ativos_db():
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT * FROM ativos")
    ativos = cursor.fetchall()
    return ativos

# =====================================
# FUNÇÕES DE ALERTAS
# =====================================

def salvar_alerta(ativo_nome, tipo, mensagem):
    """
    Salva o alerta apenas se não existir um alerta idêntico
    (mesmo ativo + mesmo tipo + mesma mensagem) ainda não resolvido.
    """
    conexao = conectar()
    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT id FROM alertas
        WHERE ativo_nome = ?
          AND tipo       = ?
          AND mensagem   = ?
          AND resolvido  = 0
        LIMIT 1
        """,
        (ativo_nome, tipo, mensagem)
    )
    if cursor.fetchone():
        return

    cursor.execute(
        """
        INSERT INTO alertas (ativo_nome, tipo, mensagem, data)
        VALUES (?, ?, ?, ?)
        """,
        (ativo_nome, tipo, mensagem, datetime.now().strftime("%d/%m/%Y %H:%M"))
    )
    conexao.commit()

def listar_alertas_ativos():
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        SELECT * FROM alertas
        WHERE resolvido = 0
        ORDER BY id DESC
        LIMIT 10
        """
    )
    return cursor.fetchall()

def resolver_alerta(alerta_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "UPDATE alertas SET resolvido = 1 WHERE id = ?",
        (alerta_id,)
    )
    conexao.commit()