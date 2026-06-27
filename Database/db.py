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
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            nome TEXT,
            criado_em TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ativos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            nome TEXT,
            tipo TEXT,
            url TEXT,
            ambiente TEXT,
            criticidade TEXT,
            score INTEGER,
            analise TEXT,
            ultima_analise TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            ativo_nome TEXT,
            tipo TEXT,
            mensagem TEXT,
            data TEXT,
            resolvido INTEGER DEFAULT 0,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            score_medio REAL,
            data TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
        """
    )


    try:
        cursor.execute("ALTER TABLE ativos ADD COLUMN usuario_id INTEGER")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE alertas ADD COLUMN usuario_id INTEGER")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE historico ADD COLUMN usuario_id INTEGER")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE ativos ADD COLUMN ultima_analise TEXT")
    except Exception:
        pass

    conexao.commit()



def criar_usuario(username, email, senha_hash, nome):
    conexao = conectar()
    cursor = conexao.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO usuarios (username, email, senha_hash, nome, criado_em)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, email, senha_hash, nome,
             datetime.now().strftime("%d/%m/%Y %H:%M"))
        )
        conexao.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None

def buscar_usuario_por_username(username):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT id, username, email, senha_hash, nome FROM usuarios WHERE username = ?",
        (username,)
    )
    return cursor.fetchone()

def buscar_usuario_por_id(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT id, username, email, senha_hash, nome FROM usuarios WHERE id = ?",
        (usuario_id,)
    )
    return cursor.fetchone()


def salvar_ativo(usuario_id, nome, tipo, url, ambiente, criticidade, score, analise):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        INSERT INTO ativos (
            usuario_id, nome, tipo, url, ambiente, criticidade, score, analise, ultima_analise
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (usuario_id, nome, tipo, url, ambiente, criticidade, score, analise,
         datetime.now().strftime("%d/%m/%Y %H:%M"))
    )
    conexao.commit()

def atualizar_ativo(usuario_id, nome, url, criticidade, score, analise):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        UPDATE ativos
        SET criticidade = ?, score = ?, analise = ?, ultima_analise = ?
        WHERE usuario_id = ? AND nome = ? AND url = ?
        """,
        (criticidade, score, analise,
         datetime.now().strftime("%d/%m/%Y %H:%M"),
         usuario_id, nome, url)
    )
    conexao.commit()


def listar_ativos_db(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT * FROM ativos WHERE usuario_id = ?", (usuario_id,))
    ativos = cursor.fetchall()
    return ativos

def deletar_ativo(usuario_id, ativo_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT nome FROM ativos WHERE id = ? AND usuario_id = ?",
        (ativo_id, usuario_id)
    )
    resultado = cursor.fetchone()

    cursor.execute(
        "DELETE FROM ativos WHERE id = ? AND usuario_id = ?",
        (ativo_id, usuario_id)
    )

    if resultado:
        nome_ativo = resultado[0]
        cursor.execute(
            "DELETE FROM alertas WHERE ativo_nome = ? AND usuario_id = ?",
            (nome_ativo, usuario_id)
        )

    conexao.commit()


def registrar_historico(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()

    cursor.execute(
        "SELECT score FROM ativos WHERE usuario_id = ? AND criticidade != 'Erro'",
        (usuario_id,)
    )
    scores = [r[0] for r in cursor.fetchall()]

    if not scores:
        return

    score_medio = sum(scores) / len(scores)

    cursor.execute(
        """
        INSERT INTO historico (usuario_id, score_medio, data)
        VALUES (?, ?, ?)
        """,
        (usuario_id, score_medio, datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    )
    conexao.commit()

def listar_historico(usuario_id, minutos=60):

    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        SELECT score_medio, data FROM historico
        WHERE usuario_id = ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (usuario_id,)
    )
    resultados = cursor.fetchall()

    if not resultados:
        return []

    agora = datetime.now()
    filtrados = []
    for score_medio, data_str in resultados:
        data_ponto = datetime.strptime(data_str, "%d/%m/%Y %H:%M:%S")
        if (agora - data_ponto).total_seconds() <= minutos * 60:
            filtrados.append((score_medio, data_str))

    return list(reversed(filtrados))


def salvar_alerta(usuario_id, ativo_nome, tipo, mensagem):

    conexao = conectar()
    cursor = conexao.cursor()

    cursor.execute(
        """
        SELECT id FROM alertas
        WHERE usuario_id = ?
          AND ativo_nome = ?
          AND tipo       = ?
          AND mensagem   = ?
          AND resolvido  = 0
        LIMIT 1
        """,
        (usuario_id, ativo_nome, tipo, mensagem)
    )
    if cursor.fetchone():
        return

    cursor.execute(
        """
        INSERT INTO alertas (usuario_id, ativo_nome, tipo, mensagem, data)
        VALUES (?, ?, ?, ?, ?)
        """,
        (usuario_id, ativo_nome, tipo, mensagem, datetime.now().strftime("%d/%m/%Y %H:%M"))
    )
    conexao.commit()

def listar_alertas_ativos(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        SELECT * FROM alertas
        WHERE usuario_id = ? AND resolvido = 0
        ORDER BY id DESC
        LIMIT 10
        """,
        (usuario_id,)
    )
    return cursor.fetchall()

def resolver_alerta(usuario_id, alerta_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "UPDATE alertas SET resolvido = 1 WHERE id = ? AND usuario_id = ?",
        (alerta_id, usuario_id)
    )
    conexao.commit()