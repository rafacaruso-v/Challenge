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

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            score_medio REAL,
            data TEXT
        )
        """
    )

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
    # registrar_historico() removido — só o scheduler registra pontos no histórico

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

def deletar_ativo(ativo_id):
    """
    Remove um ativo pelo ID e limpa quaisquer alertas
    associados a ele para não deixar registros órfãos.
    """
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT nome FROM ativos WHERE id = ?", (ativo_id,))
    resultado = cursor.fetchone()

    cursor.execute("DELETE FROM ativos WHERE id = ?", (ativo_id,))

    if resultado:
        nome_ativo = resultado[0]
        cursor.execute("DELETE FROM alertas WHERE ativo_nome = ?", (nome_ativo,))

    conexao.commit()


def registrar_historico():
    """
    Calcula o score médio de todos os ativos (exceto 'Erro')
    e salva um ponto no histórico com timestamp atual.
    Deve ser chamada APENAS pelo scheduler após o rescan completo.
    """
    conexao = conectar()
    cursor = conexao.cursor()

    cursor.execute(
        "SELECT score FROM ativos WHERE criticidade != 'Erro'"
    )
    scores = [r[0] for r in cursor.fetchall()]

    if not scores:
        return

    score_medio = sum(scores) / len(scores)

    cursor.execute(
        """
        INSERT INTO historico (score_medio, data)
        VALUES (?, ?)
        """,
        (score_medio, datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    )
    conexao.commit()

def listar_historico(minutos=60):
    """
    Retorna os pontos do histórico dos últimos N minutos.
    """
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        """
        SELECT score_medio, data FROM historico
        ORDER BY id DESC
        LIMIT 50
        """
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