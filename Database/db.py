import sqlite3

# =========================================
# CONEXÃO COM BANCO
# =========================================

def conectar():

    conexao = sqlite3.connect(
        "aspm.db",
        check_same_thread=False
    )

    return conexao

# =========================================
# CRIAR TABELA
# =========================================

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

            score INTEGER
        )
        """
    )

    conexao.commit()

# =========================================
# SALVAR ATIVO
# =========================================

def salvar_ativo(

    nome,
    tipo,
    url,
    ambiente,
    criticidade,
    score
):

    conexao = conectar()

    cursor = conexao.cursor()

    cursor.execute(
        """
        INSERT INTO ativos (

            nome,
            tipo,
            url,
            ambiente,
            criticidade,
            score

        )

        VALUES (?, ?, ?, ?, ?, ?)
        """,

        (
            nome,
            tipo,
            url,
            ambiente,
            criticidade,
            score
        )
    )

    conexao.commit()

# =========================================
# LISTAR ATIVOS
# =========================================

def listar_ativos_db():

    conexao = conectar()

    cursor = conexao.cursor()

    cursor.execute(
        "SELECT * FROM ativos"
    )

    ativos = cursor.fetchall()

    return ativos
