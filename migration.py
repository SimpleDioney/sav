import sqlite3

# Caminho para o seu arquivo .db
caminho_db = 'database.db'  # Substitua com o caminho correto

# Lista das tabelas que você quer limpar
tabelas = ['patrimonio_items', 'patrimonios_migrados', 'marcas']

def limpar_tabelas(db_path, tabelas):
    try:
        # Conecta ao banco de dados
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Desativa temporariamente a checagem de chave estrangeira (se necessário)
        cursor.execute("PRAGMA foreign_keys = OFF;")

        # Apaga os dados de cada tabela
        for tabela in tabelas:
            print(f"Limpando tabela: {tabela}")
            cursor.execute(f"DELETE FROM {tabela};")

        # Salva as mudanças
        conn.commit()
        print("Todas as tabelas foram limpas com sucesso.")

    except sqlite3.Error as e:
        print(f"Erro ao acessar o banco de dados: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    limpar_tabelas(caminho_db, tabelas)
