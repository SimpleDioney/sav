import sqlite3


caminho_db = 'database.db'  


tabelas = ['patrimonio_items', 'patrimonios_migrados', 'marcas']

def limpar_tabelas(db_path, tabelas):
    try:
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        
        cursor.execute("PRAGMA foreign_keys = OFF;")

        
        for tabela in tabelas:
            print(f"Limpando tabela: {tabela}")
            cursor.execute(f"DELETE FROM {tabela};")

        
        conn.commit()
        print("Todas as tabelas foram limpas com sucesso.")

    except sqlite3.Error as e:
        print(f"Erro ao acessar o banco de dados: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    limpar_tabelas(caminho_db, tabelas)
