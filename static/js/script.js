document.addEventListener('DOMContentLoaded', function() {
    const deleteButtons = document.querySelectorAll('button.delete');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            const confirmation = confirm('Tem certeza que deseja excluir este item? Esta ação não pode ser desfeita.');
            if (!confirmation) {
                event.preventDefault();
            }
        });
    });
});

/**
 * Filtra as linhas de uma tabela com base no texto digitado em um campo de busca.
 * O campo de busca deve ter o id 'table-search'.
 * A tabela deve estar dentro de um elemento com a classe 'table-wrapper'.
 */
function filterTable() {
    const input = document.getElementById("table-search");
    const filter = input.value.toUpperCase();
    const table = document.querySelector(".table-wrapper table");
    if (!table) return;

    const trs = table.getElementsByTagName("tr");

    // Itera por todas as linhas da tabela (começando de 1 para pular o cabeçalho)
    for (let i = 1; i < trs.length; i++) {
        const row = trs[i];
        const tds = row.getElementsByTagName("td");
        let found = false;

        // Itera por todas as células da linha
        for (let j = 0; j < tds.length; j++) {
            const cell = tds[j];
            if (cell) {
                const txtValue = cell.textContent || cell.innerText;
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    found = true;
                    break; // Encontrou correspondência na linha, não precisa checar outras células
                }
            }
        }
        // Mostra ou esconde a linha com base no resultado da busca
        if (found) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }
    }
}