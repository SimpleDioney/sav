document.addEventListener('DOMContentLoaded', function() {
    // Delegação de eventos para ações AJAX
    document.body.addEventListener('submit', function(event) {
        const form = event.target;
        if (form.matches('form[data-ajax="true"]')) {
            event.preventDefault();
            handleFormSubmit(form);
        }
    });

    document.body.addEventListener('click', function(event) {
        const link = event.target.closest('a');
        // Manipula cliques nos links de paginação
        if (link && link.matches('.pagination a')) {
            // A paginação na página de busca não será AJAX
            if (document.body.dataset.pageType === 'search-results') {
                return;
            }
            event.preventDefault();
            handlePaginationClick(link);
        }
    });
});

/**
 * Manipula o envio de formulários AJAX (adição e exclusão).
 * @param {HTMLFormElement} form O formulário que foi submetido.
 */
async function handleFormSubmit(form) {
    const isDeleteForm = form.classList.contains('delete-form');
    
    if (isDeleteForm) {
        const confirmation = confirm('Tem certeza que deseja excluir este item? Esta ação não pode ser desfeita.');
        if (!confirmation) return;
    }

    const url = form.action;
    const method = form.method;
    const formData = new FormData(form);

    try {
        const response = await fetch(url, {
            method: method,
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });

        const result = await response.json();

        if (response.ok) {
            displayFlashMessage(result.message, 'success');
            if (isDeleteForm) {
                document.querySelector(`tr[data-id='${result.itemId}']`).remove();
            } else {
                // Adiciona a nova linha e reseta o formulário
                const tableBody = document.querySelector('.table-wrapper tbody');
                if (tableBody && result.item) {
                    const newRow = createTableRow(result.item, result.page_type);
                    tableBody.insertAdjacentHTML('afterbegin', newRow);
                }
                form.reset();
            }
        } else {
            displayFlashMessage(result.message || 'Ocorreu um erro.', 'danger');
        }
    } catch (error) {
        console.error('Erro na requisição AJAX:', error);
        displayFlashMessage('Erro de conexão. Verifique sua rede e tente novamente.', 'danger');
    }
}

/**
 * Manipula cliques nos links de paginação para carregar dados dinamicamente.
 * @param {HTMLAnchorElement} link O link de paginação que foi clicado.
 */
async function handlePaginationClick(link) {
    const url = link.href;

    try {
        const response = await fetch(url, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (!response.ok) {
             // Se a resposta não for OK, trata como erro antes de tentar parsear JSON
             throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();

        // Atualiza o conteúdo da tabela
        const tableBody = document.querySelector('.table-wrapper tbody');
        tableBody.innerHTML = ''; // Limpa a tabela
        result.items.forEach(item => {
            const newRow = createTableRow(item, result.page_type);
            tableBody.insertAdjacentHTML('beforeend', newRow);
        });

        // Atualiza os links de paginação
        const paginationContainer = document.querySelector('.pagination');
        if (paginationContainer) {
            paginationContainer.innerHTML = result.pagination_html;
        }
         // Atualiza a URL da página sem recarregar
        window.history.pushState({path: url}, '', url);

    } catch (error) {
        console.error('Erro na paginação AJAX:', error);
        displayFlashMessage('Erro de conexão ou resposta inválida do servidor.', 'danger');
    }
}

/**
 * Cria o HTML para uma nova linha de tabela.
 * @param {object} item O objeto com os dados do item.
 * @param {string} pageType O tipo de página (e.g., 'patrimonio', 'cobranca').
 * @returns {string} O HTML da linha da tabela (<tr>).
 */
function createTableRow(item, pageType) {
    const isSuperAdmin = document.body.dataset.isSuperAdmin === 'true';
    let cells = '';
    let actionsCell = '';

    // Colunas específicas para cada tipo de página
    switch (pageType) {
        case 'patrimonio':
            cells = `
                <td>${item.id}</td>
                ${isSuperAdmin ? `<td>${item.store_name || 'N/A'}</td>` : ''}
                <td>${item.codigo_cliente}</td>
                <td>${item.nome_cliente}</td>
                <td>${item.patrimonios}</td>
                <td>${item.numero_caixa}</td>
            `;
            break;
        case 'cobranca':
             cells = `
                <td class="drag-handle"><i class="fas fa-grip-vertical"></i></td>
                <td>${item.id}</td>
                ${isSuperAdmin ? `<td>${item.store_name || 'N/A'}</td>` : ''}
                <td>${item.ficha_acerto}</td>
                <td>${item.caixa}</td>
                <td>${item.range_cliente_inicio} - ${item.range_cliente_fim}</td>
            `;
            break;
        case 'contas_a_pagar_pagamentos':
            cells = `
                <td>${item.id}</td>
                ${isSuperAdmin ? `<td>${item.store_name || 'N/A'}</td>` : ''}
                <td>${item.pagamento_data_inicio}</td>
                <td>${item.pagamento_data_fim}</td>
                <td>${item.caixa}</td>
            `;
            break;
        case 'contas_a_pagar_diversos':
            cells = `
                <td>${item.id}</td>
                ${isSuperAdmin ? `<td>${item.store_name || 'N/A'}</td>` : ''}
                <td>${item.numero_caixa}</td>
            `;
            break;
        case 'user_management':
            cells = `
                <td>${item.id}</td>
                <td>${item.username}</td>
                <td>${(item.role || '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</td>
                <td>${item.store_name || 'N/A'}</td>
                <td>${item.can_add_users ? 'Sim' : 'Não'}</td>
            `;
            break;
        case 'manage_stores':
            cells = `
                <td>${item.id}</td>
                <td>${item.name}</td>
                <td>${(item.departments || 'Nenhum').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</td>
            `;
            break;
    }

    // Coluna de ações (Editar/Excluir)
    if (pageType === 'user_management' || pageType === 'manage_stores') {
        const deleteUrl = `/super_admin/${pageType === 'user_management' ? 'users' : 'stores'}/delete/${item.id}`;
        actionsCell = `
             <td class="actions">
                <form action="${deleteUrl}" method="POST" style="display:inline;" class="delete-form" data-ajax="true">
                    <button type="submit" class="delete" title="Excluir"><i class="fas fa-trash-alt"></i></button>
                </form>
            </td>
        `;
    } else {
        const editUrl = `/${pageType.replace(/_/g, '/')}/edit/${item.id}`;
        const deleteUrl = `/${pageType.replace(/_/g, '/')}/delete/${item.id}`;
        actionsCell = `
            <td class="actions">
                <a href="${editUrl}" class="edit" title="Editar"><i class="fas fa-edit"></i></a>
                <form action="${deleteUrl}" method="POST" style="display:inline;" class="delete-form" data-ajax="true">
                    <button type="submit" class="delete" title="Excluir"><i class="fas fa-trash-alt"></i></button>
                </form>
            </td>
        `;
    }

    return `<tr data-id="${item.id}">${cells}${actionsCell}</tr>`;
}


/**
 * Exibe uma mensagem flash dinâmica.
 * @param {string} message A mensagem a ser exibida.
 * @param {string} category A categoria ('success', 'danger', etc.).
 */
function displayFlashMessage(message, category) {
    const wrapper = document.querySelector('.messages-wrapper');
    const messageLi = document.createElement('li');
    messageLi.className = `messages ${category}`;
    messageLi.innerHTML = `<i class="fas fa-info-circle"></i> ${message}`;
    
    // Limpa mensagens antigas antes de adicionar a nova
    wrapper.innerHTML = '';
    wrapper.appendChild(messageLi);

    setTimeout(() => {
        messageLi.style.opacity = '0';
        setTimeout(() => messageLi.remove(), 500);
    }, 5000);
}

/**
 * Filtra as linhas de uma tabela com base no texto digitado.
 */
function filterTable() {
    const input = document.getElementById("table-search");
    const filter = input.value.toUpperCase();
    const table = document.querySelector(".table-wrapper table");
    if (!table) return;

    const trs = table.getElementsByTagName("tr");
    for (let i = 1; i < trs.length; i++) {
        const row = trs[i];
        row.style.display = Array.from(row.cells).some(cell => 
            cell.textContent.toUpperCase().includes(filter)
        ) ? "" : "none";
    }
}
