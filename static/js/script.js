document.addEventListener('DOMContentLoaded', function() {
    // Lógica para autocompletar nome do cliente no formulário de patrimônio
    const codigoClienteInput = document.getElementById('codigo_cliente');
    if (codigoClienteInput) {
        codigoClienteInput.addEventListener('blur', async function() {
            const codigo = this.value.trim();
            const nomeClienteInput = document.getElementById('nome_cliente');
            const clienteInfoSpan = document.getElementById('cliente-info');
            const scriptRoot = document.body.dataset.scriptName || '';
            
            // Para super_admin, precisamos passar o store_id selecionado
            const storeSelect = document.getElementById('store_id');
            const storeId = storeSelect ? storeSelect.value : '';

            if (codigo) {
                try {
                    let url = `${scriptRoot}/api/cliente/${codigo}`;
                    // Adiciona store_id como parâmetro de consulta para a API
                    if (storeId) {
                        url += `?store_id=${storeId}`;
                    }
                    const response = await fetch(url);
                    if (response.ok) {
                        const data = await response.json();
                        nomeClienteInput.value = data.nome_cliente;
                        nomeClienteInput.readOnly = true;
                        clienteInfoSpan.textContent = 'Cliente encontrado. O patrimônio será adicionado a este cliente.';
                        clienteInfoSpan.style.color = 'green';
                    } else {
                        nomeClienteInput.value = '';
                        nomeClienteInput.readOnly = false;
                        clienteInfoSpan.textContent = 'Novo cliente. Preencha o nome.';
                        clienteInfoSpan.style.color = '#3498db';
                    }
                } catch (error) {
                    console.error('Erro ao buscar cliente:', error);
                    clienteInfoSpan.textContent = 'Erro ao buscar dados do cliente.';
                    clienteInfoSpan.style.color = 'red';
                }
            } else {
                nomeClienteInput.value = '';
                nomeClienteInput.readOnly = false;
                clienteInfoSpan.textContent = '';
            }
        });
    }

    // Lógica para formulário de patrimônio dinâmico (marcas e tamanho)
    const tipoSelect = document.getElementById('tipo_id');
    const marcaSelect = document.getElementById('marca_id');
    const tamanhoDiv = document.getElementById('tamanho-div');
    const scriptRoot = document.body.dataset.scriptName || '';

    if (tipoSelect && marcaSelect) {
        tipoSelect.addEventListener('change', async function() {
            const tipoId = this.value;
            
            marcaSelect.innerHTML = '<option value="">Carregando...</option>';
            marcaSelect.disabled = true;

            const selectedText = this.options[this.selectedIndex].text;
            tamanhoDiv.style.display = selectedText.toLowerCase() === 'freezer' ? 'block' : 'none';

            if (tipoId) {
                try {
                    const url = `${scriptRoot}/api/marcas/${tipoId}`;
                    const response = await fetch(url);
                    if (!response.ok) throw new Error('Falha na resposta da rede');
                    
                    const marcas = await response.json();
                    
                    marcaSelect.innerHTML = '<option value="">Selecione uma marca</option>';
                    marcas.forEach(marca => {
                        const option = new Option(marca.nome, marca.id);
                        marcaSelect.add(option);
                    });
                    marcaSelect.disabled = false;
                } catch (error) {
                    console.error('Erro ao buscar marcas:', error);
                    marcaSelect.innerHTML = '<option value="">Erro ao carregar</option>';
                }
            } else {
                marcaSelect.innerHTML = '<option value="">Selecione um tipo primeiro</option>';
            }
        });
    }
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
            const newRow = createTableRow(item, result.page_type, result.script_root);
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
 * @param {string} scriptRoot O prefixo da URL da aplicação (e.g., /arquivos).
 * @returns {string} O HTML da linha da tabela (<tr>).
 */
function createTableRow(item, pageType, scriptRoot) {
    const isSuperAdmin = document.body.dataset.isSuperAdmin === 'true';
    const prefix = scriptRoot || document.body.dataset.scriptName || '';
    let cells = '';
    
    let editUrl, deleteUrl;

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
            editUrl = `${prefix}/patrimonio/edit/${item.id}`;
            deleteUrl = `${prefix}/patrimonio/delete/${item.id}`;
            break;
        case 'cobranca':
             cells = `
                <td>${item.id}</td>
                ${isSuperAdmin ? `<td>${item.store_name || 'N/A'}</td>` : ''}
                <td>${item.ficha_acerto}</td>
                <td>${item.caixa}</td>
                <td>${item.range_cliente_inicio} - ${item.range_cliente_fim}</td>
            `;
            editUrl = `${prefix}/cobranca/fichas_acerto/edit/${item.id}`;
            deleteUrl = `${prefix}/cobranca/fichas_acerto/delete/${item.id}`;
            break;
        case 'contas_a_pagar_pagamentos':
            cells = `
                <td>${item.id}</td>
                ${isSuperAdmin ? `<td>${item.store_name || 'N/A'}</td>` : ''}
                <td>${item.pagamento_data_inicio}</td>
                <td>${item.pagamento_data_fim}</td>
                <td>${item.caixa}</td>
            `;
            editUrl = `${prefix}/contas_a_pagar/pagamentos/edit/${item.id}`;
            deleteUrl = `${prefix}/contas_a_pagar/pagamentos/delete/${item.id}`;
            break;
        case 'contas_a_pagar_diversos':
            cells = `
                <td>${item.id}</td>
                ${isSuperAdmin ? `<td>${item.store_name || 'N/A'}</td>` : ''}
                <td>${item.numero_caixa}</td>
            `;
            editUrl = `${prefix}/contas_a_pagar/documentos_diversos/edit/${item.id}`;
            deleteUrl = `${prefix}/contas_a_pagar/documentos_diversos/delete/${item.id}`;
            break;
        case 'user_management':
            cells = `
                <td>${item.id}</td>
                <td>${item.username}</td>
                <td>${(item.role || '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</td>
                <td>${item.store_name || 'N/A'}</td>
                <td>${item.can_add_users ? 'Sim' : 'Não'}</td>
            `;
            editUrl = `${prefix}/super_admin/users/edit/${item.id}`;
            deleteUrl = `${prefix}/super_admin/users/delete/${item.id}`;
            break;
        case 'manage_stores':
            cells = `
                <td>${item.id}</td>
                <td>${item.name}</td>
                <td>${(item.departments || 'Nenhum').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</td>
            `;
            deleteUrl = `${prefix}/super_admin/stores/delete/${item.id}`;
            break;
    }

    // Coluna de ações (Editar/Excluir)
    let actionsCell = `<td class="actions">`;
    if (editUrl) {
        actionsCell += `<a href="${editUrl}" class="edit" title="Editar"><i class="fas fa-edit"></i></a>`;
    }
    if (deleteUrl) {
        actionsCell += `
            <form action="${deleteUrl}" method="POST" style="display:inline;" class="delete-form" data-ajax="true">
                <button type="submit" class="delete" title="Excluir"><i class="fas fa-trash-alt"></i></button>
            </form>
        `;
    }
    actionsCell += `</td>`;


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