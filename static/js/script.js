document.addEventListener('DOMContentLoaded', function() {
    // Lógica para autocompletar nome do cliente no formulário de patrimônio
    const patrimonioForm = document.getElementById('patrimonio-form');
    if (patrimonioForm) {
        const codigoClienteInput = document.getElementById('codigo_cliente');
        const nomeClienteInput = document.getElementById('nome_cliente');
        const clienteInfoSpan = document.getElementById('cliente-info');
        // Lê a BASE do URL da API de clientes
        const clienteApiUrlBase = patrimonioForm.dataset.clienteApiBaseUrl;

        codigoClienteInput.addEventListener('blur', async function() {
            const codigo = this.value.trim();
            const storeSelect = document.getElementById('store_id');
            const storeId = storeSelect ? storeSelect.value : '';

            if (codigo && clienteApiUrlBase) {
                try {
                    // CONSTRÓI o URL final juntando a base + o código
                    let url = clienteApiUrlBase + `/${codigo}`;
                    
                    if (storeId) {
                        url += `?store_id=${storeId}`;
                    }
                    
                    const response = await fetch(url);
                    if (response.ok) {
                        const data = await response.json();
                        nomeClienteInput.value = data.nome_cliente;
                        nomeClienteInput.readOnly = true;
                        clienteInfoSpan.textContent = 'Cliente encontrado. Os dados foram preenchidos.';
                        clienteInfoSpan.style.color = 'var(--color-success)';
                    } else {
                        nomeClienteInput.value = '';
                        nomeClienteInput.readOnly = false;
                        clienteInfoSpan.textContent = 'Novo cliente. Preencha o nome.';
                        clienteInfoSpan.style.color = 'var(--color-primary)';
                    }
                } catch (error) {
                    console.error('Erro ao buscar cliente:', error);
                    clienteInfoSpan.textContent = 'Erro ao conectar com a API.';
                    clienteInfoSpan.style.color = 'var(--color-danger)';
                }
            } else {
                nomeClienteInput.value = '';
                nomeClienteInput.readOnly = false;
                clienteInfoSpan.textContent = '';
            }
        });

        // Lógica para formulário dinâmico de marcas e tamanho
        const tipoSelect = document.getElementById('tipo_id');
        const marcaSelect = document.getElementById('marca_id');
        const tamanhoDiv = document.getElementById('tamanho-div');
        // Lê a BASE do URL da API de marcas
        const marcasApiUrlBase = patrimonioForm.dataset.marcasApiBaseUrl;

        if (tipoSelect && marcaSelect && marcasApiUrlBase) {
            tipoSelect.addEventListener('change', async function() {
                const tipoId = this.value;
                
                marcaSelect.innerHTML = '<option value="">Carregando...</option>';
                marcaSelect.disabled = true;

                const selectedText = this.options[this.selectedIndex].text;
                if (tamanhoDiv) {
                    tamanhoDiv.style.display = selectedText.toLowerCase().includes('freezer') ? 'block' : 'none';
                }

                if (tipoId) {
                    try {
                        // CONSTRÓI o URL final juntando a base + o ID do tipo
                        const url = marcasApiUrlBase + `/${tipoId}`;
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
             throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();

        // Atualiza o conteúdo da tabela
        const tableBody = document.querySelector('.table-wrapper tbody');
        if (tableBody) {
            tableBody.innerHTML = ''; // Limpa a tabela
            result.items.forEach(item => {
                const newRow = createTableRow(item, result.page_type, result.script_root);
                tableBody.insertAdjacentHTML('beforeend', newRow);
            });
        }

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
 * Cria o HTML para uma nova linha de tabela (função genérica).
 * @param {object} item O objeto com os dados do item.
 * @param {string} pageType O tipo de página (e.g., 'patrimonio', 'cobranca').
 * @param {string} scriptRoot O prefixo da URL da aplicação.
 * @returns {string} O HTML da linha da tabela (<tr>).
 */
function createTableRow(item, pageType, scriptRoot = '') {
    const isSuperAdmin = document.body.dataset.isSuperAdmin === 'true';
    let cells = '';
    let editUrl, deleteUrl;

    switch (pageType) {
        // ... (as implementações de 'case' para cada tipo de página podem ser adicionadas aqui se necessário) ...
        default:
            cells = `<td>${item.id || ''}</td><td>${item.name || 'Novo Item'}</td>`;
            break;
    }

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
    if (!wrapper) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${category}`;
    messageDiv.innerHTML = `<p>${message}</p><button class="close-message">&times;</button>`;
    
    wrapper.innerHTML = ''; // Limpa mensagens antigas
    wrapper.appendChild(messageDiv);

    messageDiv.querySelector('.close-message').addEventListener('click', () => {
        messageDiv.style.opacity = '0';
        setTimeout(() => messageDiv.remove(), 300);
    });

    setTimeout(() => {
        messageDiv.style.opacity = '0';
        setTimeout(() => messageDiv.remove(), 500);
    }, 5000);
}