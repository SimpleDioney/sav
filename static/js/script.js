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