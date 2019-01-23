'use strict';

let userActions = {
    openModalWindowDelete: openModalWindowDelete,
    searchInformationRule: searchInformationRule,
    uploadFiles: uploadFiles
};

export { userActions };

function openModalWindowDelete(typeDeleted) {
    document.querySelector('#modalLabelDelete .modal-title').innerHTML = 'Удаление';
    let modalBody = document.querySelector('#modalDelete .modal-body');

    switch (typeDeleted) {
    case 'deleteSelected':
        cleanEvent();
        modalBody.innerHTML = '<p>Действительно удалить выбранные классы решающих правил СОА?</p>';
        document.querySelector('#modalDelete .btn-primary').addEventListener('click', deleteChangeClass);
        break;
    case 'dropDB':
        cleanEvent();
        modalBody.innerHTML = '<p>Действительно очистить всю базу данных решающих правил СОА?</p>';
        document.querySelector('#modalDelete .btn-primary').addEventListener('click', dropDB);
        break;
    }
    $('#modalDelete').modal('show');

    function cleanEvent() {
        let arrayFunctionEvents = [dropDB, deleteChangeClass];
        arrayFunctionEvents.forEach(function(item) {
            document.querySelector('#modalDelete .btn-primary').removeEventListener('click', item);
        });
    }
}

function deleteChangeClass() {
    let arrayCheckBox = document.querySelectorAll('.checkbox [name=rulesClass]');
    let arrayChangeClass = [];

    arrayCheckBox.forEach(function(item) {
        if (item.checked) arrayChangeClass.push(item.value);
    });

    //проверяем было ли что то выбранно
    if (arrayChangeClass.length === 0) {
        $('#modalDelete').modal('hide');
        return common.showNotify('warning', 'необходимо выбрать хотя бы один класс решающих правил СОА');
    }

    socket.emit('delete rules ids', { processingType: 'drop change class', options: { arrayChangeClass: arrayChangeClass } });
    $('#modalDelete').modal('hide');
}

function dropDB() {
    socket.emit('delete rules ids', { processingType: 'drop data base', options: {} });
    //закрыть модальное окно
    $('#modalDelete').modal('hide');
}

function searchInformationRule() {
    let content = document.querySelectorAll('.tokenfield > .token > span');
    let result = [];
    for (let i = 0; i < content.length; i++) {
        result.push(content[i].textContent);
    }
    let stringSid = result.join(',');

    socket.emit('search rules sid', { processingType: 'search', options: { sid: stringSid } });
}

function uploadFiles() {
    $(document).on('change', '.btn-file :file', function() {
        let input = $(this),
            numFiles = input.get(0).files ? input.get(0).files.length : 1,
            label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
        input.trigger('fileselect', [numFiles, label]);
    });

    $(document).ready(function() {
        $('.btn-file :file').on('fileselect', function(event, numFiles, label) {
            let file = event.target.files[0];
            if (typeof file === 'undefined') return;

            let stream = ss.createStream();
            $('#modalProgressBar').modal('show');
            ss(socket).emit('upload file rules IDS', stream, { name: label, size: file.size });
            let blobStream = ss.createBlobReadStream(file);

            let size = 0;
            blobStream.pipe(stream);
            blobStream.on('data', function(chunk) {
                size += chunk.length;
                let percent = (Math.floor(size / file.size * 100) + '%');

                let divProgressBar = document.querySelector('#modalProgressBar .progress-bar');
                divProgressBar.setAttribute('aria-valuenow', percent);
                divProgressBar.style.width = percent;
                divProgressBar.innerHTML = percent;
            });
        });
    });
}