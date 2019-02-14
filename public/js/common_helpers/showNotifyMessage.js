/** Вывод информационного сообщения */

let showNotifyMessage = function(data) {
    let notify = JSON.parse(data.notify)
    $.notify({
        message: notify.message
    }, {
        type: notify.type,
        placement: { from: 'top', align: 'right' },
        offset: { x: 10, y: 10 }
    });
}

export default showNotifyMessage