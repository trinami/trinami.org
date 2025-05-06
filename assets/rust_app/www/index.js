import init, * as wasm from '../pkg/rust_app';

init(wasm_path).then(_ => {
    function encrypt()
    {
        if (!document.getElementById('imnotarobot').checked) {
            return;
        }
        var message = document.getElementById('reason').value + document.getElementById('message').value;
        var encryptedMessage = wasm.encrypt_message(message);

        const email = 'root@trinami.org';
        const subject = 'Encrypted message';
        const body = encryptedMessage;

        const mailtoLink = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

        window.location.href = mailtoLink;
    }
    let button = document.getElementById('encryptButton');
    button.addEventListener('click', () => {
        encrypt();
    });
});
