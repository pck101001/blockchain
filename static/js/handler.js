document.getElementById('transactionForm').addEventListener('submit', function (event) {
    event.preventDefault();

    const sender_private_key = document.getElementById('senderPri').value;
    const sender_public_key = document.getElementById('senderPub').value;
    const receiver_public_key = document.getElementById('receiver').value;
    const amount = parseFloat(document.getElementById('amount').value);

    fetch('/transaction/submit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ sender_private_key, sender_public_key, receiver_public_key, amount })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Success:', data);
        })
        .catch((error) => {
            console.error('Error:', error);
        });
});

document.getElementById('connectForm').addEventListener('submit', function (event) {
    event.preventDefault();

    const des_ip = document.getElementById('targetIp').value;
    const des_port = parseInt(document.getElementById('targetPort').value);
    const src_ip = '0.0.0.0';
    const src_port = parseInt(0);

    fetch('/connect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ des_ip, des_port, src_ip, src_port })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Success:', data);
        })
        .catch((error) => {
            console.error('Error:', error);
        });
});
document.getElementById('generateKeyPair').addEventListener('click', async function () {
    try {
        const response = await fetch('/generate_key_pair', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const keyPair = await response.json();
        document.getElementById('privateKeyDisplay').textContent = `Private Key: ${keyPair.private_key}`;
        document.getElementById('publicKeyDisplay').textContent = `Public Key: ${keyPair.public_key}`;
    } catch (error) {
        console.error('Failed to generate key pair:', error);
    }
});