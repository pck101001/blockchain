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
document.getElementById('createGenesisBlock').addEventListener('click', async () => {
    try {
        const response = await fetch('/genesis_block', { method: 'POST' });
        const result = await response.json();
        alert(result.status || 'Genesis block created successfully!');
    } catch (error) {
        alert('Failed to create genesis block: ' + error.message);
    }
});
document.getElementById('faucetForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const publicKey = document.getElementById('faucetPublicKey').value;
    try {
        const response = await fetch('/faucet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ public_key: publicKey })
        });
        const result = await response.json();
        alert(result.status);
    } catch (error) {
        alert('Faucet request failed: ' + error.message);
    }
});
document.getElementById('miningForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const publicKey = document.getElementById('minerPublicKey').value;
    try {
        const response = await fetch('/mine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ public_key: publicKey })
        });
        const result = await response.json();
        alert(result.status);
    } catch (error) {
        alert('Mining failed to start: ' + error.message);
    }
});
document.getElementById('balanceForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const publicKey = document.getElementById('publicKeyBalance').value;
    try {
        const response = await fetch('/balance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ public_key: publicKey })
        });
        const { balance } = await response.json();
        document.getElementById('balanceDisplay').textContent = `Balance: ${balance}`;
    } catch (error) {
        document.getElementById('balanceDisplay').textContent = `Error: ${error.message}`;
    }
});