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
            if (data.status) {
                alert(data.status);
            }
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
        body: JSON.stringify({ des_ip, des_port, src_ip, src_port, public_key: '', is_broadcast: false, is_response: false })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Success:', data);
            if (data.status) {
                alert(data.status);
            }
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
    const publicKey = document.getElementById('minerPublicKeyDisplay').value;
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
        const { fixed_balance, pending_balance } = await response.json();
        document.getElementById('balanceDisplay').textContent = `Balance: ${fixed_balance}(${pending_balance} pending)`;
    } catch (error) {
        document.getElementById('balanceDisplay').textContent = `Error: ${error.message}`;
    }
});
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch('/miner_keys', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const keyPair = await response.json();
        document.getElementById('minerPrivateKeyDisplay').textContent = `Private Key: ${keyPair.private_key}`;
        document.getElementById('minerPublicKeyDisplay').textContent = `Public Key: ${keyPair.public_key}`;
    } catch (error) {
        console.error('Failed to generate key pair:', error);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    let updateInterval;
    let intervalSeconds = 30;

    function updateBlockchainInfo() {
        fetch('/blockchain_info', { method: 'GET' })
            .then(response => response.json())
            .then(data => {
                updateNodesList(data.nodes);
                updateBlockchain(data.blockchain, data.pending_transactions);
                document.getElementById('last-update').textContent = new Date().toLocaleString();
            })
            .catch(error => console.error('Error fetching blockchain info:', error));
    }

    function startAutoUpdate() {
        clearInterval(updateInterval);
        updateInterval = setInterval(updateBlockchainInfo, intervalSeconds * 1000);
    }

    function updateNodesList(nodes) {
        const nodesList = document.getElementById('nodes-list');
        nodesList.innerHTML = '';
        nodes.forEach(node => {
            const li = document.createElement('li');
            li.innerHTML = `<strong>${node.addr}</strong> - Public Key: ${node.public_key || 'Unknown'}`;
            nodesList.appendChild(li);
        });
    }

    function updateBlockchain(chain, pendingTransactions) {
        const container = document.getElementById('blocks-container');
        container.innerHTML = '';
        chain.forEach(block => {
            const details = document.createElement('details');
            const summary = document.createElement('summary');
            summary.innerHTML = `<strong>Block ${block.index}</strong> - Miner: ${block.miner} - Time: ${new Date(block.timestamp).toLocaleString()}`;
            details.appendChild(summary);

            const blockDetails = document.createElement('div');
            blockDetails.className = 'block-details';
            blockDetails.innerHTML = `
                <p><strong>Timestamp:</strong> ${new Date(block.timestamp).toLocaleString()}</p>
                <p><strong>Previous Hash:</strong> ${block.previous_hash}</p>
                <p><strong>Merkle Hash:</strong> ${block.merkle_hash}</p>
                <p><strong>Nonce:</strong> ${block.nonce}</p>
                <p><strong>Mining Difficulty:</strong> ${block.mining_difficulty}</p>
                <h3>Transactions:</h3>
            `;
            block.data.forEach(tx => {
                const txDetails = document.createElement('details');
                const txSummary = document.createElement('summary');
                txSummary.innerHTML = `<strong>Transaction ID:</strong> ${tx.txid}`;
                txDetails.appendChild(txSummary);

                const txInfo = document.createElement('div');
                txInfo.className = 'transaction-details';
                txInfo.innerHTML = `
                    <p><strong>Sender:</strong> ${tx.raw_data.sender}</p>
                    <p><strong>Receiver:</strong> ${tx.raw_data.receiver}</p>
                    <p><strong>Amount:</strong> ${tx.raw_data.amount}</p>
                    <p><strong>Signature:</strong> ${tx.signature || 'Not signed'}</p>
                `;
                txDetails.appendChild(txInfo);
                blockDetails.appendChild(txDetails);
            });
            details.appendChild(blockDetails);
            container.appendChild(details);
        });

        if (pendingTransactions.length > 0) {
            const pendingHeader = document.createElement('h3');
            pendingHeader.textContent = 'Pending Transactions:';
            container.appendChild(pendingHeader);
            pendingTransactions.forEach(tx => {
                const txDiv = document.createElement('div');
                txDiv.textContent = `Pending TX: ${tx.txid} - Amount: ${tx.raw_data.amount} from ${tx.raw_data.sender} to ${tx.raw_data.receiver}`;
                container.appendChild(txDiv);
            });
        }
    }

    document.getElementById('update-info').addEventListener('click', () => {
        updateBlockchainInfo();
        startAutoUpdate();
    });

    document.getElementById('updateIntervalSlider').addEventListener('input', (e) => {
        intervalSeconds = parseInt(e.target.value);
        document.getElementById('intervalDisplay').textContent = intervalSeconds;
    });

    document.getElementById('updateIntervalSlider').addEventListener('change', () => {
        startAutoUpdate();
    });

    updateBlockchainInfo();
    startAutoUpdate();
});