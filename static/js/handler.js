document.addEventListener('DOMContentLoaded', () => {
    initializePage();
});

function initializePage() {
    generateMinerKeys();
    setupAutoUpdate();
    setupMiningToggle();
    setupFormListeners();
}
async function generateMinerKeys() {
    try {
        const response = await fetch('/miner_keys', {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
        });
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const keyPair = await response.json();
        updateKeyDisplay('minerPrivateKeyDisplay', `Private Key: ${keyPair.private_key}`);
        updateKeyDisplay('minerPublicKeyDisplay', `Public Key: ${keyPair.public_key}`);
    } catch (error) {
        console.error('Failed to generate miner keys:', error);
    }
}
let updateInterval;
let intervalSeconds = 30;

function setupAutoUpdate() {
    const updateInfoButton = document.getElementById('update-info');
    const intervalSlider = document.getElementById('updateIntervalSlider');
    const intervalDisplay = document.getElementById('intervalDisplay');

    updateInfoButton.addEventListener('click', () => {
        updateBlockchainInfo();
        startAutoUpdate();
    });

    intervalSlider.addEventListener('input', (e) => {
        intervalSeconds = parseInt(e.target.value);
        intervalDisplay.textContent = intervalSeconds;
    });

    intervalSlider.addEventListener('change', startAutoUpdate);

    updateBlockchainInfo();
    startAutoUpdate();
}

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
    chain.forEach(block => renderBlock(block, container));
    if (pendingTransactions.length > 0) renderPendingTransactions(pendingTransactions, container);
}
function renderBlock(block, container) {
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
    block.data.forEach(tx => renderTransaction(tx, blockDetails));
    details.appendChild(blockDetails);
    container.appendChild(details);
}
function renderTransaction(tx, container) {
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
    container.appendChild(txDetails);
}
function renderPendingTransactions(pendingTransactions, container) {
    const pendingHeader = document.createElement('h3');
    pendingHeader.textContent = 'Pending Transactions:';
    container.appendChild(pendingHeader);
    pendingTransactions.forEach(tx => {
        const txDiv = document.createElement('div');
        txDiv.textContent = `Pending TX: ${tx.txid} - Amount: ${tx.raw_data.amount} from ${tx.raw_data.sender} to ${tx.raw_data.receiver}`;
        container.appendChild(txDiv);
    });
}
function setupMiningToggle() {
    const miningSwitch = document.getElementById('miningSwitch');
    miningSwitch.addEventListener('change', () => {
        const stateControl = miningSwitch.checked ? 'ON' : 'OFF';
        fetch('/mine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ state_control: stateControl }),
        })
            .then(response => response.json())
            .then(data => {
                console.log('Mining state updated:', data);
                if (data.state === 'ON') {
                    miningSwitch.checked = true;
                    alert(data.status);
                } else {
                    miningSwitch.checked = false;
                    alert(data.status);
                }
            })
            .catch(error => {
                console.error('Error updating mining state:', error);
                alert('Failed to update mining state');
            });
    });
}
function setupFormListeners() {
    setupTransactionSubmit();
    setupConnectForm();
    setupKeyPairGeneration();
    setupGenesisBlockCreation();
    setupFaucetRequest();
    setupBalanceCheck();
}
function setupTransactionSubmit() {
    document.getElementById('transactionForm').addEventListener('submit', handleFormSubmit('/transaction/submit', {
        'senderPri': ['sender_private_key', 'string'],
        'senderPub': ['sender_public_key', 'string'],
        'receiver': ['receiver_public_key', 'string'],
        'amount': ['amount', 'float']
    }));
}

function setupConnectForm() {
    document.getElementById('connectForm').addEventListener('submit', handleFormSubmit('/connect', {
        'targetIp': ['des_ip', 'string'],
        'targetPort': ['des_port', 'number']
    }, {
        'src_ip': ['0.0.0.0', 'string'],
        'src_port': [0, 'number'],
        'public_key': ['', 'string'],
        'is_broadcast': [false, 'boolean'],
        'is_response': [false, 'boolean']
    }));
}

function setupFaucetRequest() {
    document.getElementById('faucetForm').addEventListener('submit', handleFormSubmit('/faucet', {
        'faucetPublicKey': ['public_key', 'string']
    }));
}

function setupBalanceCheck() {
    document.getElementById('balanceForm').addEventListener('submit', handleFormSubmit('/balance', {
        'publicKeyBalance': ['public_key', 'string']
    }, {}, (data) => {
        document.getElementById('balanceDisplay').textContent = `Balance: ${data.fixed_balance}(${data.pending_balance} pending)`;
    }));
}

function handleFormSubmit(url, idToNameTypeMap, additionalData = {}, onSuccess = defaultSuccessHandler) {
    return async function (event) {
        event.preventDefault();
        const data = Object.entries(idToNameTypeMap).reduce((acc, [id, [name, type]]) => {
            let value = document.getElementById(id).value;
            switch (type) {
                case 'number':
                    value = parseInt(value, 10);
                    break;
                case 'float':
                    value = parseFloat(value);
                    break;
                case 'boolean':
                    value = value === 'true' || value === '1';
                    break;
                default:
                    value = value;
            }
            acc[name] = value;
            return acc;
        }, {});

        Object.entries(additionalData).forEach(([key, value]) => {
            let type;
            if (Array.isArray(value)) {
                type = value[1];
                value = value[0];
            } else {
                type = 'string';
            }
            switch (type) {
                case 'number':
                    data[key] = parseInt(value, 10);
                    break;
                case 'float':
                    data[key] = parseFloat(value);
                    break;
                case 'boolean':
                    data[key] = value === true || value === 'true' || value === '1';
                    break;
                default:
                    data[key] = value;
            }
        });

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const result = await response.json();
            onSuccess(result);
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred: ' + error.message);
        }
    };
}
function setupKeyPairGeneration() {
    document.getElementById('generateKeyPair').addEventListener('click', async () => {
        try {
            const response = await fetch('/generate_key_pair', { method: 'GET' });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const keyPair = await response.json();
            updateKeyDisplay('privateKeyDisplay', `Private Key: ${keyPair.private_key}`);
            updateKeyDisplay('publicKeyDisplay', `Public Key: ${keyPair.public_key}`);
        } catch (error) {
            console.error('Failed to generate key pair:', error);
        }
    });
}
function setupGenesisBlockCreation() {
    document.getElementById('createGenesisBlock').addEventListener('click', async () => {
        try {
            const response = await fetch('/genesis_block', { method: 'POST' });
            const result = await response.json();
            alert(result.status || 'Genesis block created successfully!');
        } catch (error) {
            alert('Failed to create genesis block: ' + error.message);
        }
    });
}
function defaultSuccessHandler(data) {
    console.log('Success:', data);
    if (data.status) {
        alert(data.status);
    }
}
function updateKeyDisplay(elementId, content) {
    document.getElementById(elementId).textContent = content;
}