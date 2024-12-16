document.getElementById('transactionForm').addEventListener('submit', function (event) {
    event.preventDefault();

    const sender = document.getElementById('sender').value;
    const receiver = document.getElementById('receiver').value;
    const amount = parseFloat(document.getElementById('amount').value);

    fetch('/transaction/submit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ sender, receiver, amount })
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