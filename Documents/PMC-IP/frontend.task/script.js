document.getElementById('convertBtn').addEventListener('click', () => {
  const input = document.getElementById('inputField').value.trim();
  const resultArea = document.getElementById('resultArea');
  resultArea.innerHTML = 'Loading...';

  fetch(`http://localhost:8080/convert-measurements?input=${encodeURIComponent(input)}`)
      .then(response => {
          if (!response.ok) {
              throw new Error('Server error or invalid response');
          }
          return response.json();
      })
      .then(data => {
          resultArea.innerHTML = `Result: [${data.join(', ')}]`;
      })
      .catch(error => {
          resultArea.innerHTML = `Error: ${error.message}`;
      });
});

document.getElementById('historyBtn').addEventListener('click', () => {
  const resultArea = document.getElementById('resultArea');
  resultArea.innerHTML = 'Loading history...';

  fetch('http://localhost:8080/history')
      .then(response => {
          if (!response.ok) {
              throw new Error('Could not fetch history');
          }
          return response.json();
      })
      .then(history => {
          if (history.length === 0) {
              resultArea.innerHTML = 'No history available.';
              return;
          }
          const historyHtml = history.map(item => `<li>${item.input} -> [${item.output.join(', ')}]</li>`).join('');
          resultArea.innerHTML = `<ul>${historyHtml}</ul>`;
      })
      .catch(error => {
          resultArea.innerHTML = `Error: ${error.message}`;
      });
});

document.getElementById('clearBtn').addEventListener('click', () => {
  document.getElementById('resultArea').innerHTML = '';
});
