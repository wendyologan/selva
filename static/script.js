function updateDiaryEntriesTable() {
    fetch('/therapist/dashboard/entries')
      .then((response) => response.json())
      .then((data) => {
        const tableBody = document.querySelector('table tbody');
        tableBody.innerHTML = ''; // Clear the table body
  
        if (data.length > 0) {
          data.forEach((entry, index) => {
            const row = document.createElement('tr');
            const entryNumber = data.length - index; // Calculate the entry number in descending order
            row.innerHTML = `
              <td>${entryNumber}</td>
              <td>${entry.date}</td>
              <td>${entry.client_name}</td>
              <td>${entry.header}</td>
            `;
            tableBody.appendChild(row);
          });
        } else {
          const row = document.createElement('tr');
          row.innerHTML = `<td colspan="4" class="empty-message">No entries found.</td>`;
          tableBody.appendChild(row);
        }
      })
      .catch((error) => {
        console.error('Error fetching diary entries:', error);
      });
  }
  
  // Function to get the CSRF token from cookies
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }
  
// Call the function initially to populate the table
updateDiaryEntriesTable();
