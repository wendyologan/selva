// Function to fetch and update diary entries table
function updateDiaryEntriesTable() {
  fetch('/therapist/dashboard/entries')
    .then((response) => response.json())
    .then((data) => {
      const tableBody = document.querySelector('table tbody');
      tableBody.innerHTML = ''; // Clear the table body

      if (data.length > 0) {
        data.forEach((entry, index) => {
          const row = document.createElement('tr');
          const entryNumber = data.length - index;
          const formattedDate = formatDate(entry.date);
          row.innerHTML = `
            <td>${entryNumber}</td>
            <td>${formattedDate}</td>
            <td>${entry.client_name}</td>
            <td>${entry.header}</td>
          `;
          row.classList.add("row");
          row.dataset.entryId = entry.id; // Use correct attribute
          tableBody.appendChild(row);
        });

        // Add click event listener to each row
        const rows = document.querySelectorAll(".row");
        rows.forEach(row => {
          row.addEventListener("click", function() {
            const url = `/diary_entry/${this.dataset.entryId}`;
            if (url) {
              console.log("URL: ", url);
              window.location.href = url;
            }
          });
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

document.addEventListener("DOMContentLoaded", function() {
  updateDiaryEntriesTable();
});

function formatDate(dateStr) {
  const dateObj = new Date(dateStr);
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  const year = dateObj.getFullYear();
  return `${month}/${day}/${year}`;
}
      
// Function to get the CSRF token from cookies
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}
