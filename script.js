console.log("JavaScript is working!");

const alertButton = document.getElementById("alertButton");

if (alertButton) {
    alertButton.addEventListener("click", function () {
        alert("You have new security alerts!");
    });
}

const searchInput = document.getElementById("searchInput");
const severityFilter = document.getElementById("severityFilter");
const threatTable = document.getElementById("threatTable");

if (searchInput && severityFilter && threatTable) {

    function filterThreats() {

        const searchText = searchInput.value.toLowerCase();
        const selectedSeverity = severityFilter.value;

        const rows = threatTable.getElementsByTagName("tr");

        for (let row of rows) {

            const rowText = row.textContent.toLowerCase();
            const severity = row.cells[2].textContent;

            const matchesSearch = rowText.includes(searchText);

            const matchesSeverity =
                selectedSeverity === "all" ||
                severity === selectedSeverity;

            if (matchesSearch && matchesSeverity) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        }
    }

    searchInput.addEventListener("input", filterThreats);

    severityFilter.addEventListener("change", filterThreats);
}