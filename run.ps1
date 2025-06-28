# Set UTF-8 encoding
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

# Change to the ExpenseTracker directory
Set-Location -Path "ExpenseTracker"

# Run the Flask app
python app.py 