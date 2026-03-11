# Intelligent DDoS Detection and Prevention System

An End-to-End Machine Learning project for detecting and preventing DDoS attacks in real-time.

## Features
- **Real-Time Detection**: Uses Random Forest Classifier (99% Accuracy).
- **Automated IP Blocking**: Simulates firewall rules to block malicious IPs.
- **Web Dashboard**: Interactive Flask interface for monitoring and simulation.
- **Visual Analytics**: Graphs for feature importance and confusion matrix.

## Installation

1. **Prerequisites**:
   - Python 3.8+
   - pip

2. **Install Dependencies**:
   ```bash
   pip install flask pandas numpy joblib scikit-learn matplotlib
   ```

## How to Run
1. **Navigate to Project Directory**:
   ```bash
   cd d:\DDOS_ML_PROJECT
   ```

2. **Start the Application**:
   ```bash
   python app.py
   ```

3. **Open Dashboard**:
   Go to `http://localhost:5000` in your web browser.

## Project Structure
- `app.py`: Main web application file.
- `ip_blocker.py`: Module handling IP blocking logic.
- `generate_graphs.py`: Script to generate performance visualizations.
- `model/`: Directory containing the trained ML model.
- `dataset/`: Directory containing the dataset CSV.
- `docs/`: Deployment and thesis documentation templates.
- `static/`: Generated graphs and assets.
- `templates/`: HTML templates for the web interface.

## Usage Guide
1. **Dashboard**: View the list of currently blocked IPs and system status.
2. **Simulation**: Use the form on the dashboard to test "Attack" scenarios vs "Normal" scenarios.
   - **Attack Preset**: Sets high packet rate, triggers detection and blocking.
   - **Normal Preset**: Sets low packet rate, shows "Normal Traffic".
3. **Unblock**: Manually unblock IPs from the dashboard table.

## Documentation
- **Final Report Structure**: See `docs/final_report_structure.md` for thesis outline.
- **Viva Preparation**: See `docs/viva_questions.md` for Q&A guide.
