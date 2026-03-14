from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from ip_blocker import IPBlocker

app = Flask(__name__)

# Load Model and Resources
try:
    model = joblib.load("model/ddos_rf_model.pkl")
    feature_names = joblib.load("model/feature_names.pkl")
    print("✅ Model and Feature Names Loaded Successfully")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None
    feature_names = []

# Initialize IP Blocker
blocker = IPBlocker()

@app.route('/')
def index():
    blocked_ips = blocker.get_blocked_ips()
    return render_template('index.html', blocked_ips=blocked_ips)

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({'error': 'Model not loaded'}), 500

    try:
        # Get data from form or JSON
        data = request.json or request.form
        
        # Create input dataframe
        input_data = {feature: 0 for feature in feature_names}
        
        # Helper to get float from dict with a safe default
        def get_safe_float(key, default=0.0):
            val = data.get(key)
            if val == "" or val is None:
                return default
            try:
                return float(val)
            except ValueError:
                return default

        # Update with provided values (basic simulation mapping)
        input_data['Flow Packets/s'] = get_safe_float('flow_packets_s')
        input_data['Flow Bytes/s'] = get_safe_float('flow_bytes_s')
        input_data['Total Fwd Packets'] = get_safe_float('total_fwd_packets')
        input_data['Total Backward Packets'] = get_safe_float('total_bwd_packets')
        input_data['Total Length of Fwd Packets'] = get_safe_float('total_len_fwd')
        input_data['Total Length of Bwd Packets'] = get_safe_float('total_len_bwd')
        
        # Create DataFrame for prediction with exact columns from feature_names
        df = pd.DataFrame([input_data])
        df = df[feature_names] # Ensure correct order and set of columns
        
        # Make Prediction
        prediction = int(model.predict(df)[0]) # Cast to int for JSON serializability
        
        result = "Normal"
        is_blocked = False
        if prediction == 1:
            result = "DDoS Attack"
            is_blocked = True
            # Simulate Source IP (In a real scenario, this comes from the packet)
            source_ip = data.get('source_ip', '192.168.1.100') 
            blocker.block_ip(source_ip, reason="ML Detection: High Traffic Anomaly")
            
        return jsonify({
            'prediction': result,
            'blocked': is_blocked,
            'source_ip': data.get('source_ip', 'Unknown')
        })

    except Exception as e:
        print(f"ERROR in /predict: {e}") # Print for server logs
        return jsonify({'error': str(e)}), 400

@app.route('/unblock', methods=['POST'])
def unblock():
    ip = request.json.get('ip')
    if ip:
        if blocker.unblock_ip(ip):
            return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
    return jsonify({'success': False, 'message': 'IP not found or error'})

@app.route('/unblock_all', methods=['POST'])
def unblock_all():
    if blocker.clear_all():
        return jsonify({'success': True, 'message': 'All IPs unblocked'})
    return jsonify({'success': False, 'message': 'Error clearing block list'})

@app.route('/api/stats')
def stats():
    # Simple mock stats for the dashboard
    # In a real app, you'd track these in a database or global counter
    blocked_count = len(blocker.get_blocked_ips())
    return jsonify({
        'blocked_ips': blocked_count,
        'status': 'Active'
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
