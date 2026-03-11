# Viva Questions & Answers

## Core ML Concepts
### Q1: Why did you choose Random Forest?
**A:** Random Forest is an ensemble learning method that combines multiple decision trees to improve accuracy and prevent overfitting. It handles large datasets well and provides feature importance metrics, which is crucial for identifying key attack characteristics.

### Q2: Why not SVM or Deep Learning?
**A:** 
- **SVM:** Computationally expensive for large datasets like CICIDS.
- **Deep Learning (CNN/LSTM):** Requires more computational power and longer training times. Random Forest provides a good balance of speed and accuracy (99%+).

### Q3: What is "Overfitting"? How did you prevent it?
**A:** Overfitting happens when a model learns noise in the training data instead of the underlying pattern. Random Forest prevents this by averaging multiple decision trees trained on random subsets of data (Bootstrapping).

### Q4: Explain Precision vs. Recall in DDoS context.
**A:** 
- **Precision:** Of all traffic predicted as "Attack", how many were actually attacks? (High precision means few false alarms).
- **Recall:** Of all actual attacks, how many did we catch? (High recall means we don't miss attacks).
- **DDoS Priority:** Recall is often more critical because missing an attack is dangerous.

## Project Specifics
### Q5: How does your IP Blocking work?
**A:** When the model predicts traffic as "DDoS Attack" (Label 1), the system extracts the source IP from the packet. It adds this IP to a blacklist (simulated in a JSON file/database). Future packets from this IP are dropped/blocked until an administrator reviews them.

### Q6: What dataset did you use?
**A:** CICIDS 2017 / 2018 (Canadian Institute for Cybersecurity). It is a standard benchmark dataset for Intrusion Detection Systems.

### Q7: What features were most important?
**A:** Typically `Flow Packets/s`, `Flow Bytes/s`, `Total Fwd Packets`, and `Packet Length Mean`. These features show the volume and intensity of traffic, which spikes during DDoS.

### Q8: Is your system real-time?
**A:** Yes, the Flask application processes simulated traffic in real-time. In a production environment, it would hook into a packet sniffer (like Scapy or Wireshark) to process live network packets.

## Future Scope
### Q9: How would you improve this project?
**A:** 
1. Implement Deep Learning (LSTM) for sequence prediction.
2. Deploy on Cloud (AWS/Azure) for scalability.
3. Integrate with hardware firewalls (Cisco/Juniper) using APIs.

### Q10: What are the limitations?
**A:**
- Currently simulates blocking (doesn't modify OS firewall).
- Dependent on the quality of training data (concept drift).
- Zero-day attacks might be missed if they don't match known patterns.
