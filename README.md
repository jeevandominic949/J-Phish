# J-Phish
 phishing URL Detector

# J-Phish – Phishing URL Detection System

## Project Overview
J-Phish is a web-based phishing URL detection application that uses Machine Learning and Rule-Based Detection to identify potentially malicious or suspicious website links.

Users can enter a URL and receive a detection result along with the phishing probability, risk score and identified warning signs.

## Technologies Used
- Python
- Flask
- HTML, CSS and JavaScript
- Scikit-learn
- Pandas
- Joblib
- Random Forest Classifier

## Main Features
- Machine Learning-based URL analysis.
- Rule-based suspicious URL detection.
- Trusted-domain verification.
- Phishing probability calculation.
- Risk score and warning explanations.
- Simple web interface.

## Project Files
- `app.py` – Flask backend and API.
- `detector.py` – Main phishing detection logic.
- `feature_extraction.py` – Extracts URL features.
- `trainmodel.py` – Trains and saves the ML model.
- `test_detector.py` – Automated tests.
- `index.html` – Frontend interface.
- `phish_model.joblib` – Trained ML model.
- `PhiUSIIL_Phishing_URL_Dataset.csv` – Training dataset.

## Installation

Install the required libraries:

`pip install flask pandas numpy scikit-learn joblib`

## Run the Application

Execute:

`python app.py`

Open your browser and visit:

`http://127.0.0.1:5000/`

## Train the Model

To train the model again, run:

`python trainmodel.py`

## Run Tests

Execute:

`python -m unittest test_detector.py`

## Disclaimer
J-Phish is an educational cybersecurity project. Its results are predictions and do not guarantee that a website is safe or malicious.
