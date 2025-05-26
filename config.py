# At the top of app.py or config.py
FIELD_TABLE_MAP = {
    # Patient related fields
    'admission_date': 'patients',
    'discharge_date': 'patients',
    'disease': 'patients',
    'blood_sugar': 'patients',
    'blood_pressure':'patients',
    'age': 'patients',
    'gender': 'patients',
    'department': 'patients',
    'hospital_id': 'patients',
    'allergies': 'patients',
    'recovery_time': 'admissions',
    'repeated_admissions':'admissions',
    
    # Program related fields
    'start_date': 'data_entries',
    'actual_end_date': 'data_entries',
    'people_participated': 'data_entries',
    'delay_reason': 'data_entries',
    
    # Policy related fields
    'policy_name': 'policy_inputs',
    'key_area': 'policy_inputs'
}

# Field data types and aggregation methods
FIELD_CONFIG = {
    'admission_date': {'type': 'date', 'aggregation': 'count'},
    'discharge_date': {'type': 'date', 'aggregation': 'count'},
    'disease': {'type': 'categorical', 'aggregation': 'count'},
    'blood_sugar': {'type': 'numeric', 'aggregation': 'avg'},
    'blood_pressure': {'type': 'numeric', 'aggregation': 'avg'},
    'age': {'type': 'numeric', 'aggregation': 'avg'},
    'gender': {'type': 'categorical', 'aggregation': 'count'},
    'department': {'type': 'categorical', 'aggregation': 'count'},
    'hospital_id': {'type': 'categorical', 'aggregation': 'count'},
    'allergies': {'type': 'categorical', 'aggregation': 'count'},
    'start_date': {'type': 'date', 'aggregation': 'count'},
    'actual_end_date': {'type': 'date', 'aggregation': 'count'},
    'people_participated': {'type': 'numeric', 'aggregation': 'sum'},
    'delay_reason': {'type': 'categorical', 'aggregation': 'count'},
    'policy_name': {'type': 'categorical', 'aggregation': 'count'},
    'key_area': {'type': 'categorical', 'aggregation': 'count'}
}

# Chart type recommendations based on data types
CHART_TYPE_MAP = {
    ('date', 'numeric'): 'line',
    ('date', 'categorical'): 'bar',
    ('categorical', 'numeric'): 'bar',
    ('categorical', 'categorical'): 'pie',
    ('numeric', 'numeric'): 'scatter'
}

JOIN_PATHS = {
    ('patients', 'data_entries'): ['hospitals'],
    ('data_entries', 'patients'): ['hospitals'],
    ('patients', 'policy_inputs'): ['policy_involvement'],
    ('policy_inputs','patients'):['policy_involvement'],
    ('data_entries', 'policy_inputs'): ['program_id=policy_inputs.id'],
    ('policy_inputs','data_entries'):['program_id=policy_inputs.id'],
    ('hospitals','patients'):['hospital_id=hospitals.id'],
    ('patients','hospitals'):['hospital_id=hospitals.id'],
    ('patients','admissions'):['patient_id=patients.patient_id'],
    ('admissions','patients'):['patient_id=patients.patient_id']
    # Add more if needed
}