from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import numpy as np
import pickle
from elasticsearch import Elasticsearch
import json
import os

# ---------------------------
# Load model pipeline
# ---------------------------
with open("iot_anomaly_pipeline.pkl", "rb") as f:
    model_package = pickle.load(f)

binary_model = model_package["binary_model"]
multi_model = model_package["multi_model"]
attack_map = model_package["attack_type_mapping"]





with open("column_stats.json", "r") as f:
    COLUMN_STATS = json.load(f)

# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI(
    title="IoT Anomaly Detection API",
    description="Predicts whether traffic is malicious and identifies attack type",
    version="1.0"
)
# Connect to Elasticsearch (adjust user/pass if security is enabled)
es = Elasticsearch(
    ["https://host.docker.internal:9200"],  
    basic_auth=("elastic", "insert_your_password"),
    verify_certs=False
)
# ---------------------------
# Input data model
from pydantic import BaseModel, Field

class TrafficLog(BaseModel):
    Src_Port:float
    Dst_Port:float
    Protocol:float
    Flow_Duration:float
    Total_Fwd_Packet:float
    Total_Bwd_packets:float
    Total_Length_of_Fwd_Packet:float
    Total_Length_of_Bwd_Packet:float
    Fwd_Packet_Length_Max:float
    Fwd_Packet_Length_Min:float
    Fwd_Packet_Length_Mean:float
    Fwd_Packet_Length_Std:float
    Bwd_Packet_Length_Max:float
    Bwd_Packet_Length_Min:float
    Bwd_Packet_Length_Mean:float
    Bwd_Packet_Length_Std:float
    Flow_Bytes_s: float
    Flow_Packets_s:float
    Flow_IAT_Mean:float
    Flow_IAT_Std:float
    Flow_IAT_Max:float
    Flow_IAT_Min:float
    Fwd_IAT_Total:float
    Fwd_IAT_Mean:float
    Fwd_IAT_Std:float
    Fwd_IAT_Max	:float
    Fwd_IAT_Min	:float
    Bwd_IAT_Total:float
    Bwd_IAT_Mean:float
    Bwd_IAT_Std	:float
    Bwd_IAT_Max	:float
    Bwd_IAT_Min	:float
    Fwd_PSH_Flags:float
    Bwd_PSH_Flags:float
    Fwd_URG_Flags:float
    Bwd_URG_Flags:float
    Fwd_Header_Length:float
    Bwd_Header_Length:float
    Fwd_Packets_s:float
    Bwd_Packets_s:float
    Packet_Length_Min:float
    Packet_Length_Max:float
    Packet_Length_Mean:float
    Packet_Length_Std:float
    Packet_Length_Variance:float
    FIN_Flag_Count:float
    SYN_Flag_Count:float
    RST_Flag_Count:float
    PSH_Flag_Count:float
    ACK_Flag_Count:float
    URG_Flag_Count:float
    CWR_Flag_Count:float
    ECE_Flag_Count:float
    Down_Up_Ratio:float
    Average_Packet_Size	:float
    Fwd_Segment_Size_Avg:float
    Bwd_Segment_Size_Avg:float
    Fwd_Bytes_Bulk_Avg:	float
    Fwd_Packet_Bulk_Avg:float
    Fwd_Bulk_Rate_Avg:	float
    Bwd_Bytes_Bulk_Avg:	float
    Bwd_Packet_Bulk_Avg:float
    Bwd_Bulk_Rate_Avg:	float
    Subflow_Fwd_Packets	:float
    Subflow_Fwd_Bytes:	float
    Subflow_Bwd_Packets	:float
    Subflow_Bwd_Bytes:	float
    FWD_Init_Win_Bytes:	float
    Bwd_Init_Win_Bytes:	float
    Fwd_Act_Data_Pkts:	float
    Fwd_Seg_Size_Min:float
    Active_Mean:float
    Active_Std:	float
    Active_Max:	float
    Active_Min:	float
    Idle_Mean:float
    Idle_Std:float
    Idle_Max:float
    Idle_Min:float


def clean_single_row(df):
    df = df.copy()
    for col in df.select_dtypes(include=['number']).columns:
        if col in COLUMN_STATS:
            stats = COLUMN_STATS[col]
            # Step 1: Replace infinities with NaN
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)
            # Step 2: Fill NaN with training median
            df[col] = df[col].fillna(stats["median"])
            # Step 3: Clip using training mean ± 5*std
            upper_limit = stats["mean"] + 5 * stats["std"]
            lower_limit = stats["mean"] - 5 * stats["std"]
            df[col] = df[col].clip(lower_limit, upper_limit)
        else:
            # fallback for unknown columns
            df[col] = df[col].fillna(-1)
    return df   



# ---------------------------
# Prediction endpoint
# ---------------------------
@app.post("/predict")
def predict(log: TrafficLog):
    try:
        # Convert incoming JSON to DataFrame
        data = pd.DataFrame([log.dict()])

        # Clean the row using precomputed stats
        data_clean = clean_single_row(data)

        # Binary prediction
        binary_pred = binary_model.predict(data_clean)[0]

        if binary_pred == 0:
            result = {"prediction": "Benign", "attack_type": "none"}
        else:
            attack_pred = multi_model.predict(data_clean)[0]
            if attack_pred == 0:
                attack_type = "Unknown Attack"
            else:
                attack_type = attack_map.get(attack_pred, "Unknown Attack")
            result = {"prediction": "Malicious", "attack_type": attack_type}

        # ---------------------------
        # Index into Elasticsearch (for both benign and malicious)
        # ---------------------------
        doc = {
            "features": data_clean.fillna(-1).to_dict(orient="records")[0],
            "result": result,
            "timestamp": pd.Timestamp.now().isoformat()
        }
        es.index(index="iot-traffic", document=doc)

        return result

    except Exception as e:
        return {"error": str(e)}
