# Tạo venv
python3 -m venv .venv

# Kích hoạt venv
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate      # Windows PowerShell
#run chương trình
sudo /media/haduckien/E/Tool/miniconda3/bin/conda run -n base --no-capture-output python app/capture_packet/ids_byte_deep.py --iface lo --filter "tcp port 80 or udp port 53"
wlx40ae30551234
eth0
sudo /media/haduckien/E/Tool/miniconda3/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
sudo /media/haduckien/E/Tool/miniconda3/bin/conda run -n base --no-capture-output python app/capture_packet/ids_byte_deep.py --iface wlx40ae30551234 --filter "tcp port 80"
