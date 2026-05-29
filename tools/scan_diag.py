import sys
from pathlib import Path
proj_root = Path(__file__).resolve().parents[1]
if str(proj_root) not in sys.path:
    sys.path.insert(0, str(proj_root))

from modules.wifi_analysis import WiFiAnalyzer
import json

wa = WiFiAnalyzer()
print('OS:', wa._os)
try:
    nets = wa.scan_networks()
    print('Networks found:', len(nets))
    print(json.dumps(nets[:20], indent=2))
    # Create a DataBridge and set reports to exercise the UI pipeline
    from ui.data_bridge import DataBridge
    db = DataBridge()
    report = wa.run_analysis()
    db.set_reports(wifi_report=report)
    snap = db.get_reports()
    wr = snap.get('wifi_report')
    print('DataBridge stored wifi_report nearby_networks:', len(getattr(wr, 'nearby_networks', [])))
except Exception as e:
    print('Scan failed:', e)
