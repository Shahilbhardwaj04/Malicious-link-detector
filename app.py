import os
import time
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from utils import (
    analyze_url,
    virus_total_check,
    get_ssl_info,
    get_domain_reputation,
    check_urlhaus,
    check_phishtank,
    compute_risk_score,
    cached_virus_total_check,
    cached_get_ssl_info,
    cached_get_domain_reputation,
    cached_check_urlhaus,
    cached_check_phishtank,
)

load_dotenv()

app = Flask(__name__)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def api_check():
    import concurrent.futures
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    heuristics = analyze_url(url)
    
    # Define tasks for concurrent execution
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    pt_key = os.getenv('PHISHTANK_API_KEY')
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Submit tasks
        vt_future = executor.submit(cached_virus_total_check, url, vt_key) if vt_key and vt_key != 'YOUR_API_KEY_HERE' else None
        ssl_future = executor.submit(cached_get_ssl_info, url)
        domain_future = executor.submit(cached_get_domain_reputation, url)
        urlhaus_future = executor.submit(cached_check_urlhaus, url)
        phishtank_future = executor.submit(cached_check_phishtank, url, pt_key)

        # Gather results with try/except
        def get_result(future, default=None):
            if not future: return default
            try:
                return future.result()
            except Exception as e:
                print(f"Error in background task: {e}")
                return {'error': str(e)}

        vt_result = get_result(vt_future)
        ssl_info = get_result(ssl_future)
        domain_info = get_result(domain_future)
        urlhaus = get_result(urlhaus_future)
        phishtank = get_result(phishtank_future)

    response = {
        'url': url,
        'heuristics': heuristics,
        'virustotal': vt_result,
        'ssl': ssl_info,
        'domain': domain_info,
        'urlhaus': urlhaus,
        'phishtank': phishtank
    }

    try:
        score = compute_risk_score(heuristics, vt_result, urlhaus, phishtank, domain_info, ssl_info)
        response['score'] = score
    except Exception as e:
        print(f"Error computing risk score: {e}")
        response['score_error'] = str(e)
        
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
