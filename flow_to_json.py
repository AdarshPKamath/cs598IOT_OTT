import json
from mitmproxy.io import FlowReader
from mitmproxy.exceptions import FlowReadException
from mitmproxy.net.http.http1.assemble import assemble_request, assemble_response

INPUT_FILE = "flows.flow"
OUTPUT_FILE = "signedin_youtube.json"

flows = []
with open(INPUT_FILE, "rb") as f:
    reader = FlowReader(f)
    try:
        for flow in reader.stream():
            if flow.response:
                try:
                    flows.append({
                        "timestamp": str(flow.request.timestamp_start),
                        "host": flow.request.host,
                        "method": flow.request.method,
                        "url": flow.request.pretty_url,
                        "status_code": flow.response.status_code,
                        "request_headers": dict(flow.request.headers),
                        "response_headers": dict(flow.response.headers),
                        "request_body": flow.request.get_text(),
                        "response_body": flow.response.get_text(),
                        "content_type": flow.response.headers.get("Content-Type", "")
                    })
                except Exception as e:
                    print("Skipped malformed flow:", e)
    except FlowReadException as e:
        print(f"Flow file corrupt: {e}")

# Save to a JSON array
with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    json.dump(flows, out, ensure_ascii=False, indent=2)

print(f"✅ Exported {len(flows)} flows to {OUTPUT_FILE}")
