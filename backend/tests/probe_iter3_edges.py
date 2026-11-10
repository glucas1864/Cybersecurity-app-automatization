# Edge probes for batch IOC + timeline (iteration 3)
import os, requests
from dotenv import load_dotenv
load_dotenv("/app/frontend/.env")
API = os.environ.get("EXPO_PUBLIC_BACKEND_URL").rstrip("/") + "/api"
s = requests.Session()
tok = s.post(f"{API}/auth/login", json={"email": "debug-blue@example.com", "password": "BlueTeam123!"}).json()["token"]
s.headers["Authorization"] = f"Bearer {tok}"

r = s.post(f"{API}/ioc/lookup/batch", json={"indicators": ["Example.com", "example.com", "EXAMPLE[.]COM"]})
print("case dedup:", r.status_code, [i["indicator"] for i in r.json()["items"]])
r = s.post(f"{API}/ioc/lookup/batch", json={"indicators": ["hxxps://bad[.]com/x", "HXXP://bad.com"]})
print("hxxp:", r.status_code, [(i["indicator"], i["ioc_type"]) for i in r.json()["items"]])
r = s.post(f"{API}/ioc/lookup/batch", json={"indicators": ["a" * 20000]})
print("huge item:", r.status_code, len(r.text))
r = s.post(f"{API}/ioc/lookup/batch", json={"indicators": [123]})
print("non-str:", r.status_code)
r = s.post(f"{API}/ioc/lookup/batch", json={"indicators": ["999.1.1.1", "::1"]})
print("bad ip/ipv6:", r.status_code, [(i["indicator"], i["ioc_type"], i["classification"]) for i in r.json()["items"]])

# timeline: checklist then evidence later -> checklist event timestamp
inc = s.post(f"{API}/incidents", json={"title": "TEST_timeline ts"}).json()
s.post(f"{API}/incidents/{inc['id']}/checklist/contain")
import time; time.sleep(1.5)
ev = s.post(f"{API}/incidents/{inc['id']}/evidence", json={"content": "TEST later"}).json()
tl = s.get(f"{API}/incidents/{inc['id']}/timeline").json()
print("order:", [(e["kind"], e["at"]) for e in tl["events"]])
# toggle back -> checklist disappears
s.post(f"{API}/incidents/{inc['id']}/checklist/contain")
tl = s.get(f"{API}/incidents/{inc['id']}/timeline").json()
print("after untoggle kinds:", [e["kind"] for e in tl["events"]])
r = s.post(f"{API}/incidents/{inc['id']}/checklist/does-not-exist")
print("bad checklist id:", r.status_code)
