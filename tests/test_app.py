from app import app
 
 
def test_health_endpoint():
    resp = app.test_client().get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
 
 
def test_check_rejects_bad_port():
    resp = app.test_client().get("/check?host=example.com&port=abc")
    assert resp.status_code == 400
