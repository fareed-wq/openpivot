from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_validate_domain():
    response = client.post("/validate", json={"target": "EXAMPLE.COM"})
    assert response.status_code == 200
    assert response.json() == {
        "input": "EXAMPLE.COM",
        "normalized": "example.com",
        "type": "domain",
        "valid": True
    }

def test_validate_ipv4():
    response = client.post("/validate", json={"target": "8.8.8.8"})
    assert response.status_code == 200
    assert response.json() == {
        "input": "8.8.8.8",
        "normalized": "8.8.8.8",
        "type": "ipv4",
        "valid": True
    }

def test_validate_invalid():
    invalid_cases = [
        "192.168.1.1",
        "http://example.com",
        "localhost"
    ]
    for target in invalid_cases:
        response = client.post("/validate", json={"target": target})
        assert response.status_code == 422
        assert "detail" in response.json()
