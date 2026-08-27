import pytest
from unittest.mock import patch, Mock
import json
from app.intelligence.ct import collect_ct_assets

def test_ct_normalization_and_dedupe():
    mock_resp = Mock()
    mock_resp.status_code = 200
    data = [
        {"name_value": "*.example.com"},
        {"name_value": "www.example.com."},
        {"name_value": "www.example.com"},
        {"name_value": "test.example.com\n*.test.example.com"},
        {"name_value": "example.com"},
        {"name_value": "malicious-example.com"} # should be filtered out
    ]
    mock_resp.iter_bytes.return_value = [json.dumps(data).encode('utf-8')]
    
    mock_cm = Mock()
    mock_cm.__enter__ = Mock(return_value=mock_resp)
    mock_cm.__exit__ = Mock(return_value=None)
    
    with patch("httpx.stream", return_value=mock_cm):
        res = collect_ct_assets("example.com")
        
        assert res["status"] == "success"
        # malicious-example.com does not end with .example.com
        assert set(res["hostnames"]) == {"example.com", "www.example.com", "test.example.com"}
        assert res["count"] == 3
        assert res["truncated"] == False

def test_ct_truncation():
    mock_resp = Mock()
    mock_resp.status_code = 200
    data = [{"name_value": f"sub{i}.example.com"} for i in range(150)]
    mock_resp.iter_bytes.return_value = [json.dumps(data).encode('utf-8')]
    
    mock_cm = Mock()
    mock_cm.__enter__ = Mock(return_value=mock_resp)
    mock_cm.__exit__ = Mock(return_value=None)
    
    with patch("httpx.stream", return_value=mock_cm):
        res = collect_ct_assets("example.com")
        
        assert res["status"] == "success"
        assert len(res["hostnames"]) == 100
        assert res["count"] == 100
        assert res["truncated"] == True

def test_ct_failure_isolation():
    import httpx
    with patch("httpx.stream", side_effect=httpx.TimeoutException("timeout")):
        res = collect_ct_assets("example.com")
        assert res["status"] == "timeout"
        assert res["hostnames"] == []
def test_ct_size_limit():
    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.iter_bytes.return_value = [b'a' * (2 * 1024 * 1024), b'a' * (4 * 1024 * 1024)]
    
    mock_cm = Mock()
    mock_cm.__enter__ = Mock(return_value=mock_resp)
    mock_cm.__exit__ = Mock(return_value=None)
    
    with patch('httpx.stream', return_value=mock_cm):
        res = collect_ct_assets('example.com')
        assert res['status'] == 'error'
        assert 'exceeded 5MB' in res['error']
