"""
Test script for code modification API
"""
import json
import requests
from datetime import datetime

# API endpoint
BASE_URL = "http://localhost:8006"

def test_create_request():
    """Test creating a code modification request"""
    print("=" * 60)
    print("測試 1: 建立程式碼修改請求")
    print("=" * 60)
    
    request_data = {
        "source": "orchestrate",
        "type": "vulnerability_fix",
        "vulnerability_info": {
            "project_name": "sentinel-flow-demo",
            "version": "1.0.0",
            "severity": "HIGH",
            "vulnerability_type": "SQL_INJECTION",
            "affected_files": [
                "account-service/app/main.py"
            ],
            "description": "SQL injection vulnerability detected in user query endpoint"
        },
        "modification_request": {
            "action": "fix_vulnerability",
            "details": "修復 SQL injection 漏洞，使用參數化查詢替代字串拼接",
            "priority": "high"
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/code-modification/request",
            json=request_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ 請求建立成功!")
            print(f"  Request ID: {result['request_id']}")
            print(f"  Status: {result['status']}")
            print(f"  Message: {result['message']}")
            return result['request_id']
        else:
            print(f"✗ 請求失敗: {response.status_code}")
            print(f"  {response.text}")
            return None
    except requests.exceptions.ConnectionError:
        print("✗ 無法連接到服務器。請確保 blackduck-service 正在運行。")
        print("  啟動命令: cd blackduck-service && python -m uvicorn app.main:app --port 8006")
        return None
    except Exception as e:
        print(f"✗ 錯誤: {e}")
        return None


def test_get_status(request_id):
    """Test getting request status"""
    print("\n" + "=" * 60)
    print("測試 2: 查詢請求狀態")
    print("=" * 60)
    
    try:
        response = requests.get(
            f"{BASE_URL}/code-modification/status/{request_id}",
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ 狀態查詢成功!")
            print(f"  Request ID: {result['request_id']}")
            print(f"  Status: {result['status']}")
            print(f"  Timestamp: {result['timestamp']}")
            print(f"  Vulnerability: {result['vulnerability_info']['vulnerability_type']}")
            print(f"  Affected Files: {', '.join(result['vulnerability_info']['affected_files'])}")
        else:
            print(f"✗ 查詢失敗: {response.status_code}")
            print(f"  {response.text}")
    except Exception as e:
        print(f"✗ 錯誤: {e}")


def test_list_requests():
    """Test listing all requests"""
    print("\n" + "=" * 60)
    print("測試 3: 列出所有請求")
    print("=" * 60)
    
    try:
        response = requests.get(
            f"{BASE_URL}/code-modification/list",
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ 列表查詢成功!")
            print(f"  總共 {result['total']} 個請求")
            
            for req in result['requests'][:3]:  # Show first 3
                print(f"\n  - Request ID: {req['request_id']}")
                print(f"    Status: {req['status']}")
                print(f"    Type: {req['vulnerability_info']['vulnerability_type']}")
                print(f"    Priority: {req['modification_request']['priority']}")
        else:
            print(f"✗ 查詢失敗: {response.status_code}")
            print(f"  {response.text}")
    except Exception as e:
        print(f"✗ 錯誤: {e}")


def test_update_status(request_id):
    """Test updating request status"""
    print("\n" + "=" * 60)
    print("測試 4: 更新請求狀態")
    print("=" * 60)
    
    try:
        response = requests.post(
            f"{BASE_URL}/code-modification/update-status/{request_id}",
            params={
                "new_status": "completed",
                "result": "Successfully fixed SQL injection vulnerability using parameterized queries"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ 狀態更新成功!")
            print(f"  Request ID: {result['request_id']}")
            print(f"  Old Status: {result['old_status']}")
            print(f"  New Status: {result['new_status']}")
            print(f"  Message: {result['message']}")
        else:
            print(f"✗ 更新失敗: {response.status_code}")
            print(f"  {response.text}")
    except Exception as e:
        print(f"✗ 錯誤: {e}")


def main():
    print("\n" + "🚀 " * 20)
    print("程式碼修改 API 測試")
    print("🚀 " * 20 + "\n")
    
    # Test 1: Create request
    request_id = test_create_request()
    
    if request_id:
        # Test 2: Get status
        test_get_status(request_id)
        
        # Test 3: List all requests
        test_list_requests()
        
        # Test 4: Update status
        test_update_status(request_id)
        
        # Test 5: Get updated status
        print("\n" + "=" * 60)
        print("測試 5: 查詢更新後的狀態")
        print("=" * 60)
        test_get_status(request_id)
    
    print("\n" + "=" * 60)
    print("測試完成!")
    print("=" * 60)
    print("\n下一步:")
    print("1. 檢查 .code-requests/ 目錄中的 JSON 檔案")
    print("2. 通知 Bob (Roo Cline) 處理 pending 請求")
    print("3. Bob 會讀取請求、分析並修改程式碼")
    print("4. Bob 完成後會更新狀態為 completed")
    print()


if __name__ == "__main__":
    main()

# Made with Bob
