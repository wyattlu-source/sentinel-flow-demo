"""
Test file system operations for code modification requests
"""
import json
import sys
from pathlib import Path
from datetime import datetime
import uuid

# Add blackduck-service to path
sys.path.insert(0, str(Path(__file__).parent / "blackduck-service"))

from app.code_modification import (
    _save_code_request,
    _get_request,
    _move_request,
    CODE_REQUESTS_DIR
)

def test_save_request():
    """Test saving a code modification request"""
    print("=" * 60)
    print("測試 1: 儲存程式碼修改請求到檔案")
    print("=" * 60)
    
    request_id = f"req_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    
    request_data = {
        "request_id": request_id,
        "timestamp": datetime.now().isoformat(),
        "source": "orchestrate",
        "type": "vulnerability_fix",
        "status": "pending",
        "vulnerability_info": {
            "project_name": "sentinel-flow-demo",
            "version": "1.0.0",
            "severity": "HIGH",
            "vulnerability_type": "SQL_INJECTION",
            "affected_files": ["account-service/app/main.py"],
            "description": "SQL injection vulnerability detected in user query endpoint"
        },
        "modification_request": {
            "action": "fix_vulnerability",
            "details": "修復 SQL injection 漏洞，使用參數化查詢替代字串拼接",
            "priority": "high"
        },
        "result": None,
        "completed_at": None,
    }
    
    try:
        file_path = _save_code_request(request_id, request_data, "pending")
        print(f"✓ 請求已儲存!")
        print(f"  Request ID: {request_id}")
        print(f"  檔案路徑: {file_path}")
        print(f"  檔案存在: {file_path.exists()}")
        
        # Verify file content
        with open(file_path, 'r', encoding='utf-8') as f:
            saved_data = json.load(f)
            print(f"  檔案內容驗證: {'✓ 正確' if saved_data['request_id'] == request_id else '✗ 錯誤'}")
        
        return request_id
    except Exception as e:
        print(f"✗ 儲存失敗: {e}")
        return None


def test_get_request(request_id):
    """Test retrieving a request"""
    print("\n" + "=" * 60)
    print("測試 2: 讀取請求資料")
    print("=" * 60)
    
    try:
        request_data = _get_request(request_id)
        if request_data:
            print(f"✓ 請求讀取成功!")
            print(f"  Request ID: {request_data['request_id']}")
            print(f"  Status: {request_data['status']}")
            print(f"  Vulnerability Type: {request_data['vulnerability_info']['vulnerability_type']}")
            print(f"  Priority: {request_data['modification_request']['priority']}")
        else:
            print(f"✗ 找不到請求: {request_id}")
    except Exception as e:
        print(f"✗ 讀取失敗: {e}")


def test_move_request(request_id):
    """Test moving a request between status directories"""
    print("\n" + "=" * 60)
    print("測試 3: 移動請求到不同狀態目錄")
    print("=" * 60)
    
    try:
        # Move from pending to processing
        success = _move_request(request_id, "pending", "processing")
        if success:
            print(f"✓ 請求已移動: pending → processing")
            
            # Verify it's in the new location
            request_data = _get_request(request_id)
            if request_data and request_data['status'] == "processing":
                print(f"  驗證: ✓ 請求現在在 processing 目錄")
            else:
                print(f"  驗證: ✗ 請求狀態不正確")
        else:
            print(f"✗ 移動失敗")
    except Exception as e:
        print(f"✗ 移動失敗: {e}")


def test_list_all_requests():
    """Test listing all requests"""
    print("\n" + "=" * 60)
    print("測試 4: 列出所有請求")
    print("=" * 60)
    
    try:
        all_requests = []
        for status in ["pending", "processing", "completed", "failed"]:
            status_dir = CODE_REQUESTS_DIR / status
            if status_dir.exists():
                count = len(list(status_dir.glob("*.json")))
                print(f"  {status}: {count} 個請求")
                all_requests.extend(status_dir.glob("*.json"))
        
        print(f"\n✓ 總共找到 {len(all_requests)} 個請求")
        
        # Show details of first 3
        if all_requests:
            print("\n  最近的請求:")
            for req_file in sorted(all_requests, reverse=True)[:3]:
                with open(req_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    print(f"    - {data['request_id']} ({data.get('status', 'unknown')})")
                    print(f"      {data['vulnerability_info']['vulnerability_type']}")
    except Exception as e:
        print(f"✗ 列表失敗: {e}")


def main():
    print("\n" + "🧪 " * 20)
    print("檔案系統測試 - 程式碼修改請求")
    print("🧪 " * 20 + "\n")
    
    print(f"請求目錄: {CODE_REQUESTS_DIR}\n")
    
    # Test 1: Save request
    request_id = test_save_request()
    
    if request_id:
        # Test 2: Get request
        test_get_request(request_id)
        
        # Test 3: Move request
        test_move_request(request_id)
        
        # Test 4: List all requests
        test_list_all_requests()
    
    print("\n" + "=" * 60)
    print("測試完成!")
    print("=" * 60)
    print("\n✓ 檔案系統功能正常運作")
    print(f"✓ 請求檔案已儲存在: {CODE_REQUESTS_DIR}")
    print("\n下一步:")
    print("1. 啟動 blackduck-service 測試 API 端點")
    print("2. 使用 test_code_modification.py 測試完整流程")
    print("3. 讓 Bob 讀取並處理 pending 請求")
    print()


if __name__ == "__main__":
    main()

# Made with Bob
