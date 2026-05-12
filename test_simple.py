"""
Simple test for code modification file system
"""
import json
from pathlib import Path
from datetime import datetime
import uuid

# Project root
PROJECT_DIR = Path(__file__).parent
CODE_REQUESTS_DIR = PROJECT_DIR / ".code-requests"

def create_test_request():
    """Create a test code modification request"""
    print("=" * 60)
    print("建立測試請求")
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
    
    # Save to pending directory
    pending_dir = CODE_REQUESTS_DIR / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    
    request_file = pending_dir / f"{request_id}.json"
    
    with open(request_file, 'w', encoding='utf-8') as f:
        json.dump(request_data, f, indent=2, ensure_ascii=False)
    
    print(f"✓ 請求已建立!")
    print(f"  Request ID: {request_id}")
    print(f"  檔案路徑: {request_file}")
    print(f"  檔案大小: {request_file.stat().st_size} bytes")
    
    return request_id, request_file


def read_request(request_file):
    """Read and display request"""
    print("\n" + "=" * 60)
    print("讀取請求內容")
    print("=" * 60)
    
    with open(request_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"✓ 請求讀取成功!")
    print(f"  Request ID: {data['request_id']}")
    print(f"  Status: {data['status']}")
    print(f"  Source: {data['source']}")
    print(f"  Type: {data['type']}")
    print(f"\n  漏洞資訊:")
    print(f"    - 專案: {data['vulnerability_info']['project_name']}")
    print(f"    - 版本: {data['vulnerability_info']['version']}")
    print(f"    - 嚴重性: {data['vulnerability_info']['severity']}")
    print(f"    - 類型: {data['vulnerability_info']['vulnerability_type']}")
    print(f"    - 受影響檔案: {', '.join(data['vulnerability_info']['affected_files'])}")
    print(f"\n  修改請求:")
    print(f"    - 動作: {data['modification_request']['action']}")
    print(f"    - 優先級: {data['modification_request']['priority']}")
    print(f"    - 詳情: {data['modification_request']['details']}")


def list_all_requests():
    """List all requests in all status directories"""
    print("\n" + "=" * 60)
    print("列出所有請求")
    print("=" * 60)
    
    total = 0
    for status in ["pending", "processing", "completed", "failed"]:
        status_dir = CODE_REQUESTS_DIR / status
        if status_dir.exists():
            files = list(status_dir.glob("*.json"))
            count = len(files)
            total += count
            print(f"  {status:12s}: {count} 個請求")
            
            # Show first 2 files in each status
            for f in files[:2]:
                print(f"    - {f.name}")
    
    print(f"\n✓ 總共 {total} 個請求")


def main():
    print("\n" + "🧪 " * 20)
    print("簡單檔案系統測試")
    print("🧪 " * 20 + "\n")
    
    print(f"請求目錄: {CODE_REQUESTS_DIR}\n")
    
    # Create test request
    request_id, request_file = create_test_request()
    
    # Read request
    read_request(request_file)
    
    # List all requests
    list_all_requests()
    
    print("\n" + "=" * 60)
    print("測試完成!")
    print("=" * 60)
    print(f"\n✓ 測試請求已建立: {request_id}")
    print(f"✓ 檔案位置: {request_file}")
    print("\n下一步:")
    print("1. 檢查 .code-requests/pending/ 目錄")
    print("2. 通知 Bob 處理這個請求")
    print("3. Bob 會讀取、分析並修改程式碼")
    print()


if __name__ == "__main__":
    main()

# Made with Bob
