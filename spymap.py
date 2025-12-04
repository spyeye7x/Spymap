import socket
import re
import concurrent.futures
import time

# اسم الأداة وثوابت الإعدادات
TOOL_NAME = "SPYMAP"
TIMEOUT = 0.8
DEFAULT_IP = "127.0.0.1"
DEFAULT_PORTS = "21-25, 80, 443, 8080"

# ----------------------------------------------------
# 1. المكونات الأساسية (Banner and Parser)
# ----------------------------------------------------

def display_banner():
    """
    عرض شعار الأداة SPYMAP بشكل بارز باستخدام ASCII Art.
    """
    banner = """
  ███████╗██████╗   ██╗  ██╗███╗   ███╗ █████╗ ██████╗ 
  ██╔════╝██╔══██╗  ╚██╗██╔╝████╗ ████║██╔══██╗██╔══██╗
  ███████╗██████╔╝   ╚███╔╝ ██╔████╔██║███████║██████╔╝
  ╚════██║██╔═══╝    ██╔██╗ ██║╚██╔╝██║██╔══██║██╔══██╗
  ███████║██║       ██╔╝ ██╗██║ ╚═╝ ██║██║  ██║██║  ██║
  ╚══════╝╚═╝       ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
             
        >> Simple Port and Your Map for Security <<
    """
    print("\033[96m" + banner + "\033[0m") # طباعة باللون السماوي البارز

def parse_ports(port_range_str):
    """
    تحليل سلسلة نصية من المنافذ (مثل '21, 80-85, 443') إلى قائمة أرقام المنافذ.
    """
    ports = set()
    parts = re.findall(r'\d+-\d+|\d+', port_range_str)
    
    for part in parts:
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 1 <= start <= end <= 65535:
                    for port in range(start, end + 1):
                        ports.add(port)
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                continue
    
    return sorted(list(ports))

# ----------------------------------------------------
# 2. وظيفة جلب/حل عنوان IP (Option 1)
# ----------------------------------------------------

def resolve_ip():
    """
    يطلب من المستخدم اسم نطاق ويقوم بحل عنوان IP المقابل له.
    """
    print("\n" + "=" * 50)
    target_domain = input("أدخل اسم النطاق (مثال: example.com): ")
    print("=" * 50)
    
    if not target_domain:
        print("\033[91m[!] لم يتم إدخال اسم نطاق.\033[0m")
        return

    try:
        # استخدام دالة socket.gethostbyname لحل اسم النطاق إلى عنوان IP
        resolved_ip = socket.gethostbyname(target_domain)
        
        print("\n\033[92m[+] عملية جلب عنوان IP ناجحة:\033[0m")
        print("-" * 50)
        print(f"  الهدف (Domain): {target_domain}")
        print(f"  عنوان IP (Resolved IP): \033[96m{resolved_ip}\033[0m")
        print("-" * 50)
        
    except socket.gaierror:
        print(f"\n\033[91m[!] خطأ: تعذر حل اسم النطاق '{target_domain}'. تحقق من الاسم أو اتصال الإنترنت.\033[0m")
    except Exception as e:
        print(f"\n\033[91m[!] حدث خطأ غير متوقع: {e}\033[0m")

# ----------------------------------------------------
# 3. وظيفة فحص المنافذ (Option 2)
# ----------------------------------------------------

def check_port(target_ip, port):
    """
    تحاول إنشاء اتصال TCP مع المنفذ المحدد.
    """
    common_services = {
        21: ("FTP", "Weak/Legacy Auth"), 22: ("SSH", "Strong/Encrypted"),
        23: ("Telnet", "Very Weak/Plaintext"), 80: ("HTTP", "Unencrypted Web"),
        443: ("HTTPS", "Strong/TLS/SSL"), 3306: ("MySQL", "Database"),
        3389: ("RDP", "Remote Desktop"), 8080: ("HTTP-Proxy", "Custom Web App")
    }
    
    service, security = common_services.get(port, ("Unknown", "N/A"))
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    
    try:
        result_code = s.connect_ex((target_ip, port))
        
        if result_code == 0:
            return (port, "Open", service, security)
        
        return (port, "Closed", service, security)
            
    except socket.gaierror:
        return (port, "Error", "Host Not Found", "N/A")
    except socket.error:
        return (port, "Filtered", service, "Firewall Present")
    finally:
        s.close()

def port_scan_utility():
    """
    توجيه المستخدم لإدخال الهدف ونطاق المنافذ وتنفيذ الفحص.
    """
    print("\n" + "=" * 80)
    print(f"[*] تفعيل وضع فحص المنافذ في {TOOL_NAME}")
    print("=" * 80)

    target_input = input(f"أدخل عنوان IP أو اسم المضيف (الافتراضي: {DEFAULT_IP}): ") or DEFAULT_IP
    ports_input = input(f"أدخل نطاق المنافذ (الافتراضي: {DEFAULT_PORTS}): ") or DEFAULT_PORTS

    ports_to_scan = parse_ports(ports_input)
    
    if not ports_to_scan:
        print("\033[91m[!] خطأ: الرجاء إدخال نطاق منافذ صالح.\033[0m")
        return

    # محاولة حل IP في حال إدخال اسم نطاق
    try:
        target_ip = socket.gethostbyname(target_input)
    except socket.gaierror:
        print(f"\n\033[91m[!] خطأ: تعذر حل اسم المضيف أو IP غير صالح: '{target_input}'.\033[0m")
        return

    print("\n" + "=" * 80)
    print(f"[*] بدء الفحص لـ: {target_ip} ({len(ports_to_scan)} منفذ)")
    print("=" * 80)
    
    start_time = time.time()
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_port, target_ip, port) for port in ports_to_scan}
        
        for future in concurrent.futures.as_completed(futures):
            try:
                port, status, service, security = future.result()
                
                if status == "Open":
                    print(f"[+] المنفذ {port:<5} | الحالة: \033[92m{status:<8}\033[0m | الخدمة: {service:<15} | الحماية المتوقعة: {security}")
                    open_ports.append(future.result())
                elif status == "Filtered":
                    print(f"[!] المنفذ {port:<5} | الحالة: \033[93m{status:<8}\033[0m | الخدمة: {service:<15} | تنبيه: قد يكون هناك جدار ناري.")
                
            except Exception as e:
                pass # تجاهل أخطاء الخيوط البسيطة


    end_time = time.time()
    
    # تلخيص النتائج
    print("\n" + "=" * 80)
    print(f"ملخص نتائج فحص {TOOL_NAME} النهائي:")
    print(f"الهدف: {target_ip}")
    print(f"إجمالي المنافذ المفتوحة: {len(open_ports)}")
    print(f"المدة الكلية للفحص: {end_time - start_time:.2f} ثانية")
    print("=" * 80)

# ----------------------------------------------------
# 4. القائمة الرئيسية (Main Menu Loop)
# ----------------------------------------------------

def display_menu():
    """
    عرض خيارات القائمة الرئيسية.
    """
    print("\n\033[94m" + "=" * 40)
    print("    القائمة الرئيسية لـ SPYMAP")
    print("=" * 40 + "\033[0m")
    print("\033[92m1\033[0m: جلب/حل عنوان IP من اسم نطاق (Domain)")
    print("\033[92m2\033[0m: كشف المنافذ المفتوحة (Port Scanning)")
    print("\033[91m3\033[0m: خروج (Exit)")
    print("-" * 40)

def main():
    """
    الدالة الرئيسية التي تدير حلقة القائمة.
    """
    display_banner()

    print("\n" * 2)
    print("!" * 60)
    print(f"تذكير: {TOOL_NAME} تستخدم Sockets حقيقية لإجراء الفحص.")
    print("يرجى استخدامها بشكل أخلاقي وعلى الأنظمة المسموح بفحصها فقط.")
    print("!" * 60)
    
    while True:
        display_menu()
        choice = input("اختر رقماً من القائمة: ").strip()

        if choice == '1':
            resolve_ip()
        elif choice == '2':
            port_scan_utility()
        elif choice == '3':
            print("\n\033[96m[+] شكراً لاستخدام SPYMAP. إلى اللقاء!\033[0m")
            break
        else:
            print("\n\033[91m[!] خيار غير صالح. الرجاء إدخال رقم من القائمة.\033[0m")

if __name__ == "__main__":
    main()
