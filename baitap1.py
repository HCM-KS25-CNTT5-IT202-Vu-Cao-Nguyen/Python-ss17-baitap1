raw_logs = []
processed_logs = []


def clean_logs(raw_text):
    """
    Làm sạch chuỗi log thô do người dùng nhập vào.

    Quy trình:
    - Dùng str.maketrans() và str.translate() để loại bỏ các ký tự không mong muốn (!@#$).
    - Dùng split(';') để tách thành danh sách các dòng log riêng biệt.
    - Dùng strip() để xóa khoảng trắng thừa ở đầu/cuối mỗi phần tử.

    Parameters:
        raw_text (str): Chuỗi log thô do người dùng nhập, các dòng cách nhau bởi dấu chấm phẩy.

    Returns:
        list[str]: Danh sách các dòng log đã được làm sạch.
    """
    translation_table = str.maketrans("", "", "!@#$")
    cleaned_text = raw_text.translate(translation_table)

    logs = [log.strip() for log in cleaned_text.split(";") if log.strip()]

    return logs


def filter_danger_logs():
    """
    Lọc các dòng log có mức độ nguy hiểm cao từ danh sách raw_logs toàn cục.

    Chỉ giữ lại các dòng chứa từ khóa 'ERROR' hoặc 'CRITICAL' (không phân biệt hoa thường).
    Kết quả được lưu vào biến toàn cục processed_logs.

    Returns:
        list[str]: Danh sách các dòng log chứa cảnh báo ERROR hoặc CRITICAL.
    """
    global processed_logs

    processed_logs = [
        log
        for log in raw_logs
        if "ERROR" in log.upper() or "CRITICAL" in log.upper()
    ]

    return processed_logs


def mask_ip_logs():
    """
    Ẩn danh địa chỉ IP trong các dòng log nguy hiểm đã được lọc.

    Với mỗi dòng trong processed_logs, hàm tìm các từ có định dạng địa chỉ IPv4
    (4 phần cách nhau bởi dấu chấm), sau đó thay thế phần thứ 3 và thứ 4 bằng '*'
    để bảo vệ thông tin nhạy cảm.

    Ví dụ: '192.168.1.100' -> '192.168.*.*'

    Returns:
        list[str]: Danh sách các dòng log đã được ẩn danh địa chỉ IP.
    """
    masked_logs = []

    for log in processed_logs:
        words = log.split()

        for i, word in enumerate(words):
            if word.count(".") == 3:
                ip_parts = word.split(".")

                if len(ip_parts) == 4:
                    ip_parts[2] = "*"
                    ip_parts[3] = "*"

                    words[i] = ".".join(ip_parts)

        masked_logs.append(" ".join(words))

    return masked_logs


def load_log_data():
    """
    Nhận dữ liệu log thô từ người dùng, làm sạch và lưu vào raw_logs toàn cục.

    Nhắc người dùng nhập chuỗi log thô (các dòng cách nhau bởi dấu ';'),
    gọi clean_logs() để xử lý, sau đó cập nhật biến toàn cục raw_logs
    và thông báo số dòng log đã được lưu thành công.

    Returns:
        None
    """
    global raw_logs

    print("\n NẠP DỮ LIỆU LOG")

    user_input = input(
        "Nhập chuỗi log thô (cách nhau bởi dấu ;): "
    )

    raw_logs = clean_logs(user_input)

    print(
        f"Đã làm sạch và lưu {len(raw_logs)} dòng log vào hệ thống."
    )


def show_danger_logs():
    """
    Hiển thị các dòng log có cảnh báo mức độ cao ra màn hình.

    Kiểm tra xem raw_logs đã có dữ liệu chưa. Nếu chưa, yêu cầu người dùng
    thực hiện chức năng nạp dữ liệu trước. Nếu có, gọi filter_danger_logs()
    và in kết quả, hoặc thông báo nếu không tìm thấy log nguy hiểm nào.

    Returns:
        None
    """
    if not raw_logs:
        print("Chưa có dữ liệu log, vui lòng thực hiện chức năng 1")
        return

    result = filter_danger_logs()

    print("\n LỌC CẢNH BÁO")

    if result:
        print(f"Tìm thấy {len(result)} cảnh báo nguy hiểm:")
        for log in result:
            print(f"{log}")
    else:
        print("Không tìm thấy cảnh báo nguy hiểm.")


def show_masked_logs():
    """
    Hiển thị báo cáo log an toàn sau khi đã ẩn danh địa chỉ IP.

    Kiểm tra xem raw_logs đã có dữ liệu chưa. Nếu processed_logs chưa được
    tạo, tự động gọi filter_danger_logs() trước. Sau đó gọi mask_ip_logs()
    và in danh sách log đã được ẩn danh IP theo định dạng đánh số thứ tự.

    Returns:
        None
    """
    if not raw_logs:
        print("Chưa có dữ liệu log, vui lòng thực hiện chức năng 1")
        return

    if not processed_logs:
        filter_danger_logs()

    masked_logs = mask_ip_logs()

    print("\n MÃ HÓA IP")

    if masked_logs:
        print("Báo cáo log an toàn:")
        for index, log in enumerate(masked_logs, start=1):
            print(f"{index}. {log}")
    else:
        print("Không có log nguy hiểm để mã hóa.")


def main():
    """
    Vòng lặp chính của chương trình Security Log Analyzer.

    Hiển thị menu với 4 lựa chọn và điều hướng đến chức năng tương ứng:
        1. Nhập và làm sạch dữ liệu log thô.
        2. Lọc log cảnh báo mức độ cao (ERROR/CRITICAL).
        3. Ẩn danh địa chỉ IP trong log nguy hiểm.
        4. Thoát chương trình.

    Vòng lặp tiếp tục cho đến khi người dùng chọn '4' để đóng hệ thống.

    Returns:
        None
    """
    while True:
        print("\n============= SECURITY LOG ANALYZER ============= ")
        print("1. Nhập và làm sạch dữ liệu Log thô ")
        print("2. Lọc các Log cảnh báo mức độ cao (ERROR/CRITICAL)")
        print("3. Mã hóa địa chỉ IP (Masking)")
        print("4. Đóng hệ thống")
        print("================================================= ")

        choice = input("Chọn chức năng (1-4): ")

        if choice == "1":
            load_log_data()

        elif choice == "2":
            show_danger_logs()

        elif choice == "3":
            show_masked_logs()

        elif choice == "4":
            print("Đóng hệ thống. Tạm biệt!")
            break

        else:
            print("Lựa chọn không hợp lệ.")

main()