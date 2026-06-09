raw_logs = []
processed_logs = []


def clean_logs(raw_text):
    translation_table = str.maketrans("", "", "!@#$")
    cleaned_text = raw_text.translate(translation_table)

    logs = [log.strip() for log in cleaned_text.split(";") if log.strip()]

    return logs


def filter_danger_logs():
    global processed_logs

    processed_logs = [
        log
        for log in raw_logs
        if "ERROR" in log.upper() or "CRITICAL" in log.upper()
    ]

    return processed_logs


def mask_ip_logs():
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
    global raw_logs

    print("\n--- NẠP DỮ LIỆU LOG ---")

    user_input = input(
        "Nhập chuỗi log thô (cách nhau bởi dấu ;): "
    )

    raw_logs = clean_logs(user_input)

    print(
        f"Đã làm sạch và lưu {len(raw_logs)} dòng log vào hệ thống."
    )


def show_danger_logs():
    if not raw_logs:
        print("Chưa có dữ liệu log, vui lòng thực hiện chức năng 1")
        return

    result = filter_danger_logs()

    print("\n--- LỌC CẢNH BÁO ---")

    if result:
        print(f"Tìm thấy {len(result)} cảnh báo nguy hiểm:")
        for log in result:
            print(f"- {log}")
    else:
        print("Không tìm thấy cảnh báo nguy hiểm.")


def show_masked_logs():
    if not raw_logs:
        print("Chưa có dữ liệu log, vui lòng thực hiện chức năng 1")
        return

    if not processed_logs:
        filter_danger_logs()

    masked_logs = mask_ip_logs()

    print("\n--- MÃ HÓA IP ---")

    if masked_logs:
        print("Báo cáo log an toàn:")
        for index, log in enumerate(masked_logs, start=1):
            print(f"{index}. {log}")
    else:
        print("Không có log nguy hiểm để mã hóa.")


def main():
    while True:
        print("\n============= SECURITY LOG ANALYZER =============")
        print("1. Nhập và làm sạch dữ liệu Log thô")
        print("2. Lọc các Log cảnh báo mức độ cao (ERROR/CRITICAL)")
        print("3. Mã hóa địa chỉ IP (Masking)")
        print("4. Đóng hệ thống")
        print("=================================================")

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