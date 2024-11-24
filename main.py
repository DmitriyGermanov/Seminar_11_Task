import nmap

def scan_ports(target, ports):
    scanner = nmap.PortScanner()

    print(f"Сканируем {target} на порты {ports}...")

    scanner.scan(hosts=target, ports=ports, arguments='-sT')

    for host in scanner.all_hosts():
        print(f"\nРезультаты для {host}:")
        if 'tcp' in scanner[host]:
            for port in scanner[host]['tcp']:
                state = scanner[host]['tcp'][port]['state']
                print(f"  Порт {port}: {state}")
        else:
            print("  TCP порты не найдены.")

if __name__ == "__main__":
    while True:
        print("\n=== Сканер портов ===")
        target = input("Введите IP или доменное имя для сканирования: ").strip()
        ports = input("Введите диапазон портов (например, 22-80): ").strip()

        if not target or not ports:
            print("IP и диапазон портов не могут быть пустыми!")
            continue

        scan_ports(target, ports)

        # Спрашиваем пользователя, хочет ли он завершить работу программы
        choice = input("\nХотите выполнить ещё одно сканирование? (да/нет): ").strip().lower()
        if choice != "да":
            print("Программа завершена.")
            break