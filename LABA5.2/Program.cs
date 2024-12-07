using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFwTypeLib;
using SharpPcap;
using PacketDotNet;
using System.Runtime.InteropServices;


class FirewallAndScanner
{
    //Початок програми
    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("Виберіть операцію:");
        Console.WriteLine("1 - Налаштування брандмауера");
        Console.WriteLine("2 - Сканування мережі");
        Console.WriteLine("3 - Перехоплення мережевого трафіку");
        Console.Write("Введіть номер операції: ");
        int choice = int.Parse(Console.ReadLine());

        switch (choice)
        {
            case 1:
                ConfigureFirewall();
                break;
            case 2:
                NetworkScanner();
                break;
            case 3:
                NetworkTrafficSniffer();
                break;
            default:
                Console.WriteLine("Невірний вибір.");
                break;
        }
    }
    // Налаштування правил у брандмауері
    public static void ConfigureFirewall()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("\nНалаштування брандмауера...");
        bool continueConfiguring = true;

        while (continueConfiguring)
        {
            Console.WriteLine("\nДоступні дії:");
            Console.WriteLine("1 - Додати правило (блокування/дозвіл трафіку)");
            Console.WriteLine("2 - Вивести список поточних правил");
            Console.WriteLine("3 - Видалити правило");
            Console.WriteLine("4 - Завершити налаштування");
            Console.Write("Оберіть дію: ");
            int action = int.Parse(Console.ReadLine());

            switch (action)
            {
                case 1:
                    AddCustomFirewallRule();
                    break;

                case 2:
                    Console.WriteLine("\nСписок поточних правил:");
                    ListFirewallRules();
                    break;

                case 3:
                    Console.Write("\nВведіть ім'я правила, яке потрібно видалити: ");
                    string ruleName = Console.ReadLine();
                    RemoveFirewallRule(ruleName);
                    break;

                case 4:
                    continueConfiguring = false;
                    break;

                default:
                    Console.WriteLine("Невірний вибір. Спробуйте ще раз.");
                    break;
            }
        }

        Console.WriteLine("\nНалаштування завершено.");
    }
    // Додавання користувацького правила до брандмауера
    private static void AddCustomFirewallRule()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            Console.Write("\nВведіть ім'я правила: ");
            string ruleName = Console.ReadLine();

            Console.Write("Введіть IP-адресу (або * для всіх, LocalSubnet): ");
            string remoteIP = Console.ReadLine();

            if (!string.Equals(remoteIP, "*", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(remoteIP, "LocalSubnet", StringComparison.OrdinalIgnoreCase) &&
                !System.Net.IPAddress.TryParse(remoteIP, out _))
            {
                throw new ArgumentException("Некоректний формат IP-адреси.");
            }

            Console.Write("Виберіть протокол (TCP/UDP/All): ");
            string protocol = Console.ReadLine();

            Console.Write("Введіть номер порту (або 0 для всіх портів): ");
            if (!int.TryParse(Console.ReadLine(), out int port) || port < 0 || port > 65535)
            {
                throw new ArgumentException("Некоректний номер порту.");
            }

            Console.Write("Виберіть для якого трафіку воно буде (1 - Вхідний, 2 - Вихідний): ");
            NET_FW_RULE_DIRECTION_ direction = Console.ReadLine() == "1"
                ? NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN
                : NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;

            Console.Write("Виберіть дію (1 - Дозволити, 2 - Заборонити): ");
            bool allow = Console.ReadLine() == "1";

            AddFirewallRule(ruleName, remoteIP, protocol, port, direction, allow);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка додавання правила: {ex.Message}");
        }
    }
    // Додає правило до брандмауера
    public static void AddFirewallRule(string ruleName, string remoteIP, string protocol, int port, NET_FW_RULE_DIRECTION_ direction, bool allow)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            Type firewallType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(firewallType);

            INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
            firewallRule.Name = ruleName;
            firewallRule.Description = $"Rule to {(allow ? "allow" : "block")} traffic.";
            firewallRule.Action = allow ? NET_FW_ACTION_.NET_FW_ACTION_ALLOW : NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            firewallRule.Enabled = true;
            firewallRule.Direction = direction;

            // Встановлення віддалених адрес
            firewallRule.RemoteAddresses = remoteIP;

            // Встановлення протоколу та портів
            if (protocol.Equals("All", StringComparison.OrdinalIgnoreCase))
            {
                firewallRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                firewallRule.LocalPorts = null; // Порти не встановлюються для All
            }
            else if (protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            {
                firewallRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                firewallRule.LocalPorts = port > 0 ? port.ToString() : null;
            }
            else if (protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
            {
                firewallRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP;
                firewallRule.LocalPorts = port > 0 ? port.ToString() : null;
            }
            else
            {
                throw new ArgumentException("Невідомий протокол.");
            }

            firewallPolicy.Rules.Add(firewallRule);
            Console.WriteLine($"[Брандмауер] Правило '{ruleName}' успішно створено.");
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Помилка доступу: будь ласка, запустіть програму від імені адміністратора.");
        }
        catch (COMException ex)
        {
            Console.WriteLine($"Помилка COM-об'єкта: {ex.Message}. Переконайтеся, що брандмауер Windows увімкнено.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Невідома помилка: {ex.Message}");
        }
    }
    // Виводить список правил у брандмауері
    public static void ListFirewallRules()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            Type firewallType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(firewallType);

            foreach (INetFwRule rule in firewallPolicy.Rules)
            {
                string protocolName = GetProtocolName(rule.Protocol);
                Console.WriteLine($"Правило: {rule.Name}, Дія: {rule.Action}, Напрямок: {rule.Direction}, Протокол: {protocolName}, Дистанційні адреси: {rule.RemoteAddresses}");
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Помилка доступу: будь ласка, запустіть програму від імені адміністратора.");
        }
        catch (COMException ex)
        {
            Console.WriteLine($"Помилка COM-об'єкта: {ex.Message}. Переконайтеся, що брандмауер Windows увімкнено.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Невідома помилка: {ex.Message}");
        }
    }
    private static string GetProtocolName(int protocolNumber)
    {
        return protocolNumber switch
        {
            6 => "TCP",               
            17 => "UDP",               
            1 => "ICMP",               
            58 => "ICMPv6",            
            2 => "IGMP",               
            256 => "Any",              
            _ => $"Unknown ({protocolNumber})"
        };
    }
    // Видаляє правило з брандмауера
    public static void RemoveFirewallRule(string ruleName)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            Type firewallType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(firewallType);

            bool ruleFound = false;
            foreach (INetFwRule rule in firewallPolicy.Rules)
            {
                if (rule.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase))
                {
                    firewallPolicy.Rules.Remove(ruleName);
                    Console.WriteLine($"[Брандмауер] Правило '{ruleName}' успішно видалено.");
                    ruleFound = true;
                    break;
                }
            }

            if (!ruleFound)
            {
                Console.WriteLine($"[Брандмауер] Правило '{ruleName}' не знайдено.");
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Помилка доступу: будь ласка, запустіть програму від імені адміністратора.");
        }
        catch (COMException ex)
        {
            Console.WriteLine($"Помилка COM-об'єкта: {ex.Message}. Переконайтеся, що брандмауер Windows увімкнено.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Невідома помилка: {ex.Message}");
        }
    }

    // Метод для сканування мережі
    public static void NetworkScanner()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        try
        {
            // Введення початкової IP-адреси
            Console.WriteLine("Введіть початкову IP-адресу для сканування (наприклад, 192.168.1.1):");
            string startIP = Console.ReadLine();
            if (!IPAddress.TryParse(startIP, out _))
            {
                throw new FormatException("Неправильний формат початкової IP-адреси.");
            }

            // Введення кінцевої IP-адреси
            Console.WriteLine("Введіть кінцеву IP-адресу для сканування (наприклад, 192.168.1.10):");
            string endIP = Console.ReadLine();
            if (!IPAddress.TryParse(endIP, out _))
            {
                throw new FormatException("Неправильний формат кінцевої IP-адреси.");
            }

            // Введення портів
            Console.WriteLine("Введіть список портів для перевірки (наприклад, 80, 443-445, 8080):");
            string portsInput = Console.ReadLine();
            var ports = ParsePortsSafe(portsInput);
            if (ports == null || !ports.Any())
            {
                throw new ArgumentException("Невірний формат списку портів. Введіть порти у форматі: 80, 443-445.");
            }

            Console.WriteLine("\nСканування мережі...\n");

            // Сканування мережі
            var results = ScanNetworkRangeAsync(startIP, endIP, ports).Result;

            // Групуємо та сортуємо результати для виведення
            var groupedResults = results.GroupBy(r => r.IP).OrderBy(g => g.Key);

            // Виведення результатів у зрозумілому форматі
            foreach (var group in groupedResults)
            {
                Console.WriteLine($"Хост: {group.Key}");
                foreach (var result in group.OrderBy(r => r.Port))
                {
                    Console.WriteLine($"  Порт: {result.Port}, Статус: {result.Status}, Сервіс: {result.Service}");
                }
            }
        }
        catch (FormatException ex)
        {
            Console.WriteLine($"Помилка формату вводу: {ex.Message}");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Помилка аргументів: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Невідома помилка під час сканування: {ex.Message}");
        }

        Console.WriteLine("\nСканування завершено.");
    }

    // Метод для безпечного парсингу портів з введеного користувачем рядка
    public static IEnumerable<int> ParsePortsSafe(string input)
    {
        try
        {
            var ports = new List<int>();

            foreach (var part in input.Split(','))
            {
                if (part.Contains('-'))
                {
                    var range = part.Split('-').Select(int.Parse).ToArray();
                    if (range.Length != 2 || range[0] > range[1] || range[0] < 1 || range[1] > 65535)
                    {
                        throw new ArgumentException($"Невірний діапазон портів: {part}");
                    }
                    ports.AddRange(Enumerable.Range(range[0], range[1] - range[0] + 1));
                }
                else
                {
                    int port = int.Parse(part);
                    if (port < 1 || port > 65535)
                    {
                        throw new ArgumentException($"Невірний порт: {port}");
                    }
                    ports.Add(port);
                }
            }

            return ports.Distinct();
        }
        catch (Exception)
        {
            return null; // Повертаємо null у разі помилки
        }
    }
    // Асинхронне сканування діапазону IP-адрес
    public static async Task<List<ScanResult>> ScanNetworkRangeAsync(string startIP, string endIP, IEnumerable<int> ports)
    {
        Console.WriteLine($"Скануємо діапазон IP: {startIP} - {endIP}");
        Console.WriteLine($"Список портів для сканування: {string.Join(", ", ports)}");

        var start = IPAddress.Parse(startIP);
        var end = IPAddress.Parse(endIP);

        long startNum = IPAddressToLong(start);
        long endNum = IPAddressToLong(end);

        if (startNum > endNum)
        {
            throw new ArgumentException("Початкова IP-адреса не може бути більшою за кінцеву.");
        }

        var results = new List<ScanResult>();
        var tasks = new List<Task<List<ScanResult>>>();

        // Скануємо кожну IP-адресу
        for (var ip = start; IPAddressToLong(ip) <= endNum; ip = IncrementIP(ip))
        {
            string ipAddress = ip.ToString();
            tasks.Add(ScanPortsAsync(ipAddress, ports));
        }

        // Чекаємо на завершення всіх завдань
        try
        {
            var resultsArray = await Task.WhenAll(tasks);
            foreach (var resultList in resultsArray)
            {
                if (resultList != null)
                {
                    results.AddRange(resultList);
                }
                else
                {
                    Console.WriteLine("Попередження: Один із результатів сканування був null.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка під час виконання завдань: {ex.Message}");
            throw;
        }

        return results;
    }

    // Асинхронне сканування портів для одного хоста
    public static async Task<List<ScanResult>> ScanPortsAsync(string host, IEnumerable<int> ports)
    {
        var results = new List<ScanResult>();
        var tasks = ports.Select(port => ScanPortAsync(host, port));

        try
        {
            var portResults = await Task.WhenAll(tasks);

            // Фільтруємо результати
            results.AddRange(portResults.Where(r => r != null));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка під час сканування портів хоста {host}: {ex.Message}");
            throw;
        }

        return results;
    }
    // Асинхронне сканування одного порту
    public static async Task<ScanResult> ScanPortAsync(string host, int port)
    {
        try
        {
            using (var client = new TcpClient())
            {
                // Підключення до хоста
                var connectTask = client.ConnectAsync(host, port);

                if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask)
                {
                    // Зчитування банера сервісу
                    string banner = GetServiceBanner(client);

                    // Якщо банер порожній, встановлюємо ім'я за портом
                    if (string.IsNullOrEmpty(banner))
                    {
                        banner = GetServiceByPort(port);
                    }

                    return new ScanResult
                    {
                        IP = host,
                        Port = port,
                        Status = "Відкритий",
                        Service = banner
                    };
                }
            }
        }
        catch { }

        return new ScanResult
        {
            IP = host,
            Port = port,
            Status = "Закритий",
            Service = "Невідомо"
        };
    }

    public static string GetServiceBanner(TcpClient client)
    {
        try
        {
            var stream = client.GetStream();
            var buffer = new byte[512];
            stream.ReadTimeout = 2000; 
            int bytesRead = stream.Read(buffer, 0, buffer.Length);

            return Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
        }
        catch
        {
            return null;
        }
    }
    // Словник портів для відомих сервісів
    public static string GetServiceByPort(int port)
    {
        var knownServices = new Dictionary<int, string>
    {
        { 80, "HTTP" },
        { 443, "HTTPS" },
        { 22, "SSH" },
        { 25, "SMTP" },
        { 110, "POP3" },
        { 143, "IMAP" },
        { 3306, "MySQL" },
        { 5000, "MyServer" },
        { 8080, "HTTP Proxy" }
    };

        return knownServices.TryGetValue(port, out string service) ? service : "Невідомий сервіс";
    }
    // Перетворення IP-адреси у числовий формат
    public static long IPAddressToLong(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }

    // Інкремент IP-адреси
    public static IPAddress IncrementIP(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        for (int i = bytes.Length - 1; i >= 0; i--)
        {
            if (++bytes[i] != 0)
                break;
        }
        return new IPAddress(bytes);
    }

    // Парсинг портів із підтримкою діапазонів
    public static IEnumerable<int> ParsePorts(string input)
    {
        var ports = new List<int>();

        foreach (var part in input.Split(','))
        {
            if (part.Contains('-'))
            {
                var range = part.Split('-').Select(int.Parse).ToArray();
                ports.AddRange(Enumerable.Range(range[0], range[1] - range[0] + 1));
            }
            else
            {
                ports.Add(int.Parse(part));
            }
        }

        return ports.Distinct();
    }

    // Вкладений клас для зберігання результатів сканування
    public class ScanResult
    {
        public string IP { get; set; }
        public int Port { get; set; }
        public string Status { get; set; }
        public string Service { get; set; }
    }

    //Перехоплення мережевого трафіку
    private static Dictionary<string, int> suspiciousActivities = new();
    private static List<(string PacketInfo, bool IsSuspicious)> capturedPackets = new(); // Список для збереження пакетів
    private static bool isCapturing = false; // Флаг для управління перехопленням
    private static readonly string LogFilePath = "CapturedPackets.txt"; // Шлях до файлу для збереження

    //Перехоплення мережевого трафіку
    public static void NetworkTrafficSniffer()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("Перехоплення мережевого трафіку...");

        // Отримання списку мережевих інтерфейсів
        var devices = CaptureDeviceList.Instance;
        if (devices.Count < 1)
        {
            Console.WriteLine("Не знайдено мережевих інтерфейсів.");
            return;
        }

        // Виведення списку інтерфейсів
        Console.WriteLine("Доступні інтерфейси:");
        for (int i = 0; i < devices.Count; i++)
        {
            Console.WriteLine($"{i}: {devices[i].Description}");
        }
        Console.Write("Оберіть інтерфейс (номер): ");
        int deviceIndex = int.Parse(Console.ReadLine() ?? "0");

        // Вибір інтерфейсу
        var device = devices[deviceIndex];
        device.Open(); // Відкриття інтерфейсу в стандартному режимі

        Console.WriteLine($"Початок захоплення пакетів на інтерфейсі: {device.Description}...");
        isCapturing = true; // Початок перехоплення
        Thread captureThread = new(() => StartPacketCapture(device));
        captureThread.Start();

        Console.WriteLine("Натисніть Enter для завершення...");
        Console.ReadLine();

        isCapturing = false; // Зупинка перехоплення
        device.Close();
        Console.WriteLine("Перехоплення завершено.");

        // Запис пакетів у файл
        SavePacketsToFile();

        // Перегляд захоплених пакетів
        ViewCapturedPackets();
    }
    //Запуск захоплення пакетів
    private static void StartPacketCapture(ICaptureDevice device)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            device.OnPacketArrival += (sender, e) =>
            {
                if (!isCapturing) return;

                try
                {
                    var rawCapture = e.GetPacket();
                    var rawPacket = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

                    var ipPacket = rawPacket.Extract<IPPacket>();
                    if (ipPacket == null) return;

                    string sourceIP = ipPacket.SourceAddress.ToString();
                    string destIP = ipPacket.DestinationAddress.ToString();
                    string protocol = ipPacket.Protocol.ToString();

                    bool isSuspicious = DetectSuspiciousActivity(sourceIP);

                    string packetInfo = $"Пакет від {sourceIP} до {destIP}, Протокол: {protocol}";
                    capturedPackets.Add((packetInfo, isSuspicious)); // Збереження інформації про пакет
                    Console.WriteLine(packetInfo);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Помилка обробки пакету: {ex.Message}");
                }
            };

            device.Capture(); // Запуск захоплення пакетів
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка запуску захоплення: {ex.Message}");
        }
    }
    //Виявлення підозрілої активності у трафіку
    private static bool DetectSuspiciousActivity(string sourceIP)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        if (!suspiciousActivities.ContainsKey(sourceIP))
        {
            suspiciousActivities[sourceIP] = 0;
        }

        suspiciousActivities[sourceIP]++;
        if (suspiciousActivities[sourceIP] > 100)
        {
            Console.ForegroundColor = ConsoleColor.Red; // Червоний текст
            Console.WriteLine($"⚠️ Попередження! Підозріла активність від {sourceIP}");
            Console.ResetColor();
            return true; // Пакет підозрілий
        }

        return false; // Пакет не підозрілий
    }
    //Збереження перехоплених пакетів у файл
    private static void SavePacketsToFile()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            using (var writer = new StreamWriter(LogFilePath))
            {
                foreach (var (packetInfo, isSuspicious) in capturedPackets)
                {
                    string line = isSuspicious ? $"[Підозрілий] {packetInfo}" : packetInfo;
                    writer.WriteLine(line);
                }
            }
            Console.WriteLine($"Пакети успішно збережені у файл: {LogFilePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка запису у файл: {ex.Message}");
        }
    }
    //Перегляд захоплених пакетів
    private static void ViewCapturedPackets()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("\nЗахоплені пакети:");
        if (capturedPackets.Count == 0)
        {
            Console.WriteLine("Немає захоплених пакетів.");
        }
        else
        {
            foreach (var (packetInfo, isSuspicious) in capturedPackets)
            {
                if (isSuspicious)
                {
                    Console.ForegroundColor = ConsoleColor.Red; // Червоний текст для підозрілих
                }
                Console.WriteLine(packetInfo);
                Console.ResetColor();
            }
        }
    }
}