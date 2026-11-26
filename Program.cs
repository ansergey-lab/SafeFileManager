using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using Microsoft.Data.Sqlite;

namespace SafeFileManager;

internal static class Program
{
    private static readonly string Root = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "Files"));
    private static readonly string DbPath = Path.Combine(
        AppContext.BaseDirectory, "filemanager.db");
    private static int _userId;
    private static string _username = "";

    private const long MaxArchiveBytes = 50 * 1024 * 1024; // 50 МБ
    private const int MaxArchiveEntries = 500;

    private static string ConnectionString =>
        new SqliteConnectionStringBuilder { DataSource = DbPath }.ToString();

    private static void Main()
    {
        Directory.CreateDirectory(Root);
        InitializeDatabase();

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("=== SAFE FILE MANAGER ===");

        if (!Authenticate())
            return;

        while (true)
        {
            Console.WriteLine($"\nПользователь: {_username}");
            Console.WriteLine("1. Диски и файловая система");
            Console.WriteLine("2. Просмотр файлов и каталогов");
            Console.WriteLine("3. Создать текстовый файл");
            Console.WriteLine("4. Прочитать файл");
            Console.WriteLine("5. Изменить текстовый файл");
            Console.WriteLine("6. Удалить файл");
            Console.WriteLine("7. Создать каталог");
            Console.WriteLine("8. Работа с JSON");
            Console.WriteLine("9. Работа с XML");
            Console.WriteLine("10. Создать ZIP-архив");
            Console.WriteLine("11. Распаковать ZIP-архив");
            Console.WriteLine("12. История операций");
            Console.WriteLine("0. Выход");
            Console.Write("Выберите действие: ");

            switch (Console.ReadLine())
            {
                case "1": ShowDrives(); break;
                case "2": ListFiles(); break;
                case "3": CreateTextFile(); break;
                case "4": ReadFile(); break;
                case "5": ModifyTextFile(); break;
                case "6": DeleteFile(); break;
                case "7": CreateDirectory(); break;
                case "8": JsonMenu(); break;
                case "9": XmlMenu(); break;
                case "10": CreateZip(); break;
                case "11": ExtractZip(); break;
                case "12": ShowHistory(); break;
                case "0": return;
                default: Console.WriteLine("Неизвестная команда."); break;
            }
        }
    }

    // ---------- БАЗА ДАННЫХ И АУТЕНТИФИКАЦИЯ ----------

    private static void InitializeDatabase()
    {
        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();

        string sql = """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NOT NULL,
                Salt TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Files (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                FileName TEXT NOT NULL,
                CreatedAt TEXT NOT NULL,
                Size INTEGER NOT NULL,
                Location TEXT NOT NULL,
                OwnerId INTEGER NOT NULL,
                UNIQUE(Location, OwnerId),
                FOREIGN KEY(OwnerId) REFERENCES Users(Id)
            );

            CREATE TABLE IF NOT EXISTS Operations (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Timestamp TEXT NOT NULL,
                OperationType TEXT NOT NULL,
                FileId INTEGER NULL,
                UserId INTEGER NOT NULL,
                Details TEXT NOT NULL,
                FOREIGN KEY(FileId) REFERENCES Files(Id) ON DELETE SET NULL,
                FOREIGN KEY(UserId) REFERENCES Users(Id)
            );
            """;

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static bool Authenticate()
    {
        while (true)
        {
            Console.WriteLine("\n1. Войти");
            Console.WriteLine("2. Зарегистрироваться");
            Console.WriteLine("0. Выход");
            Console.Write("Ваш выбор: ");
            string choice = Console.ReadLine() ?? "";

            if (choice == "0") return false;

            Console.Write("Логин: ");
            string username = (Console.ReadLine() ?? "").Trim();

            Console.Write("Пароль: ");
            string password = ReadPassword();

            if (username.Length is < 3 or > 30 ||
                username.Any(c => !(char.IsLetterOrDigit(c) || c == '_')))
            {
                Console.WriteLine("Логин: 3–30 символов, буквы, цифры и _.");
                continue;
            }

            if (password.Length < 8)
            {
                Console.WriteLine("Пароль должен содержать не менее 8 символов.");
                continue;
            }

            if (choice == "2")
            {
                byte[] salt = RandomNumberGenerator.GetBytes(16);
                byte[] hash = HashPassword(password, salt);

                try
                {
                    using var connection = new SqliteConnection(ConnectionString);
                    connection.Open();
                    using var command = connection.CreateCommand();
                    command.CommandText =
                        "INSERT INTO Users(Username, PasswordHash, Salt) VALUES($u,$h,$s)";
                    command.Parameters.AddWithValue("$u", username);
                    command.Parameters.AddWithValue("$h", Convert.ToBase64String(hash));
                    command.Parameters.AddWithValue("$s", Convert.ToBase64String(salt));
                    command.ExecuteNonQuery();

                    Console.WriteLine("Регистрация выполнена. Теперь войдите.");
                }
                catch (SqliteException)
                {
                    Console.WriteLine("Такой логин уже существует.");
                }
                continue;
            }

            if (choice == "1")
            {
                using var connection = new SqliteConnection(ConnectionString);
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText =
                    "SELECT Id, PasswordHash, Salt FROM Users WHERE Username=$u";
                command.Parameters.AddWithValue("$u", username);

                using var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    int id = reader.GetInt32(0);
                    byte[] savedHash = Convert.FromBase64String(reader.GetString(1));
                    byte[] salt = Convert.FromBase64String(reader.GetString(2));
                    byte[] enteredHash = HashPassword(password, salt);

                    if (CryptographicOperations.FixedTimeEquals(savedHash, enteredHash))
                    {
                        _userId = id;
                        _username = username;
                        Console.WriteLine("Авторизация успешна.");
                        return true;
                    }
                }

                Console.WriteLine("Неверный логин или пароль.");
            }
        }
    }

    private static byte[] HashPassword(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(
            password, salt, 210_000, HashAlgorithmName.SHA256, 32);

    private static string ReadPassword()
    {
        // Для простоты консольного примера ввод отображается.
        return Console.ReadLine() ?? "";
    }

    // ---------- БЕЗОПАСНАЯ РАБОТА С ПУТЯМИ ----------

    private static string SafePath(string relativePath)
    {
    return SafePathPolicy.Resolve(Root, relativePath);
    }

    private static string RelativePath(string fullPath) =>
        Path.GetRelativePath(Root, fullPath);

    // ---------- УЧЁТ ФАЙЛОВ И ЖУРНАЛ ----------

    private static void RegisterFile(string path, string operation)
    {
        string relative = RelativePath(path);
        var info = new FileInfo(path);

        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var transaction = connection.BeginTransaction();

        using (var fileCommand = connection.CreateCommand())
        {
            fileCommand.Transaction = transaction;
            fileCommand.CommandText = """
                INSERT INTO Files(FileName, CreatedAt, Size, Location, OwnerId)
                VALUES($name,$date,$size,$location,$owner)
                ON CONFLICT(Location, OwnerId) DO UPDATE SET
                    FileName=excluded.FileName,
                    Size=excluded.Size;
                """;
            fileCommand.Parameters.AddWithValue("$name", info.Name);
            fileCommand.Parameters.AddWithValue("$date", info.CreationTimeUtc.ToString("O"));
            fileCommand.Parameters.AddWithValue("$size", info.Length);
            fileCommand.Parameters.AddWithValue("$location", relative);
            fileCommand.Parameters.AddWithValue("$owner", _userId);
            fileCommand.ExecuteNonQuery();
        }

        int? fileId = null;
        using (var find = connection.CreateCommand())
        {
            find.Transaction = transaction;
            find.CommandText = "SELECT Id FROM Files WHERE Location=$p AND OwnerId=$u";
            find.Parameters.AddWithValue("$p", relative);
            find.Parameters.AddWithValue("$u", _userId);
            fileId = Convert.ToInt32(find.ExecuteScalar());
        }

        using (var log = connection.CreateCommand())
        {
            log.Transaction = transaction;
            log.CommandText = """
                INSERT INTO Operations(Timestamp, OperationType, FileId, UserId, Details)
                VALUES($time,$type,$file,$user,$details)
                """;
            log.Parameters.AddWithValue("$time", DateTime.UtcNow.ToString("O"));
            log.Parameters.AddWithValue("$type", operation);
            log.Parameters.AddWithValue("$file", fileId.Value);
            log.Parameters.AddWithValue("$user", _userId);
            log.Parameters.AddWithValue("$details", relative);
            log.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    private static void LogOperation(string operation, string details)
    {
        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Operations(Timestamp, OperationType, FileId, UserId, Details)
            VALUES($time,$type,NULL,$user,$details)
            """;
        command.Parameters.AddWithValue("$time", DateTime.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$type", operation);
        command.Parameters.AddWithValue("$user", _userId);
        command.Parameters.AddWithValue("$details", details);
        command.ExecuteNonQuery();
    }

    // ---------- ФАЙЛОВАЯ СИСТЕМА ----------

    private static void ShowDrives()
    {
        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            Console.WriteLine($"\nДиск: {drive.Name}");
            Console.WriteLine($"Тип: {drive.DriveType}");
            if (!drive.IsReady) { Console.WriteLine("Недоступен."); continue; }

            Console.WriteLine($"Файловая система: {drive.DriveFormat}");
            Console.WriteLine($"Объём: {FormatBytes(drive.TotalSize)}");
            Console.WriteLine($"Свободно: {FormatBytes(drive.AvailableFreeSpace)}");
        }
    }

    private static string FormatBytes(long bytes) =>
        $"{bytes / 1024d / 1024d:N2} МБ";

    private static void ListFiles()
    {
        Console.Write("Каталог относительно Files (пусто — корень): ");
        string relative = Console.ReadLine() ?? "";
        string directory = relative == "" ? Root : SafePath(relative);

        if (!Directory.Exists(directory))
        {
            Console.WriteLine("Каталог не найден.");
            return;
        }

        try
        {
            foreach (string dir in Directory.GetDirectories(directory))
                Console.WriteLine("[ПАПКА] " + Path.GetFileName(dir));

            foreach (string file in Directory.GetFiles(directory))
            {
                var info = new FileInfo(file);
                Console.WriteLine($"[ФАЙЛ] {info.Name} — {FormatBytes(info.Length)}");
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Недостаточно прав для просмотра каталога.");
        }
    }

    private static void CreateTextFile()
    {
        Console.Write("Имя файла (например Documents/note.txt): ");
        string path = SafePath(Console.ReadLine() ?? "");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        Console.Write("Содержимое: ");
        string content = Console.ReadLine() ?? "";

        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
            writer.Write(content);

        RegisterFile(path, "create");
        Console.WriteLine("Файл создан.");
    }

    private static void ReadFile()
    {
        Console.Write("Путь к файлу: ");
        string path = SafePath(Console.ReadLine() ?? "");
        if (!File.Exists(path)) { Console.WriteLine("Файл не найден."); return; }

        Console.WriteLine("\n" + File.ReadAllText(path, Encoding.UTF8));
        LogOperation("read", RelativePath(path));
    }

    private static void ModifyTextFile()
    {
        Console.Write("Путь к файлу: ");
        string path = SafePath(Console.ReadLine() ?? "");
        if (!File.Exists(path)) { Console.WriteLine("Файл не найден."); return; }

        Console.Write("Новое содержимое: ");
        string content = Console.ReadLine() ?? "";
        File.WriteAllText(path, content, Encoding.UTF8);
        RegisterFile(path, "modify");
        Console.WriteLine("Файл изменён.");
    }

    private static void DeleteFile()
    {
        Console.Write("Путь к файлу: ");
        string path = SafePath(Console.ReadLine() ?? "");
        if (!File.Exists(path)) { Console.WriteLine("Файл не найден."); return; }

        string relative = RelativePath(path);
        File.Delete(path);

        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var transaction = connection.BeginTransaction();

        using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM Files WHERE Location=$p AND OwnerId=$u";
            delete.Parameters.AddWithValue("$p", relative);
            delete.Parameters.AddWithValue("$u", _userId);
            delete.ExecuteNonQuery();
        }

        using (var log = connection.CreateCommand())
        {
            log.Transaction = transaction;
            log.CommandText = """
                INSERT INTO Operations(Timestamp, OperationType, FileId, UserId, Details)
                VALUES($time,'delete',NULL,$user,$details)
                """;
            log.Parameters.AddWithValue("$time", DateTime.UtcNow.ToString("O"));
            log.Parameters.AddWithValue("$user", _userId);
            log.Parameters.AddWithValue("$details", relative);
            log.ExecuteNonQuery();
        }

        transaction.Commit();
        Console.WriteLine("Файл удалён.");
    }

    private static void CreateDirectory()
    {
        Console.Write("Имя каталога: ");
        string path = SafePath(Console.ReadLine() ?? "");
        Directory.CreateDirectory(path);
        LogOperation("create_directory", RelativePath(path));
        Console.WriteLine("Каталог создан.");
    }

    // ---------- JSON ----------

    private static void JsonMenu()
    {
        Console.WriteLine("1. Создать JSON-файл");
        Console.WriteLine("2. Прочитать и проверить JSON");
        Console.Write("Выбор: ");

        string choice = Console.ReadLine() ?? "";
        Console.Write("Путь внутри Files (например JSON/data.json): ");
        string path = SafePath(Console.ReadLine() ?? "");

        if (choice == "1")
        {
            Console.Write("Введите JSON: ");
            string json = Console.ReadLine() ?? "";

            using JsonDocument document = JsonDocument.Parse(json);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string formatted = JsonSerializer.Serialize(
                document.RootElement,
                new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, formatted, Encoding.UTF8);
            RegisterFile(path, "create_json");
            Console.WriteLine("JSON сохранён и проверен.");
        }
        else if (choice == "2")
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
            Console.WriteLine(JsonSerializer.Serialize(
                document.RootElement,
                new JsonSerializerOptions { WriteIndented = true }));
            LogOperation("read_json", RelativePath(path));
        }
    }

    // ---------- XML ----------

    private static void XmlMenu()
    {
        Console.WriteLine("1. Создать XML-файл");
        Console.WriteLine("2. Прочитать и проверить XML");
        Console.Write("Выбор: ");
        string choice = Console.ReadLine() ?? "";

        Console.Write("Путь внутри Files (например XML/data.xml): ");
        string path = SafePath(Console.ReadLine() ?? "");

        if (choice == "1")
        {
            Console.Write("Название элемента: ");
            string element = Console.ReadLine() ?? "message";
            if (element.Length > 40 ||
                !System.Xml.XmlConvert.VerifyName(element).Equals(element))
                throw new ArgumentException("Недопустимое имя XML-элемента.");

            Console.Write("Текст: ");
            string value = Console.ReadLine() ?? "";

            var settings = new XmlWriterSettings { Indent = true, Encoding = Encoding.UTF8 };
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using (XmlWriter writer = XmlWriter.Create(path, settings))
            {
                writer.WriteStartDocument();
                writer.WriteStartElement("root");
                writer.WriteElementString(element, value);
                writer.WriteEndElement();
                writer.WriteEndDocument();
            }

            RegisterFile(path, "create_xml");
            Console.WriteLine("XML сохранён.");
        }
        else if (choice == "2")
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 1_000_000
            };

            using XmlReader reader = XmlReader.Create(path, settings);
            while (reader.Read())
            {
                if (reader.NodeType is XmlNodeType.Element or XmlNodeType.Text)
                    Console.WriteLine($"{reader.NodeType}: {reader.Name} {reader.Value}");
            }

            LogOperation("read_xml", RelativePath(path));
        }
    }

    // ---------- ZIP ----------

    private static void CreateZip()
    {
        Console.Write("Каталог для архивации (относительно Files): ");
        string source = SafePath(Console.ReadLine() ?? "");
        if (!Directory.Exists(source)) { Console.WriteLine("Каталог не найден."); return; }

        Console.Write("Имя ZIP-файла (например Archives/backup.zip): ");
        string archive = SafePath(Console.ReadLine() ?? "");
        Directory.CreateDirectory(Path.GetDirectoryName(archive)!);

        ZipFile.CreateFromDirectory(source, archive, CompressionLevel.Optimal, false);
        RegisterFile(archive, "create_zip");
        Console.WriteLine("Архив создан.");
    }

    private static void ExtractZip()
    {
        Console.Write("Путь к ZIP-файлу: ");
        string archivePath = SafePath(Console.ReadLine() ?? "");
        if (!File.Exists(archivePath)) { Console.WriteLine("Архив не найден."); return; }

        Console.Write("Каталог назначения: ");
        string destination = SafePath(Console.ReadLine() ?? "");
        Directory.CreateDirectory(destination);

        using ZipArchive archive = ZipFile.OpenRead(archivePath);

        if (archive.Entries.Count > MaxArchiveEntries)
            throw new InvalidDataException("Слишком много элементов в архиве.");

        long totalBytes = 0;
        string destinationPrefix = Path.GetFullPath(destination)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            totalBytes = checked(totalBytes + entry.Length);
            if (totalBytes > MaxArchiveBytes)
                throw new InvalidDataException("Превышен лимит распакованных данных (50 МБ).");

            string target = Path.GetFullPath(Path.Combine(destination, entry.FullName));

            // Защита от Zip Slip: элемент архива не должен выходить из каталога назначения.
            if (!target.StartsWith(destinationPrefix,
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
                throw new InvalidDataException("Обнаружен небезопасный путь в архиве.");

            if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using Stream input = entry.Open();
            using FileStream output = new FileStream(target, FileMode.CreateNew, FileAccess.Write);
            input.CopyTo(output);
        }

        LogOperation("extract_zip", RelativePath(archivePath) + " -> " + RelativePath(destination));
        Console.WriteLine("Архив успешно распакован.");
    }

    // ---------- ЖУРНАЛ АУДИТА ----------

    private static void ShowHistory()
    {
        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Timestamp, OperationType, Details
            FROM Operations
            WHERE UserId=$u
            ORDER BY Id DESC
            LIMIT 100
            """;
        command.Parameters.AddWithValue("$u", _userId);

        using var reader = command.ExecuteReader();
        Console.WriteLine("\nПоследние операции:");
        while (reader.Read())
            Console.WriteLine($"{reader.GetString(0)} | {reader.GetString(1)} | {reader.GetString(2)}");
    }
}
