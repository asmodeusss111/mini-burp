const axios = require('axios');

// ============================================================================
// НАСТРОЙКИ
// ============================================================================

// Замените на реальный URL вашего приложения
const BASE_URL = 'https://time.am'; 

// ============================================================================
// УТИЛИТЫ
// ============================================================================

// Функция для генерации случайного IPv4-адреса
const getRandomIp = () => {
  const r = () => Math.floor(Math.random() * 256);
  // Начинаем с 1-255, чтобы избежать 0.x.x.x
  return `${Math.floor(Math.random() * 255) + 1}.${r()}.${r()}.${r()}`;
};

// Функция задержки
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ============================================================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================================================

// Настроенный экземпляр axios
const api = axios.create({
  baseURL: BASE_URL,
  timeout: 5000,
  validateStatus: () => true, // Не выбрасывать ошибку ни при каких HTTP статусах
});

// Массив путей для проверки безопасности (60+ элементов)
const paths = [
  // 1. Секреты, конфигурации и переменные окружения
  '/.env', '/.env.example', '/.env.local', '/.env.dev', '/.env.prod', '/.env.backup',
  '/config.json', '/config.yml', '/settings.json', '/settings.yml',
  
  // 2. Системы контроля версий
  '/.git/config', '/.git/HEAD', '/.gitignore', '/.svn/entries', '/.hg/hgrc',
  
  // 3. Специфика Node.js и Railway
  '/package.json', '/package-lock.json', '/yarn.lock', '/pnpm-lock.yaml',
  '/Dockerfile', '/docker-compose.yml', '/.dockerignore', '/railway.json',
  '/server.js', '/index.js', '/app.js', '/tsconfig.json',
  
  // 4. Проверка нормализации путей и Path Traversal
  '/..%2f..%2f..%2fetc/passwd',
  '/..%2f..%2f..%2fwindows/win.ini',
  '/%2e%2e/%2e%2e/etc/passwd',
  '/....//....//etc/passwd',
  '/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
  '//.env', '/api//.env', '/api/v1//.env',
  '/app/..%2f.env', '/%5C../%5C../%5C../Windows/win.ini',
  
  // 5. Логи и бэкапы
  '/error.log', '/access.log', '/debug.log', '/app.log', '/server.log',
  '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql', '/db.sql',
  '/db.sqlite', '/db.sqlite3', '/data.db',
  
  // 6. Админ-панели и служебные эндпоинты
  '/admin', '/admin/', '/administrator', '/wp-admin',
  '/phpinfo.php', '/info.php', '/server-status', '/server-info',
  '/metrics', '/actuator/health', '/actuator/env', '/health', '/healthcheck',
  
  // 7. Документация API и прочее
  '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
  '/.well-known/security.txt', '/.well-known/apple-app-site-association',
  '/swagger.json', '/swagger-ui.html', '/api-docs', '/v1/api-docs',
  '/graphql', '/graphiql'
];

// ============================================================================
// ОСНОВНАЯ ЛОГИКА
// ============================================================================

async function runSecurityAudit() {
  console.log(`\n🚀 Запуск аудита безопасности для: ${BASE_URL}`);
  console.log(`Общее количество путей для проверки: ${paths.length}`);
  console.log('='.repeat(80));
  console.log(`[Status] | Path ${' '.repeat(35)} | Size (B) | Time`);
  console.log('-'.repeat(80));

  for (const path of paths) {
    const randomIp = getRandomIp();
    
    // Формируем заголовки, имитирующие Chrome на Windows 11 + случайный прокси IP
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      'Sec-Ch-Ua-Mobile': '?0',
      'Sec-Ch-Ua-Platform': '"Windows"',
      'X-Forwarded-For': randomIp,
      'X-Real-IP': randomIp
    };

    const startTime = Date.now();
    let statusFormatted = '';
    let sizeFormatted = '';
    let timeFormatted = '';

    try {
      // Выполняем GET-запрос
      const response = await api.get(path, { headers });
      
      const timeMs = Date.now() - startTime;
      const status = response.status;
      
      // Вычисляем размер ответа (сначала ищем заголовок, если его нет - считаем байты в body)
      let size = 0;
      if (response.headers['content-length']) {
        size = parseInt(response.headers['content-length'], 10);
      } else if (response.data) {
        size = Buffer.byteLength(
          typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
        );
      }

      // Форматирование для вывода
      statusFormatted = `[ ${status} ]`;
      sizeFormatted = size.toString();
      timeFormatted = `${timeMs}ms`;

      // Вывод результата в консоль
      console.log(`${statusFormatted.padEnd(8)} | ${path.padEnd(40)} | ${sizeFormatted.padStart(8)} | ${timeFormatted.padStart(8)}`);

    } catch (error) {
      const timeMs = Date.now() - startTime;
      timeFormatted = `${timeMs}ms`;
      
      // Обработка сетевых ошибок (Таймаут, ECONNRESET, Status 0)
      statusFormatted = '[ ERR! ]';
      const errorMsg = error.code || error.message;
      
      console.log(`${statusFormatted.padEnd(8)} | ${path.padEnd(40)} | ${'---'.padStart(8)} | ${timeFormatted.padStart(8)} -> ${errorMsg}`);
    }

    // Задержка ровно в 1 секунду перед следующим запросом
    await delay(1000);
  }

  console.log('='.repeat(80));
  console.log('✅ Аудит завершен.\n');
}

// Запускаем скрипт
runSecurityAudit();
