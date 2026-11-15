// Realistic but FAKE sensitive samples. Provider-shaped tokens are assembled from pieces so that
// repository secret scanners do not flag this file. None of these values are real credentials.
const j = (...p) => p.join("");
const rnd = (seed, len, alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") => {
  let x = seed;
  let s = "";
  for (let i = 0; i < len; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    s += alphabet[x % alphabet.length];
  }
  return s;
};

const STRIPE = j("sk_", "live_", rnd(1, 24));
const AWS_ID = j("AK", "IA", rnd(2, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"));
const AWS_SECRET = rnd(3, 40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+");
const GH = j("gh", "p_", rnd(4, 36));
const OPENAI = j("sk-", "proj-", rnd(5, 40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"));
const ANTHROPIC = j(
  "sk-",
  "ant-",
  "api03-",
  rnd(6, 60, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
);
const SLACK = j("xo", "xb-", "1234567890", "-", rnd(7, 24));
const GOOGLE = j("AI", "za", rnd(8, 35, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"));
const SENDGRID = j("SG", ".", rnd(9, 22), ".", rnd(10, 43));
const JWT = j(
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  ".",
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaSJ9",
  ".",
  rnd(11, 43, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
);
const NPM = j("np", "m_", rnd(12, 36));
const BEARER = rnd(13, 48, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-");
const K8S_B64 = Buffer.from("Sup3r$ecretDbPass").toString("base64");
const PEM_BODY = [
  rnd(14, 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
  rnd(15, 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
  rnd(16, 40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") + "=="
].join("\n");
const PEM = j("-----BEGIN ", "RSA PRIVATE KEY-----\n", PEM_BODY, "\n-----END ", "RSA PRIVATE KEY-----");

module.exports = [
  {
    name: ".env file",
    text: [
      "# production",
      "APP_ENV=production",
      "DB_HOST=db01.corp.local",
      "DB_USER=app",
      "DB_PASSWORD=hunter2pass",
      `STRIPE_SECRET_KEY=${STRIPE}`,
      "DATABASE_URL=postgres://admin:S3cretPw@10.0.3.7:5432/app",
      `export OPENAI_API_KEY="${OPENAI}"`,
      "JWT_SECRET=9f8e7d6c5b4a39281706f5e4d3c2b1a0",
      "PORT=3000"
    ].join("\n"),
    mustRedact: [
      "hunter2pass",
      STRIPE,
      "S3cretPw",
      OPENAI,
      "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
      "db01.corp.local",
      "10.0.3.7"
    ],
    mustKeep: ["DB_PASSWORD=", "PORT=3000", "APP_ENV=production"],
    blocks: ["env_file"]
  },
  {
    name: "AWS credentials file",
    text: `[default]\naws_access_key_id = ${AWS_ID}\naws_secret_access_key = ${AWS_SECRET}\nregion = eu-west-1`,
    mustRedact: [AWS_ID, AWS_SECRET],
    blocks: ["aws_credentials"]
  },
  {
    name: "GCP service account JSON",
    text: JSON.stringify(
      {
        type: "service_account",
        project_id: "acme-prod",
        private_key_id: "0123456789abcdef0123456789abcdef01234567",
        private_key: PEM.replace(/\n/g, "\\n"),
        client_email: "deployer@acme-prod.iam.gserviceaccount.com"
      },
      null,
      2
    ),
    mustRedact: [
      "0123456789abcdef0123456789abcdef01234567",
      "deployer@acme-prod.iam.gserviceaccount.com",
      PEM_BODY.split("\n")[0]
    ],
    blocks: ["gcp_service_account"]
  },
  {
    name: "docker-compose",
    text: [
      "services:",
      "  db:",
      "    image: postgres:16",
      "    environment:",
      "      POSTGRES_PASSWORD: Pg-Pass-2024!",
      "      POSTGRES_USER: admin",
      "  api:",
      "    build: .",
      "    environment:",
      `      - SENDGRID_API_KEY=${SENDGRID}`
    ].join("\n"),
    mustRedact: ["Pg-Pass-2024!", SENDGRID],
    blocks: ["docker_compose"]
  },
  {
    name: "Kubernetes Secret",
    text: `apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-creds\ntype: Opaque\ndata:\n  username: YWRtaW4=\n  password: ${K8S_B64}\n`,
    mustRedact: [K8S_B64, "YWRtaW4="],
    blocks: ["k8s_secret"]
  },
  {
    name: "kubeconfig",
    text: `apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.20.30.40:6443\n  name: prod\nusers:\n- name: admin\n  user:\n    token: ${BEARER}\n`,
    mustRedact: [BEARER, "10.20.30.40"],
    blocks: ["kubeconfig"]
  },
  {
    name: "web.config / XML",
    text: `<?xml version="1.0"?>\n<configuration>\n  <appSettings>\n    <add key="ApiKey" value="Zx9Kq2Lm8Np4Rt6V" />\n  </appSettings>\n  <connectionStrings>\n    <add name="Main" connectionString="Server=sql01.corp.local;Database=crm;User Id=sa;Password=Sql!Pass99;" />\n  </connectionStrings>\n  <smtp><password>MailPw#2024</password></smtp>\n</configuration>`,
    mustRedact: ["Zx9Kq2Lm8Np4Rt6V", "Sql!Pass99", "MailPw#2024"],
    blocks: ["xml_config"]
  },
  {
    name: "Spring application.properties",
    text: "spring.datasource.url=jdbc:mysql://db.internal:3306/shop\nspring.datasource.username=shop\nspring.datasource.password=Sh0pP@ss\nserver.port=8080",
    mustRedact: ["Sh0pP@ss", "db.internal"],
    blocks: ["properties_config"]
  },
  {
    name: "wp-config.php",
    text: "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp');\ndefine('DB_PASSWORD', 'Wp#Secret123');\ndefine('AUTH_KEY', 'p9#Lk2@Vb7$Qw1!Zx8^Mn3&Rt5*Yh6');",
    mustRedact: ["Wp#Secret123", "p9#Lk2@Vb7$Qw1!Zx8^Mn3&Rt5*Yh6"]
  },
  {
    name: "Python stack trace with DSN",
    text: [
      "Traceback (most recent call last):",
      '  File "C:\\Users\\Wasim\\projects\\billing\\app.py", line 42, in <module>',
      '    conn = psycopg2.connect("postgresql://billing:Pa55word!@db.internal:5432/prod")',
      '  File "/home/ayesha/.venv/lib/python3.12/site-packages/psycopg2/__init__.py", line 122, in connect',
      'psycopg2.errors.UniqueViolation: duplicate key value violates unique constraint "users_email_key"',
      "DETAIL:  Key (email)=(ali.khan@acme.pk) already exists."
    ].join("\n"),
    mustRedact: ["Pa55word!", "db.internal", "Wasim", "ayesha", "ali.khan@acme.pk"],
    blocks: ["stack_trace", "sql_error"]
  },
  {
    name: "Node stack trace and log lines",
    text: [
      "2024-05-01T10:22:13.511Z ERROR request failed user=sara@contoso.io ip=203.0.113.25",
      "2024-05-01T10:22:13.512Z WARN retrying with token=" + BEARER,
      "Error: connect ECONNREFUSED 10.1.2.3:6379",
      "    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1555:16)",
      "    at Object.<anonymous> (/srv/acme-payments/src/redis.js:14:9)"
    ].join("\n"),
    mustRedact: ["sara@contoso.io", "203.0.113.25", BEARER, "10.1.2.3", "acme-payments"],
    blocks: ["log", "stack_trace"]
  },
  {
    name: "Java stack trace with SQL values",
    text: [
      "2024-05-01 10:22:13 ERROR [main] o.h.engine.jdbc.spi.SqlExceptionHelper - Duplicate entry 'ahmed@bank.pk' for key 'users.email'",
      "Exception in thread \"main\" java.sql.SQLIntegrityConstraintViolationException: INSERT INTO users (name, phone) VALUES ('Ahmed Raza', '03001234567')",
      "\tat com.mysql.cj.jdbc.ClientPreparedStatement.executeInternal(ClientPreparedStatement.java:916)",
      "\tat com.acme.UserRepo.save(UserRepo.java:88)"
    ].join("\n"),
    mustRedact: ["ahmed@bank.pk", "Ahmed Raza", "03001234567"],
    blocks: ["stack_trace", "sql_error"]
  },
  {
    name: "HTTP request dump",
    text: [
      "POST /v1/charges HTTP/1.1",
      "Host: api.acme.com",
      "Authorization: Bearer " + BEARER,
      "Cookie: session=8f3k2j1h5g6f7d8s9a0q; csrftoken=Zx81Kq92Lm73",
      "X-Api-Key: " + GOOGLE,
      "",
      '{"amount": 5000}'
    ].join("\n"),
    mustRedact: [BEARER, "8f3k2j1h5g6f7d8s9a0q", GOOGLE],
    blocks: ["http_dump"]
  },
  {
    name: "curl and CLI commands",
    text: [
      `curl -u deploy:Depl0y!Pass https://ci.acme.com/api`,
      `curl -H "Authorization: Bearer ${BEARER}" "https://api.acme.com/v1/items?api_key=Qw8Er7Ty6Ui5Op4"`,
      "mysql -h 10.0.0.5 -u root -pR00tPass! shop",
      `docker run -e GITHUB_TOKEN=${GH} acme/builder`,
      `$env:NPM_TOKEN = "${NPM}"`,
      "sshpass -p 'Ssh!Pass42' ssh admin@10.0.0.9"
    ].join("\n"),
    mustRedact: ["Depl0y!Pass", BEARER, "Qw8Er7Ty6Ui5Op4", "R00tPass!", GH, NPM, "Ssh!Pass42"],
    blocks: ["shell"]
  },
  {
    name: "Provider keys in prose",
    text: `here is my key ${ANTHROPIC} and slack ${SLACK} and jwt ${JWT}`,
    mustRedact: [ANTHROPIC, SLACK, JWT]
  },
  {
    name: "Private key block",
    text: `deploy key:\n${PEM}\nthanks`,
    mustRedact: [PEM_BODY.split("\n")[0], PEM_BODY.split("\n")[2]],
    mustKeep: ["thanks", "deploy key:"]
  },
  {
    name: "Truncated private key",
    text: j("-----BEGIN ", "OPENSSH PRIVATE KEY-----\n") + PEM_BODY.split("\n").slice(0, 2).join("\n"),
    mustRedact: [PEM_BODY.split("\n")[0], PEM_BODY.split("\n")[1]]
  },
  {
    name: "Personal data",
    text: "Customer Ali, CNIC 35202-1234567-1, phone +92 300 1234567, card 4111 1111 1111 1111, IBAN PK36SCBL0000001123456702, DOB: 12/04/1990, passport no AB1234567",
    mustRedact: [
      "35202-1234567-1",
      "+92 300 1234567",
      "4111 1111 1111 1111",
      "PK36SCBL0000001123456702",
      "12/04/1990",
      "AB1234567"
    ]
  },
  {
    name: "Password hashes",
    text: "admin:$2b$12$abcdefghijklmnopqrstuuJ0mEJ4kq7QnOq2eTqJ0b1c2d3e4f5g6\nroot:$6$salty$abcdefghijklmnopqrstuvwxyzABCDEFGHIJ:19000:0:99999:7:::",
    mustRedact: [
      "$2b$12$abcdefghijklmnopqrstuuJ0mEJ4kq7QnOq2eTqJ0b1c2d3e4f5g6",
      "$6$salty$abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
    ]
  },
  {
    name: "Cloud identifiers in logs",
    text: "AccessDenied for arn:aws:iam::123456789012:role/deployer on /subscriptions/0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b/resourceGroups/prod",
    mustRedact: ["123456789012", "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"]
  },
  {
    name: ".netrc and git credentials",
    text: "machine github.com login wasim password Gh!NetrcPass9\nhttps://wasim:" + GH + "@github.com",
    mustRedact: ["Gh!NetrcPass9", GH]
  }
];
