// Text that must NOT produce redactions. Each case guards against a known false positive.
module.exports = [
  {
    name: ".env.example with placeholders",
    text: [
      "DB_HOST=localhost",
      "DB_PASSWORD=changeme",
      "STRIPE_SECRET_KEY=your_stripe_key_here",
      "OPENAI_API_KEY=<YOUR_OPENAI_KEY>",
      "JWT_SECRET=${JWT_SECRET}",
      "API_TOKEN=",
      "SESSION_SECRET=xxxxxxxxxxxxxxxx",
      "PORT=3000"
    ].join("\n")
  },
  {
    name: "Code reading secrets from the environment",
    text: [
      "const apiKey = process.env.OPENAI_API_KEY;",
      "const password = req.body.password;",
      "let token = getToken();",
      "db_password = os.environ['DB_PASSWORD']",
      "secret: config.get('secret'),",
      "if (password == null) return;",
      "password: string;",
      "token: z.string().min(10),"
    ].join("\n")
  },
  {
    name: "Docs mentioning secrets",
    text: "Set the `API_KEY` variable to your key. The password must be at least 12 characters. Keep this secret: between us. He was the Bearer of bad news. Use Authorization: Bearer <token>."
  },
  {
    name: "Dates, versions and numbers",
    text: "Released 2024-01-15 as version 1.2.3.4, build v10.0.0.1. Order #123456789012 shipped. Meeting at 10:30:45. Ref 1234-5678."
  },
  {
    name: "Localhost and loopback",
    text: "Server listening on http://127.0.0.1:8080 and http://localhost:3000, bound to 0.0.0.0, IPv6 ::1."
  },
  {
    name: "Example emails and git remotes",
    text: "Contact user@example.com or test@example.org. Clone git@github.com:org/repo.git. Icon: logo@2x.png"
  },
  {
    name: "Plain prose",
    text: "Can you help me refactor this function so it handles retries with exponential backoff? The token bucket algorithm should allow bursts."
  },
  {
    name: "Config without secrets",
    text: "server:\n  port: 8080\n  host: 0.0.0.0\nlogging:\n  level: info\nfeatures:\n  darkMode: true\n  maxTokens: 4096\n  password_min_length: 12"
  },
  {
    name: "Public paths",
    text: "Open C:\\Users\\Public\\Documents and /home/user/app and /Users/runner/work."
  },
  {
    name: "Already sanitized text",
    text: "DB_PASSWORD=[PASSWORD_1]\nemail me at [EMAIL_1]\nAuthorization: [TOKEN_1]"
  }
];
