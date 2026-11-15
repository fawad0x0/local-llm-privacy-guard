/* Personal data rules. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  const V = PG.validators;
  const R = (PG.rules = PG.rules || []);
  if (R.some(r => r.id === "email")) return;

  const EXAMPLE_DOMAIN = /(?:^|\.)(?:example\.(?:com|org|net)|example|invalid|test|localhost|domain\.com|email\.com)$/i;
  const IMAGE_TLD = /\.(?:png|jpe?g|gif|svg|webp|ico|bmp)$/i;

  R.push(
    {
      id: "email",
      label: "EMAIL",
      category: "pii",
      severity: "medium",
      reason: "Email address",
      placeholder: "none",
      re: /(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])/g,
      validate(v) {
        const at = v.lastIndexOf("@");
        const local = v.slice(0, at);
        const domain = v.slice(at + 1);
        if (EXAMPLE_DOMAIN.test(domain) || IMAGE_TLD.test(v)) return false;
        if (/^(?:git|noreply|no-reply)$/i.test(local)) return false;
        return true;
      }
    },
    {
      id: "phone_intl",
      label: "PHONE",
      category: "pii",
      severity: "medium",
      reason: "International phone number",
      placeholder: "none",
      re: /(?<![\w+])\+\d{1,3}(?:[ .-]?\(\d{1,4}\))?(?:[ .-]?\d{2,5}){2,5}(?![\w])/g,
      validate(v) {
        const n = V.digits(v).length;
        return n >= 8 && n <= 15;
      }
    },
    {
      id: "phone_nanp",
      label: "PHONE",
      category: "pii",
      severity: "medium",
      reason: "US/Canada phone number",
      pack: "us",
      placeholder: "none",
      re: /(?<![\w.+-])(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?![\w.-])/g
    },
    {
      id: "phone_pk",
      label: "PHONE",
      category: "pii",
      severity: "medium",
      reason: "Pakistani mobile number",
      pack: "pk",
      placeholder: "none",
      re: /(?<![\w+])(?:\+92[ -]?|0092[ -]?|0)3\d{2}[ -]?\d{7}(?!\d)/g
    },
    {
      id: "cnic",
      label: "CNIC",
      category: "pii",
      severity: "high",
      reason: "Pakistani CNIC number",
      pack: "pk",
      placeholder: "none",
      re: /\b\d{5}-\d{7}-\d\b/g
    },
    {
      id: "ntn",
      label: "NTN",
      category: "pii",
      severity: "medium",
      reason: "Pakistani NTN (tax number)",
      pack: "pk",
      placeholder: "none",
      re: /\bNTN[\s:#-]*(?<v>\d{7}-?\d)\b/gi
    },
    {
      id: "us_ssn",
      label: "SSN",
      category: "pii",
      severity: "high",
      reason: "US Social Security number",
      pack: "us",
      placeholder: "none",
      re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g
    },
    {
      id: "credit_card",
      label: "CARD",
      category: "pii",
      severity: "high",
      reason: "Payment card number (Luhn valid)",
      placeholder: "none",
      re: /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g,
      validate(v) {
        const d = V.digits(v);
        if (/^(\d)\1+$/.test(d)) return false;
        return V.luhn(d) && /^(?:4|5[1-5]|2[2-7]|3[47]|3[068]|6(?:011|5|4[4-9]|22))/.test(d);
      }
    },
    {
      id: "iban",
      label: "IBAN",
      category: "pii",
      severity: "high",
      reason: "IBAN bank account number",
      placeholder: "none",
      re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g,
      validate: v => V.iban(v)
    },
    {
      id: "uk_nino",
      label: "NI_NUMBER",
      category: "pii",
      severity: "high",
      reason: "UK National Insurance number",
      pack: "uk",
      placeholder: "none",
      re: /\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g
    },
    {
      id: "in_aadhaar",
      label: "AADHAAR",
      category: "pii",
      severity: "high",
      reason: "Indian Aadhaar number",
      pack: "in",
      placeholder: "none",
      re: /\b[2-9]\d{3} ?\d{4} ?\d{4}\b/g,
      validate: (v, info) => /aadh?aar|uidai/i.test(info.ctx.before(info.start, 60))
    },
    {
      id: "in_pan",
      label: "PAN",
      category: "pii",
      severity: "high",
      reason: "Indian PAN number",
      pack: "in",
      placeholder: "none",
      re: /\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b/g
    },
    {
      id: "ae_emirates_id",
      label: "EMIRATES_ID",
      category: "pii",
      severity: "high",
      reason: "UAE Emirates ID",
      pack: "ae",
      placeholder: "none",
      re: /\b784-?\d{4}-?\d{7}-?\d\b/g
    },
    {
      id: "passport",
      label: "PASSPORT",
      category: "pii",
      severity: "high",
      reason: "Passport number",
      placeholder: "strict",
      re: /\bpassport(?:\s*(?:no\.?|number|num|#))?\s*[:#-]?\s*(?<v>[A-Z0-9]{6,9})\b/gi,
      validate: v => /\d/.test(v)
    },
    {
      id: "dob",
      label: "DOB",
      category: "pii",
      severity: "medium",
      reason: "Date of birth",
      placeholder: "none",
      re: /\b(?:DOB|D\.O\.B\.?|date of birth|birth ?date|born(?: on)?)\s*[:-]?\s*(?<v>\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}|\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]{3,9},?\s+\d{4}|[A-Za-z]{3,9}\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})/gi
    },
    {
      id: "address_keyword",
      label: "ADDRESS",
      category: "pii",
      severity: "medium",
      reason: "Postal address",
      placeholder: "strict",
      re: /\b(?:home address|postal address|mailing address|street address|address|addr|residence|lives at|residing at)\s*[:-]\s*(?<v>[^\n]{8,120})/gi,
      validate(v, info) {
        const before = info.ctx.before(info.match.index, 14);
        if (/(?:ip|mac|e-?mail|web|ipv[46]|server|wallet|memory|bind|listen|remote|local|return|base|hardware|physical)\s*$/i.test(before)) return false;
        if (/^(?:https?:|0x|\d{1,3}(?:\.\d{1,3}){3})/i.test(v)) return false;
        return /\d/.test(v) && /[A-Za-z]{3,}/.test(v);
      }
    },
    {
      id: "street_address_us",
      label: "ADDRESS",
      category: "pii",
      severity: "medium",
      reason: "Street address",
      pack: "us",
      placeholder: "none",
      re: /\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?/g
    }
  );
})();
