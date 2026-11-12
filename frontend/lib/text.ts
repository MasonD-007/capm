// Registry strings are untrusted. React already escapes markup; this also
// neutralises control characters and bidi overrides that could visually
// reorder or hide text.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;

export function clean(s: unknown): string {
  return typeof s === "string" ? s.replace(UNSAFE, "�") : "";
}

// Same set as UNSAFE except tab and newline, which a multi-line text (a
// README) needs. Carriage returns are normalised to newlines first.
const UNSAFE_MULTILINE =
  /[\u0000-\u0008\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;

export function cleanMultiline(s: unknown): string {
  return typeof s === "string" ? s.replace(/\r\n?/g, "\n").replace(UNSAFE_MULTILINE, "�") : "";
}
