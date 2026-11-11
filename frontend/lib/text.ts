// Registry strings are untrusted. React already escapes markup; this also
// neutralises control characters and bidi overrides that could visually
// reorder or hide text.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;

export function clean(s: unknown): string {
  return typeof s === "string" ? s.replace(UNSAFE, "�") : "";
}
