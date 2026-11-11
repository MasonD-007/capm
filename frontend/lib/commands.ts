// Shell commands shown on a bundle page. Registry strings are untrusted, so
// each part keeps only characters valid in owner/name/semver.
const part = (s: string) => s.replace(/[^A-Za-z0-9._+-]/g, "");

export function cliCommands(owner: string, name: string, version: string) {
  const ref = `${part(owner)}/${part(name)}@${part(version)}`;
  return {
    inspect: `capm inspect ${ref}`,
    run: `capm run ${ref} --model-url <your-endpoint> --allow-unenforced-egress`,
  };
}
