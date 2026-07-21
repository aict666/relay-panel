/** Quote one shell argument for the copied bash installation command. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

export function buildInstallCommand(scriptUrl: string, token: string, panelUrl: string): string {
  return `bash <(curl -fsSL ${shellQuote(scriptUrl)}) -t ${shellQuote(token)} -u ${shellQuote(panelUrl)}`;
}
