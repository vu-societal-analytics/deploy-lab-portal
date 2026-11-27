// A pasted list of people to invite: one per line, "email" or "email, name" (a comma, semicolon or tab between).

export type Invitee = { email: string; name: string };

const EMAIL = /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/;
export const MAX_INVITEES = 1000;

/** The valid lines (each address once, lower case; without a name: the part before the @), and the invalid ones. */
export function parseInviteeList(text: string): { invitees: Invitee[]; invalid: string[] } {
  const invitees: Invitee[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const [first, ...rest] = line.split(/[,;\t]/);
    const email = first.trim().replace(/^<|>$/g, '').toLowerCase();
    if (!EMAIL.test(email)) {
      invalid.push(line.slice(0, 200));
      continue;
    }
    if (seen.has(email)) continue;
    seen.add(email);
    const name = rest.join(' ').trim().replace(/\s+/g, ' ').slice(0, 200) || email.split('@')[0];
    invitees.push({ email, name });
  }
  return { invitees, invalid };
}
