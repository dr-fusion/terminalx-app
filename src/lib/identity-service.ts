import path from "node:path";
import {
  createCanonicalIdentityAuthority,
  type CanonicalIdentityAuthority,
} from "./identity-authority";
import { openTeamSessionDatabase } from "./team-sessions/sqlite";

export function canonicalIdentityDatabaseFilename(): string {
  return (
    process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
    path.join(/* turbopackIgnore: true */ process.cwd(), "data", "team-sessions.sqlite")
  );
}

export function withCanonicalIdentityAuthority<T>(
  operation: (authority: CanonicalIdentityAuthority) => T
): T {
  const database = openTeamSessionDatabase({ filename: canonicalIdentityDatabaseFilename() });
  try {
    return operation(createCanonicalIdentityAuthority({ db: database.db }));
  } finally {
    database.close();
  }
}
