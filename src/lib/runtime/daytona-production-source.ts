import { types as utilTypes } from "node:util";
import productionSourceConfiguration from "../../../config/daytona-production-source.json";

const CONFIGURATION_FIELDS = [
  "schemaVersion",
  "kind",
  "forkRepository",
  "productionForkCommit",
  "upstreamRepository",
  "upstreamBaseCommit",
] as const;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const GITHUB_REPOSITORY =
  /^https:\/\/github\.com\/[a-z0-9](?:[a-z0-9-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/;

export interface DaytonaProductionSourceConfiguration {
  readonly schemaVersion: 1;
  readonly kind: "terminalx.daytona-production-source";
  readonly forkRepository: string;
  readonly productionForkCommit: string;
  readonly upstreamRepository: string;
  readonly upstreamBaseCommit: string;
}

export function validateDaytonaProductionSourceConfiguration(
  value: unknown
): Readonly<DaytonaProductionSourceConfiguration> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("Invalid canonical Daytona production source configuration");
  }
  const record = value as Record<string, unknown>;
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== CONFIGURATION_FIELDS.length ||
    keys.some((key) => typeof key !== "string" || !CONFIGURATION_FIELDS.includes(key as never))
  ) {
    throw new TypeError("Invalid canonical Daytona production source configuration schema");
  }
  const descriptors = Object.getOwnPropertyDescriptors(record);
  if (
    CONFIGURATION_FIELDS.some((key) => {
      const descriptor = descriptors[key];
      return !descriptor?.enumerable || !("value" in descriptor);
    }) ||
    record.schemaVersion !== 1 ||
    record.kind !== "terminalx.daytona-production-source" ||
    typeof record.forkRepository !== "string" ||
    !GITHUB_REPOSITORY.test(record.forkRepository) ||
    typeof record.upstreamRepository !== "string" ||
    !GITHUB_REPOSITORY.test(record.upstreamRepository) ||
    record.forkRepository === record.upstreamRepository ||
    typeof record.productionForkCommit !== "string" ||
    !GIT_COMMIT.test(record.productionForkCommit) ||
    typeof record.upstreamBaseCommit !== "string" ||
    !GIT_COMMIT.test(record.upstreamBaseCommit) ||
    record.productionForkCommit === record.upstreamBaseCommit
  ) {
    throw new TypeError("Invalid canonical Daytona production source configuration");
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: "terminalx.daytona-production-source",
    forkRepository: record.forkRepository,
    productionForkCommit: record.productionForkCommit,
    upstreamRepository: record.upstreamRepository,
    upstreamBaseCommit: record.upstreamBaseCommit,
  });
}

export const DAYTONA_PRODUCTION_SOURCE_CONFIGURATION = validateDaytonaProductionSourceConfiguration(
  productionSourceConfiguration
);
export const DAYTONA_FORK_REPOSITORY = DAYTONA_PRODUCTION_SOURCE_CONFIGURATION.forkRepository;
export const DAYTONA_PRODUCTION_FORK_COMMIT =
  DAYTONA_PRODUCTION_SOURCE_CONFIGURATION.productionForkCommit;
export const DAYTONA_UPSTREAM_REPOSITORY =
  DAYTONA_PRODUCTION_SOURCE_CONFIGURATION.upstreamRepository;
export const DAYTONA_UPSTREAM_BASE_COMMIT =
  DAYTONA_PRODUCTION_SOURCE_CONFIGURATION.upstreamBaseCommit;
