#!/usr/local/bin/node

import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import {
  DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_RESPONSE_BYTES,
  DaytonaAssignmentBootstrapError,
  provisionDaytonaAssignmentBootstrap,
  type DaytonaAssignmentBootstrapInstalledDescriptor,
} from "./assignment-bootstrap";
import { TERMINALX_ROOT_RUNTIME_DIRECTORY, TERMINALX_ROOT_SUPERVISOR_SOCKET } from "./relay";
import { writeOwnedBuffer } from "./owned-writable";

const STATE_ROOT = "/var/lib/terminalx-supervisor" as const;
const AUTHORITY_PIN_FILE = "/etc/terminalx/bootstrap-authority-pin.json" as const;
const IMAGE_TRUST_PIN_FILE = "/etc/terminalx/sandbox-trust-pins.json" as const;
const DEPLOYMENT_BINDING_FILE = "/run/terminalx-root/deployment-binding.json" as const;
const HOSTNAME_FILE = "/etc/hostname" as const;
const PEER_CREDENTIAL_EXECUTABLE = "/usr/local/libexec/terminalx/terminalx-peercred" as const;
const EFFECT_EXECUTABLE = "/usr/local/libexec/terminalx/terminalx-effect-enforcer" as const;
const NODE_EXECUTABLE = "/usr/local/bin/node" as const;

/**
 * Fixed root-only Docker-exec target used by the hardened runner exactly once
 * per Sandbox assignment. It accepts only the signed binary envelope on stdin
 * and emits only the public installed descriptor on stdout. This is not a
 * readiness signal; activation requires the separate live attestation call.
 */
export async function runFixedDaytonaAssignmentBootstrap(): Promise<void> {
  if (
    typeof process.geteuid !== "function" ||
    process.geteuid() !== 0 ||
    process.argv.length !== 2
  ) {
    throw new DaytonaAssignmentBootstrapError(64);
  }

  const envelope = await readBoundedEnvelope();
  const descriptor = provisionDaytonaAssignmentBootstrap(envelope, {
    runtimeRoot: TERMINALX_ROOT_RUNTIME_DIRECTORY,
    stateRoot: STATE_ROOT,
    authorityPinFile: AUTHORITY_PIN_FILE,
    imageTrustPinFile: IMAGE_TRUST_PIN_FILE,
    deploymentBindingFile: DEPLOYMENT_BINDING_FILE,
    hostnameFile: HOSTNAME_FILE,
    expectedOwnerUid: 0,
    expectedPeerCredentialExecutable: PEER_CREDENTIAL_EXECUTABLE,
    expectedEffectExecutable: EFFECT_EXECUTABLE,
    expectedNodeExecutable: NODE_EXECUTABLE,
    expectedSupervisorSocket: TERMINALX_ROOT_SUPERVISOR_SOCKET,
  });
  const response = encodeDaytonaAssignmentBootstrapInstalledResponse(descriptor);
  await writeOwnedBuffer(process.stdout, response);
}

export function encodeDaytonaAssignmentBootstrapInstalledResponse(
  descriptor: DaytonaAssignmentBootstrapInstalledDescriptor
): Buffer {
  const response = Buffer.from(canonicalRuntimeJson(descriptor), "utf8");
  if (
    response.byteLength < 2 ||
    response.byteLength > DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_RESPONSE_BYTES
  ) {
    response.fill(0);
    throw new DaytonaAssignmentBootstrapError(74);
  }
  return response;
}

async function readBoundedEnvelope(): Promise<Buffer> {
  const allocation = Buffer.alloc(DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES + 1);
  let length = 0;
  try {
    for await (const unsafeChunk of process.stdin) {
      const chunk = Buffer.isBuffer(unsafeChunk) ? unsafeChunk : Buffer.from(unsafeChunk);
      try {
        if (length + chunk.byteLength > DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES) {
          throw new DaytonaAssignmentBootstrapError(64);
        }
        chunk.copy(allocation, length);
        length += chunk.byteLength;
      } finally {
        chunk.fill(0);
      }
    }
    if (length < 1) throw new DaytonaAssignmentBootstrapError(64);
    return allocation.subarray(0, length);
  } catch (error) {
    allocation.fill(0);
    throw error;
  }
}

if (require.main === module) {
  runFixedDaytonaAssignmentBootstrap().catch((error: unknown) => {
    process.stderr.write("TerminalX assignment bootstrap failed closed\n");
    process.exitCode = error instanceof DaytonaAssignmentBootstrapError ? error.exitCode : 74;
  });
}
