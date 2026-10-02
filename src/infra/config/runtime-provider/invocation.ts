import { resolve } from 'node:path';
import { getGlobalConfigDir, getProjectConfigDir } from '../paths.js';
import {
  resolveRuntimeProviderFileWithOrigins,
  type ResolveRuntimeProviderInput,
  type ResolvedRuntimeProviderFileWithOrigins,
} from './loader.js';

type RuntimeProviderPaths = Pick<ResolveRuntimeProviderInput, 'globalConfigDir' | 'projectConfigDir'>;

interface RuntimeAssignmentInvocation {
  readonly name: string;
  readonly resolvedFiles: Map<string, ResolvedRuntimeProviderFileWithOrigins>;
}

let invocation: RuntimeAssignmentInvocation | undefined;

export function prepareRuntimeAssignmentInvocation(
  projectCwd: string,
  runtimeAssignment: string | undefined,
): void {
  invocation = undefined;
  if (runtimeAssignment !== undefined) {
    resolveRuntimeProviderFileWithOrigins({
      globalConfigDir: getGlobalConfigDir(),
      projectConfigDir: getProjectConfigDir(projectCwd),
      runtimeAssignment,
    });
  }
}

export function initializeRuntimeAssignmentInvocation(
  projectCwd: string,
  runtimeAssignment: string | undefined,
): void {
  invocation = undefined;
  if (runtimeAssignment === undefined) {
    return;
  }
  const paths = {
    globalConfigDir: getGlobalConfigDir(),
    projectConfigDir: getProjectConfigDir(projectCwd),
  };
  const resolved = resolveRuntimeProviderFileWithOrigins({ ...paths, runtimeAssignment });
  invocation = {
    name: runtimeAssignment,
    resolvedFiles: new Map([[runtimePathsKey(paths), resolved]]),
  };
}

export function getInvocationRuntimeAssignment(): string | undefined {
  return invocation?.name;
}

export function resolveInvocationRuntimeProviderFileWithOrigins(
  paths: RuntimeProviderPaths,
): ResolvedRuntimeProviderFileWithOrigins {
  if (invocation === undefined) {
    return resolveRuntimeProviderFileWithOrigins(paths);
  }
  const key = runtimePathsKey(paths);
  let resolved = invocation.resolvedFiles.get(key);
  if (resolved === undefined) {
    resolved = resolveRuntimeProviderFileWithOrigins({ ...paths, runtimeAssignment: invocation.name });
    invocation.resolvedFiles.set(key, resolved);
  }
  // Consumer の変更が同じ起動の別 resolver へ漏れないようにする。
  return structuredClone(resolved);
}

function runtimePathsKey(paths: RuntimeProviderPaths): string {
  return JSON.stringify([resolve(paths.globalConfigDir), resolve(paths.projectConfigDir)]);
}
