import { createRequire } from 'node:module';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { spawnedProcessCalls } = vi.hoisted(() => ({
  spawnedProcessCalls: [] as Array<{ command: string; args: readonly string[] }>,
}));

const { fakeQuintVerify } = vi.hoisted(() => ({
  fakeQuintVerify: { mode: 'passthrough' as 'passthrough' | 'passed' | 'failed' },
}));

const { fakeQuintParse } = vi.hoisted(() => ({
  fakeQuintParse: {
    mode: 'passthrough' as 'passthrough' | 'missing' | 'file' | 'directory',
    contents: '',
    stdout: '',
    stderr: '',
  },
}));

const { fakeQuintRun } = vi.hoisted(() => ({
  fakeQuintRun: {
    mode: 'passthrough' as 'passthrough' | 'failed',
    stdout: '',
    stderr: '',
  },
}));

vi.mock('../shared/utils/spawn.js', async () => {
  const actual = await vi.importActual<typeof import('../shared/utils/spawn.js')>('../shared/utils/spawn.js');
  return {
    ...actual,
    spawnManagedProcess: (...args: Parameters<typeof actual.spawnManagedProcess>) => {
      spawnedProcessCalls.push({ command: args[0], args: [...args[1]] });
      if (fakeQuintParse.mode !== 'passthrough' && args[1][1] === 'parse') {
        const parseOutputIndex = args[1].indexOf('--out') + 1;
        const parseOutputPath = args[1][parseOutputIndex];
        if (parseOutputPath === undefined) {
          throw new Error('Quint parse output path was missing');
        }
        const script = [
          "const fs = require('node:fs');",
          'const [outputPath, mode, contents, stdout, stderr] = process.argv.slice(1);',
          "if (mode === 'file') fs.writeFileSync(outputPath, contents);",
          "if (mode === 'directory') fs.mkdirSync(outputPath);",
          "if (stdout) process.stdout.write(stdout);",
          "if (stderr) process.stderr.write(stderr);",
          'process.exitCode = 1;',
        ].join('\n');
        return actual.spawnManagedProcess(
          process.execPath,
          [
            '-e',
            script,
            parseOutputPath,
            fakeQuintParse.mode,
            fakeQuintParse.contents,
            fakeQuintParse.stdout,
            fakeQuintParse.stderr,
          ],
          args[2],
          args[3],
          args[4],
        );
      }
      if (fakeQuintRun.mode !== 'passthrough' && args[1][1] === 'run') {
        const script = [
          'const [stdout, stderr] = process.argv.slice(1);',
          'if (stdout) process.stdout.write(stdout);',
          'if (stderr) process.stderr.write(stderr);',
          'process.exitCode = 1;',
        ].join('\n');
        return actual.spawnManagedProcess(
          process.execPath,
          ['-e', script, fakeQuintRun.stdout, fakeQuintRun.stderr],
          args[2],
          args[3],
          args[4],
        );
      }
      if (fakeQuintVerify.mode !== 'passthrough' && args[1][1] === 'verify') {
        const exitCode = fakeQuintVerify.mode === 'failed' ? 1 : 0;
        const script = exitCode === 0
          ? 'process.exit(0)'
          : "process.stderr.write('counterexample'); process.exit(1)";
        return actual.spawnManagedProcess(
          process.execPath,
          ['-e', script],
          args[2],
          args[3],
          args[4],
        );
      }
      return actual.spawnManagedProcess(...args);
    },
  };
});

import {
  detectJavaMajorVersion,
  runFormalSpecVerification,
} from '../features/interactive/formalSpecVerifier.js';
import { createConversationSession } from '../features/interactive/conversationSession.js';
import { makeProvider, makeSessionContext } from './test-helpers.js';

const require = createRequire(import.meta.url);

const java17Available = (() => {
  const result = spawnSync('java', ['-version'], {
    encoding: 'utf8',
    timeout: 5_000,
  });
  if (result.status !== 0) {
    return false;
  }
  const version = detectJavaMajorVersion(`${result.stdout}\n${result.stderr}`);
  return version !== undefined && version >= 17;
})();

function runQuint(quintCli: string, args: string[], cwd: string) {
  return spawnSync(process.execPath, [quintCli, ...args], {
    cwd,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    timeout: 15_000,
  });
}

interface AlloyFixture {
  readonly jarPath: string;
  readonly logPath: string;
}

function assertCommandSucceeded(result: ReturnType<typeof spawnSync>): void {
  expect(result.status, String(result.stderr || result.error?.message || '')).toBe(0);
}

function buildAlloyFixture(directory: string): AlloyFixture {
  const sourceDirectory = join(directory, 'alloy-fixture-source');
  const classesDirectory = join(directory, 'alloy-fixture-classes');
  const sourcePath = join(sourceDirectory, 'AlloyFixture.java');
  const jarPath = join(directory, 'alloy-fixture.jar');
  const logPath = join(directory, 'alloy-fixture-invocations.log');
  mkdirSync(sourceDirectory, { recursive: true });
  mkdirSync(classesDirectory, { recursive: true });
  writeFileSync(sourcePath, [
    'import java.nio.file.Files;',
    'import java.nio.file.Path;',
    'import java.nio.file.StandardOpenOption;',
    'import java.util.Locale;',
    '',
    'public final class AlloyFixture {',
    '  private static final String SEPARATOR = "\\u001f";',
    '',
    '  public static void main(String[] args) throws Exception {',
    '    String logPath = System.getenv("TAKT_ALLOY_FIXTURE_LOG");',
    '    if (logPath != null && !logPath.isEmpty()) {',
    '      Files.writeString(',
    '        Path.of(logPath),',
    '        String.join(SEPARATOR, args) + System.lineSeparator(),',
    '        StandardOpenOption.CREATE,',
    '        StandardOpenOption.APPEND',
    '      );',
    '    }',
    '    if (args.length == 0) {',
    '      System.exit(2);',
    '    }',
    '    if ("commands".equals(args[0])) {',
    '      printCommands(Path.of(args[args.length - 1]));',
    '      return;',
    '    }',
    '    if ("exec".equals(args[0])) {',
    '      int command = commandNumber(args);',
    '      if (!isCheckCommand(Path.of(args[args.length - 1]), command)) {',
    '        System.err.print("run commands are not executable checks");',
    '        System.exit(2);',
    '      }',
    '      return;',
    '    }',
    '    System.exit(2);',
    '  }',
    '',
    '  private static void printCommands(Path specification) throws Exception {',
    '    int number = 0;',
    '    for (String rawLine : Files.readAllLines(specification)) {',
    '      String line = rawLine.trim();',
    '      if (line.isEmpty() || line.startsWith("//")) {',
    '        continue;',
    '      }',
    '      if (line.startsWith("check ")) {',
    '        printCommand(number++, "check", line);',
    '      } else if (line.startsWith("run ")) {',
    '        printCommand(number++, "run", line);',
    '      }',
    '    }',
    '  }',
    '',
    '  private static void printCommand(int number, String type, String declaration) {',
    '    String label = declaration.substring(type.length()).trim();',
    '    int scopeIndex = label.indexOf(" for ");',
    '    if (scopeIndex >= 0) {',
    '      label = label.substring(0, scopeIndex).trim();',
    '    }',
    '    String displayType = type.substring(0, 1).toUpperCase(Locale.ROOT) + type.substring(1);',
    '    System.out.printf(Locale.ROOT, "%-2d. %s%n", number, displayType + " " + label + " for 1");',
    '  }',
    '',
    '  private static int commandNumber(String[] args) {',
    '    for (int index = 0; index < args.length - 1; index++) {',
    '      if ("--command".equals(args[index])) {',
    '        return Integer.parseInt(args[index + 1]);',
    '      }',
    '    }',
    '    throw new IllegalArgumentException("--command is required");',
    '  }',
    '',
    '  private static boolean isCheckCommand(Path specification, int target) throws Exception {',
    '    int number = 0;',
    '    for (String rawLine : Files.readAllLines(specification)) {',
    '      String line = rawLine.trim();',
    '      if (line.startsWith("check ")) {',
    '        if (number == target) {',
    '          return true;',
    '        }',
    '        number++;',
    '      } else if (line.startsWith("run ")) {',
    '        if (number == target) {',
    '          return false;',
    '        }',
    '        number++;',
    '      }',
    '    }',
    '    return false;',
    '  }',
    '}',
    '',
  ].join('\n'), { encoding: 'utf8' });

  const compile = spawnSync('javac', ['-d', classesDirectory, sourcePath], {
    cwd: directory,
    encoding: 'utf8',
  });
  assertCommandSucceeded(compile);

  const packageJar = spawnSync(
    'jar',
    ['--create', '--file', jarPath, '--main-class', 'AlloyFixture', '-C', classesDirectory, 'AlloyFixture.class'],
    { cwd: directory, encoding: 'utf8' },
  );
  assertCommandSucceeded(packageJar);
  expect(existsSync(jarPath)).toBe(true);
  return { jarPath, logPath };
}

function installHangingJava(directory: string): { binDirectory: string } {
  const binDirectory = join(directory, 'bin');
  mkdirSync(binDirectory, { recursive: true });
  const javaPath = join(binDirectory, 'java');
  writeFileSync(javaPath, [
    `#!${process.execPath}`,
    'const args = process.argv.slice(2);',
    "if (args[0] === '-version') setInterval(() => undefined, 1000);",
    'else process.exit(1);',
    '',
  ].join('\n'), { encoding: 'utf8', mode: 0o700 });
  chmodSync(javaPath, 0o755);
  return { binDirectory };
}

function validAlloyResponse(): string {
  return ['```alloy', 'sig A {}', 'check Safety for 1', '```'].join('\n');
}

function restoreEnvironmentVariable(name: 'PATH' | 'TAKT_ALLOY_JAR' | 'TAKT_ALLOY_FIXTURE_LOG', value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function readAlloyFixtureInvocations(logPath: string): string[][] {
  if (!existsSync(logPath)) {
    return [];
  }
  return readFileSync(logPath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => line.split('\u001f'));
}

function argumentAfter(args: readonly string[], option: string): string | undefined {
  const index = args.indexOf(option);
  return index >= 0 ? args[index + 1] : undefined;
}

interface VerificationSnapshot {
  readonly message?: string;
  readonly quint?: {
    readonly parse?: { readonly status?: string; readonly message?: string };
    readonly typecheck?: { readonly status?: string };
    readonly run?: { readonly status?: string; readonly message?: string };
    readonly invariants?: readonly string[];
  };
}

function createVerifySession(cwd: string, specification: string) {
  const observedVerifications: VerificationSnapshot[] = [];
  const providerResponses: string[] = [];
  const provider = makeProvider({
    setup: ({ name }) => ({
      call: async (prompt) => {
        const verificationMatch = /<verification-result>\n([\s\S]*?)\n<\/verification-result>/u.exec(prompt);
        let content = specification;
        if (verificationMatch !== null) {
          const verification = JSON.parse(verificationMatch[1] ?? '') as VerificationSnapshot;
          observedVerifications.push(verification);
          content = verification.message ?? '';
        }
        providerResponses.push(content);
        return {
          persona: name,
          status: 'done',
          content,
          timestamp: new Date(),
        };
      },
    }),
  });
  const session = createConversationSession({
    cwd,
    formalSpec: true,
    modelCheckTimeoutSeconds: 300,
    outputMode: 'silent',
    ctx: makeSessionContext({ provider }),
    strategy: {
      systemPrompt: 'formal specification test session',
      modelCheckTimeoutSeconds: 300,
      allowedTools: [],
      transformPrompt: (message) => message,
    },
  });

  return { session, observedVerifications, providerResponses };
}

beforeEach(() => {
  spawnedProcessCalls.length = 0;
  fakeQuintVerify.mode = 'passthrough';
  fakeQuintParse.mode = 'passthrough';
  fakeQuintParse.contents = '';
  fakeQuintParse.stdout = '';
  fakeQuintParse.stderr = '';
  fakeQuintRun.mode = 'passthrough';
  fakeQuintRun.stdout = '';
  fakeQuintRun.stderr = '';
});

describe('bundled Quint CLI verification boundary', () => {
  it('should parse, typecheck, and run a generated Quint specification in an isolated directory', () => {
    const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-quint-'));

    try {
      const specificationPath = join(directory, 'spec.qnt');
      const parseOutputPath = join(directory, 'parse.json');
      writeFileSync(specificationPath, [
        'module verify {',
        '  var counter: int',
        '  action init = counter\' = 0',
        '  action step = counter\' = counter',
        '  val invNonNegative = counter >= 0',
        '}',
        '',
      ].join('\n'));

      const parse = runQuint(quintCli, ['parse', specificationPath, '--out', parseOutputPath], directory);
      expect(parse.status, parse.stderr).toBe(0);

      const parseResult = JSON.parse(readFileSync(parseOutputPath, 'utf8')) as {
        modules?: Array<{ declarations?: Array<{ name?: string }> }>;
      };
      expect(parseResult.modules?.[0]?.declarations?.some(({ name }) => name === 'invNonNegative')).toBe(true);

      const typecheck = runQuint(quintCli, ['typecheck', specificationPath], directory);
      expect(typecheck.status, typecheck.stderr).toBe(0);

      const run = runQuint(
        quintCli,
        [
          'run',
          specificationPath,
          '--backend',
          'typescript',
          '--max-samples',
          '1',
          '--max-steps',
          '1',
          '--invariants',
          'invNonNegative',
        ],
        directory,
      );
      expect(run.status, run.stderr).toBe(0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }

    expect(existsSync(directory)).toBe(false);
  });

  it('includes the Quint parse diagnostic and the specification source position after a parse failure', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-parse-diagnostic-'));
    const response = [
      '```quint',
      'module verify {',
      '  val note = true',
      '  var enabled: bool',
      '}',
      '```',
    ].join('\n');

    try {
      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });
      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli)
      ));

      expect(result.quint.parse?.status).toBe('error');
      expect(result.message).toContain("[QNT101] Built-in name 'enabled' is redefined in module 'verify'");
      expect(result.message).toContain('spec.qnt:3:3');
      expect(result.quint.typecheck?.status).toBe('skipped');
      expect(result.quint.run?.status).toBe('skipped');
      expect(quintCalls.map(({ args }) => args[1])).toEqual(['parse']);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([
    {
      name: 'missing parse JSON with no process output',
      mode: 'missing' as const,
      contents: '',
      stdout: '',
      stderr: '',
      expectedMessage: 'Process exited with status 1',
      excludedMessages: [],
    },
    {
      name: 'malformed parse JSON with both process streams',
      mode: 'file' as const,
      contents: '{"errors":[',
      stdout: 'parse stdout',
      stderr: 'parse stderr',
      expectedMessage: 'parse stderr\nparse stdout',
      excludedMessages: [],
    },
    {
      name: 'unreadable parse JSON with process output',
      mode: 'directory' as const,
      contents: '',
      stdout: '',
      stderr: 'parse stderr',
      expectedMessage: 'parse stderr',
      excludedMessages: [],
    },
    {
      name: 'an empty root errors array with nested and quoted errors',
      mode: 'file' as const,
      contents: JSON.stringify({
        errors: [],
        modules: [{ errors: [{ explanation: 'nested fake diagnostic' }] }],
        note: '"errors":[{"explanation":"quoted fake diagnostic"}]',
      }),
      stdout: '',
      stderr: 'parse failed',
      expectedMessage: 'parse failed',
      excludedMessages: ['nested fake diagnostic', 'quoted fake diagnostic'],
    },
    {
      name: 'a root errors field with the wrong type',
      mode: 'file' as const,
      contents: JSON.stringify({ errors: 'not an array' }),
      stdout: '',
      stderr: 'parse failed',
      expectedMessage: 'parse failed',
      excludedMessages: [],
    },
  ])('delivers the parse failure fallback through /verify for $name', async ({
    mode,
    contents,
    stdout,
    stderr,
    expectedMessage,
    excludedMessages,
  }) => {
    fakeQuintParse.mode = mode;
    fakeQuintParse.contents = contents;
    fakeQuintParse.stdout = stdout;
    fakeQuintParse.stderr = stderr;

    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-fallback-'));
    const { session, observedVerifications } = createVerifySession(directory, '```quint\nmodule verify {}\n```');

    try {
      const result = await session.handleUserMessage({ text: '/verify' });

      if (result.kind !== 'assistant_response') {
        throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
      }
      expect(result.content).toContain(expectedMessage);
      expect(observedVerifications.map(({ quint }) => quint?.parse)).toEqual([
        { status: 'error', message: expectedMessage },
      ]);

      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli)
      ));
      expect(quintCalls.map(({ args }) => args[1])).toEqual(['parse']);
      for (const excludedMessage of excludedMessages) {
        expect(result.content).not.toContain(excludedMessage);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
    expect(existsSync(directory)).toBe(false);
  });

  it.each([
    {
      name: 'diagnostics exceed the message limit',
      lengths: [3_900, 3_900, 300],
      expectedRenderedCount: 2,
      expectedOmissionNote: '他 1 件の診断を省略',
    },
    {
      name: 'all diagnostics fit within the message limit',
      lengths: [3_900, 3_900, 100],
      expectedRenderedCount: 3,
      expectedOmissionNote: undefined,
    },
  ])('delivers parse diagnostics through /verify when $name', async ({
    lengths,
    expectedRenderedCount,
    expectedOmissionNote,
  }) => {
    const diagnosticDefinitions = [
      { code: '[QNT101] ', line: 2, position: 'spec.qnt:3:3' },
      { code: '[QNT202] ', line: 4, position: 'spec.qnt:5:3' },
      { code: '[QNT303] ', line: 6, position: 'spec.qnt:7:3' },
    ];
    const diagnostics = diagnosticDefinitions.map(({ code, line, position }, index) => {
      const length = lengths[index]!;
      const locationPrefix = `${position}: `;
      const explanation = `${code}${'x'.repeat(length - locationPrefix.length - code.length)}`;
      return {
        expectedText: `${locationPrefix}${explanation}`,
        value: {
          explanation,
          locs: [{ source: '/tmp/spec.qnt', start: { line, col: 2 } }],
        },
      };
    });
    fakeQuintParse.mode = 'file';
    fakeQuintParse.contents = JSON.stringify({ errors: diagnostics.map(({ value }) => value) });

    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-parse-overflow-'));
    const specification = '```quint\nmodule verify {}\n```';
    const { session, observedVerifications, providerResponses } = createVerifySession(directory, specification);

    try {
      const result = await session.handleUserMessage({ text: '/verify' });

      if (result.kind !== 'assistant_response') {
        throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
      }

      const verification = observedVerifications[0];
      const parseMessage = verification?.quint?.parse?.message ?? '';
      const expectedRenderedDiagnostics = diagnostics
        .slice(0, expectedRenderedCount)
        .map(({ expectedText }) => expectedText);
      const expectedMessage = [
        ...expectedRenderedDiagnostics,
        ...(expectedOmissionNote === undefined ? [] : [expectedOmissionNote]),
      ].join('\n');
      const generatedSpecificationPrefix = `${specification}\n\n`;
      const finalResponse = result.content.slice(generatedSpecificationPrefix.length);
      const providerResponse = providerResponses.at(-1) ?? '';

      expect(result.content.startsWith(generatedSpecificationPrefix)).toBe(true);
      expect(parseMessage).toBe(expectedMessage);
      expect(parseMessage.length).toBeLessThanOrEqual(8_000);
      expect(verification?.quint?.parse?.status).toBe('error');
      expect(verification?.quint?.typecheck?.status).toBe('skipped');
      expect(verification?.quint?.run?.status).toBe('skipped');
      expect(providerResponse).toContain(expectedMessage);
      expect(finalResponse).toContain(expectedMessage);

      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli)
      ));
      expect(quintCalls.map(({ args }) => args[1])).toEqual(['parse']);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
    expect(existsSync(directory)).toBe(false);
  });

  it('delivers a real Quint parse diagnostic through /verify to the final response', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-diagnostic-'));
    const specification = [
      '```quint',
      'module verify {',
      '  val note = true',
      '  var enabled: bool',
      '}',
      '```',
    ].join('\n');
    const { session, observedVerifications } = createVerifySession(directory, specification);

    try {
      const result = await session.handleUserMessage({ text: '/verify' });

      if (result.kind !== 'assistant_response') {
        throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
      }
      const finalResponse = result.content.slice(result.content.lastIndexOf('\n\n') + 2);
      expect(finalResponse).toContain("[QNT101] Built-in name 'enabled' is redefined in module 'verify'");
      expect(finalResponse).toContain('spec.qnt:3:3');
      expect(observedVerifications[0]?.quint?.parse?.status).toBe('error');
      expect(observedVerifications[0]?.quint?.typecheck?.status).toBe('skipped');
      expect(observedVerifications[0]?.quint?.run?.status).toBe('skipped');

      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli)
      ));
      expect(quintCalls.map(({ args }) => args[1])).toEqual(['parse']);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
    expect(existsSync(directory)).toBe(false);
  });

  it('delivers the violated invariant name through /verify to the final response', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-run-diagnostic-'));
    const specification = [
      '```quint',
      'module verify {',
      '  var counter: int',
      "  action init = counter' = 0",
      "  action step = counter' = counter + 1",
      '  val invSmall = q::debug("first", false)',
      '  val invOther = q::debug("second", false)',
      '  val invNonNegative = counter >= 0',
      '}',
      '```',
    ].join('\n');
    const { session, observedVerifications, providerResponses } = createVerifySession(directory, specification);

    try {
      const result = await session.handleUserMessage({ text: '/verify' });

      if (result.kind !== 'assistant_response') {
        throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
      }
      const generatedSpecificationPrefix = `${specification}\n\n`;
      expect(result.content.startsWith(generatedSpecificationPrefix)).toBe(true);
      const finalResponse = result.content.slice(generatedSpecificationPrefix.length);
      const providerResponse = providerResponses.at(-1) ?? '';
      const runMessage = observedVerifications[0]?.quint?.run?.message ?? '';
      expect(providerResponse).toContain('invSmall');
      expect(providerResponse).toContain('invOther');
      expect(providerResponse).not.toContain('invNonNegative');
      expect(providerResponse).toContain('State 0');
      expect(providerResponse).toContain('counter: 0');
      expect(providerResponse.indexOf('invSmall')).toBeLessThan(providerResponse.indexOf('invOther'));
      expect(providerResponse.indexOf('invOther')).toBeLessThan(providerResponse.indexOf('State 0'));
      expect(finalResponse).toContain('invSmall');
      expect(finalResponse).toContain('invOther');
      expect(finalResponse).not.toContain('invNonNegative');
      expect(finalResponse).toContain('State 0');
      expect(finalResponse).toContain('counter: 0');
      expect(finalResponse.indexOf('invSmall')).toBeLessThan(finalResponse.indexOf('State 0'));
      expect(finalResponse.indexOf('invOther')).toBeLessThan(finalResponse.indexOf('State 0'));
      expect(observedVerifications[0]?.quint?.parse?.status).toBe('passed');
      expect(observedVerifications[0]?.quint?.typecheck?.status).toBe('passed');
      expect(observedVerifications[0]?.quint?.run?.status).toBe('failed');
      expect(runMessage).toContain('invSmall');
      expect(runMessage).toContain('invOther');
      expect(runMessage).toContain('An example execution:');
      expect(runMessage).toContain('State 0');
      expect(runMessage).toContain('counter: 0');
      expect(runMessage.indexOf('invSmall')).toBeLessThan(runMessage.indexOf('State 0'));
      expect(runMessage.indexOf('invOther')).toBeLessThan(runMessage.indexOf('State 0'));
      expect(runMessage.indexOf('invSmall')).toBeLessThan(runMessage.indexOf('invOther'));
      expect(observedVerifications[0]?.message).toContain('invSmall');
      expect(observedVerifications[0]?.message).toContain('counter: 0');

      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintRunCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli) && args[1] === 'run'
      ));
      expect(quintRunCalls).toHaveLength(1);
      const runArgs = quintRunCalls[0]?.args ?? [];
      expect(runArgs[runArgs.indexOf('--verbosity') + 1]).toBe('2');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
    expect(existsSync(directory)).toBe(false);
  });

  it('delivers the fixed details and truncated trace through /verify to the final response', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-run-overflow-'));
    const specification = [
      '```quint',
      'module verify {',
      '  var counter: int',
      "  action init = counter' = 0",
      "  action step = counter' = counter + 1",
      '  val invSmall = counter >= 0',
      '  val invOther = counter <= 10',
      '}',
      '```',
    ].join('\n');
    const trace = `An example execution:\n[State 0] { counter: 0 }\n${'x'.repeat(9_000)}`;
    fakeQuintRun.mode = 'failed';
    fakeQuintRun.stdout = `${trace}\n[violation] Found an issue\n  ❌ invSmall`;
    fakeQuintRun.stderr = 'error: Invariant violated';
    const { session, observedVerifications, providerResponses } = createVerifySession(directory, specification);

    try {
      const result = await session.handleUserMessage({ text: '/verify' });

      if (result.kind !== 'assistant_response') {
        throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
      }

      const verification = observedVerifications[0];
      const runMessage = verification?.quint?.run?.message ?? '';
      const fixedMessage = '❌ invSmall\nerror: Invariant violated';
      const traceBudget = 8_000 - fixedMessage.length - 1 - '\n[output truncated]'.length;
      const expectedRunMessage = `${fixedMessage}\n${trace.slice(0, traceBudget)}\n[output truncated]`;
      const generatedSpecificationPrefix = `${specification}\n\n`;
      const finalResponse = result.content.slice(generatedSpecificationPrefix.length);
      const providerResponse = providerResponses.at(-1) ?? '';

      expect(result.content.startsWith(generatedSpecificationPrefix)).toBe(true);
      expect(verification?.quint?.parse?.status).toBe('passed');
      expect(verification?.quint?.typecheck?.status).toBe('passed');
      expect(verification?.quint?.run?.status).toBe('failed');
      expect(runMessage).toBe(expectedRunMessage);
      expect(runMessage.length).toBe(8_000);
      expect(providerResponse).toContain(expectedRunMessage);
      expect(finalResponse).toContain(expectedRunMessage);
      expect(verification?.message).toContain(expectedRunMessage);

      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintRunCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli) && args[1] === 'run'
      ));
      expect(quintRunCalls).toHaveLength(1);
      expect(quintRunCalls[0]?.args[quintRunCalls[0]?.args.indexOf('--verbosity') + 1]).toBe('2');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
    expect(existsSync(directory)).toBe(false);
  });

  it('preserves a short counterexample through /verify when one invariant name exceeds the message budget', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-long-invariant-'));
    const invariantName = `inv${'x'.repeat(8_000)}`;
    const specification = [
      '```quint',
      'module verify {',
      '  var counter: int',
      "  action init = counter' = 0",
      "  action step = counter' = counter + 1",
      `  val ${invariantName} = false`,
      '}',
      '```',
    ].join('\n');
    const { session, observedVerifications, providerResponses } = createVerifySession(directory, specification);

    try {
      const result = await session.handleUserMessage({ text: '/verify' });

      if (result.kind !== 'assistant_response') {
        throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
      }

      const verification = observedVerifications[0];
      const runMessage = verification?.quint?.run?.message ?? '';
      const providerResponse = providerResponses.at(-1) ?? '';
      const generatedSpecificationPrefix = `${specification}\n\n`;
      const finalResponse = result.content.slice(generatedSpecificationPrefix.length);
      expect(verification?.quint?.parse?.status).toBe('passed');
      expect(verification?.quint?.typecheck?.status).toBe('passed');
      expect(verification?.quint?.run?.status).toBe('failed');
      expect(verification?.quint?.invariants).toContain(invariantName);
      expect(result.content.startsWith(generatedSpecificationPrefix)).toBe(true);
      expect(runMessage.length).toBeLessThanOrEqual(8_000);
      expect(runMessage).toContain('❌ inv');
      expect(runMessage).toContain('[invariant name truncated]');
      expect(runMessage).not.toContain(invariantName);
      expect(runMessage).toContain('An example execution:\n\n[State 0] { counter: 0 }');
      expect(runMessage.indexOf('[invariant name truncated]')).toBeLessThan(runMessage.indexOf('State 0'));
      expect(providerResponse).toContain('[invariant name truncated]');
      expect(providerResponse).toContain('An example execution:\n\n[State 0] { counter: 0 }');
      expect(finalResponse).toContain('[invariant name truncated]');
      expect(finalResponse).toContain('An example execution:\n\n[State 0] { counter: 0 }');
      expect(finalResponse).not.toContain(invariantName);
      expect(verification?.message).toContain('[invariant name truncated]');

      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintRunCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli) && args[1] === 'run'
      ));
      expect(quintRunCalls).toHaveLength(1);
      const runArgs = quintRunCalls[0]?.args ?? [];
      expect(runArgs).toContain(invariantName);
      expect(runArgs[runArgs.indexOf('--backend') + 1]).toBe('typescript');
      expect(runArgs[runArgs.indexOf('--verbosity') + 1]).toBe('2');
      expect(runArgs[runArgs.indexOf('--max-samples') + 1]).toBe('1');
      expect(runArgs[runArgs.indexOf('--max-steps') + 1]).toBe('20');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
    expect(existsSync(directory)).toBe(false);
  });

  it('preserves the complete invariant name and available trace at message boundaries through /verify', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-name-boundary-'));
    const trace = 'An example execution:\n\n[State 0] { counter: 0 }';
    const invariantNameLengths = [7_952, 7_953, 7_972, 7_973];

    try {
      for (const invariantNameLength of invariantNameLengths) {
        const invariantName = `inv${'x'.repeat(invariantNameLength - 3)}`;
        const runDirectory = join(directory, String(invariantNameLength));
        mkdirSync(runDirectory);
        const specification = [
          '```quint',
          'module verify {',
          '  var counter: int',
          "  action init = counter' = 0",
          "  action step = counter' = counter + 1",
          `  val ${invariantName} = false`,
          '}',
          '```',
        ].join('\n');
        const { session, observedVerifications, providerResponses } = createVerifySession(runDirectory, specification);
        const result = await session.handleUserMessage({ text: '/verify' });

        if (result.kind !== 'assistant_response') {
          throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
        }

        const verification = observedVerifications[0];
        const runMessage = verification?.quint?.run?.message ?? '';
        const providerResponse = providerResponses.at(-1) ?? '';
        const generatedSpecificationPrefix = `${specification}\n\n`;
        const finalResponse = result.content.slice(generatedSpecificationPrefix.length);
        const retainedTraceLength = Math.max(0, Math.min(trace.length, 8_000 - invariantNameLength - 1));
        const expectedMessage = invariantNameLength === 8_000
          ? invariantName
          : `${invariantName}\n${trace.slice(0, retainedTraceLength)}`;

        expect(result.content.startsWith(generatedSpecificationPrefix)).toBe(true);
        expect(verification?.quint?.parse?.status).toBe('passed');
        expect(verification?.quint?.typecheck?.status).toBe('passed');
        expect(verification?.quint?.run?.status).toBe('failed');
        expect(verification?.quint?.invariants).toContain(invariantName);
        expect(runMessage.length).toBeLessThanOrEqual(8_000);
        expect(runMessage).toBe(expectedMessage);
        expect(runMessage.slice(0, invariantNameLength)).toBe(invariantName);
        expect(runMessage.slice(invariantNameLength + 1)).toBe(trace.slice(0, retainedTraceLength));
        expect(verification?.message).toContain(expectedMessage);
        expect(providerResponse).toContain(expectedMessage);
        expect(finalResponse).toContain(expectedMessage);

        const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
        const quintRunCall = spawnedProcessCalls.find(({ command, args }) => (
          command === process.execPath && args.includes(quintCli) && args[1] === 'run' && args.includes(invariantName)
        ));
        const runArgs = quintRunCall?.args ?? [];
        expect(runArgs).toContain(invariantName);
        expect(runArgs[runArgs.indexOf('--backend') + 1]).toBe('typescript');
        expect(runArgs[runArgs.indexOf('--verbosity') + 1]).toBe('2');
        expect(runArgs[runArgs.indexOf('--max-samples') + 1]).toBe('1');
        expect(runArgs[runArgs.indexOf('--max-steps') + 1]).toBe('20');
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }

    expect(existsSync(directory)).toBe(false);
  });

  it('preserves the counterexample through /verify when the violated invariant list exceeds the message budget', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-verify-run-budget-'));

    try {
      const verifyWithInvariantCount = async (invariantCount: number) => {
        const invariantNames = Array.from(
          { length: invariantCount },
          (_, index) => `invFailure${String(index).padStart(4, '0')}`,
        );
        const specification = [
          '```quint',
          'module verify {',
          '  var counter: int',
          "  action init = counter' = 0",
          "  action step = counter' = counter + 1",
          ...invariantNames.map((name) => `  val ${name} = counter < 0`),
          '}',
          '```',
        ].join('\n');
        const runDirectory = join(directory, String(invariantCount));
        mkdirSync(runDirectory);
        const { session, observedVerifications, providerResponses } = createVerifySession(runDirectory, specification);
        const result = await session.handleUserMessage({ text: '/verify' });

        if (result.kind !== 'assistant_response') {
          throw new Error(`Expected /verify to return an assistant response, received ${result.kind}`);
        }

        const generatedSpecificationPrefix = `${specification}\n\n`;
        expect(result.content.startsWith(generatedSpecificationPrefix)).toBe(true);
        return {
          verification: observedVerifications[0],
          providerResponse: providerResponses.at(-1) ?? '',
          finalResponse: result.content.slice(generatedSpecificationPrefix.length),
        };
      };

      const standard = await verifyWithInvariantCount(2);
      const large = await verifyWithInvariantCount(600);

      for (const { verification, providerResponse, finalResponse } of [standard, large]) {
        const runMessage = verification?.quint?.run?.message ?? '';
        const firstViolationName = /❌ invFailure\d{4}/u.exec(runMessage)?.[0];
        if (firstViolationName === undefined) {
          throw new Error('The Quint run failure did not include a violated invariant name');
        }

        expect(verification?.quint?.parse?.status).toBe('passed');
        expect(verification?.quint?.typecheck?.status).toBe('passed');
        expect(verification?.quint?.run?.status).toBe('failed');
        expect(runMessage.length).toBeLessThanOrEqual(8_000);
        expect(runMessage).toContain(firstViolationName);
        expect(runMessage).toContain('An example execution:');
        expect(runMessage).toContain('State 0');
        expect(runMessage).toContain('counter: 0');
        expect(runMessage.indexOf(firstViolationName)).toBeLessThan(runMessage.indexOf('State 0'));
        expect(providerResponse).toContain(firstViolationName);
        expect(providerResponse).toContain('State 0');
        expect(finalResponse).toContain(firstViolationName);
        expect(finalResponse).toContain('State 0');
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }

    expect(existsSync(directory)).toBe(false);
  });

  it('reports the violated invariant from a real Quint simulation failure', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-run-diagnostic-'));
    const response = [
      '```quint',
      'module verify {',
      '  var counter: int',
      "  action init = counter' = 0",
      "  action step = counter' = counter + 1",
      '  val invSmall = false',
      '  val invNonNegative = counter >= 0',
      '}',
      '```',
    ].join('\n');

    try {
      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });
      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const runCall = spawnedProcessCalls.find(({ command, args }) => (
        command === process.execPath && args.includes(quintCli) && args[1] === 'run'
      ));

      expect(result.quint.parse?.status).toBe('passed');
      expect(result.quint.typecheck?.status).toBe('passed');
      expect(result.quint.run?.status).toBe('failed');
      expect(result.verdict).toBe('failed');
      expect(result.message).toContain('invSmall');
      expect(result.message).not.toContain('invNonNegative');
      expect(runCall).toBeDefined();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('runs Quint basic verification and reports Java-dependent stages as skipped when Java is unavailable', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-runner-'));
    const originalPath = process.env.PATH;
    process.env.PATH = directory;

    try {
      const prime = String.fromCharCode(39);
      const response = [
        '```quint',
        'module verify {',
        '  var counter: int',
        `  action init = counter${prime} = 0`,
        `  action step = counter${prime} = counter`,
        '  val invNonNegative = counter >= 0',
        '}',
        '```',
        '```alloy',
        'sig A {}',
        'check Empty for 1',
        '```',
      ].join('\n');

      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('passed');
      expect(result.quint.parse?.status).toBe('passed');
      expect(result.quint.typecheck?.status).toBe('passed');
      expect(result.quint.run?.status).toBe('passed');
      expect(result.quint.verify?.status).toBe('skipped');
      expect(result.alloy.status).toBe('skipped');
      expect(result.alloy.message).toContain('Alloy specifications remain unverified');
    } finally {
      if (originalPath === undefined) {
        delete process.env.PATH;
      } else {
        process.env.PATH = originalPath;
      }
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('runs temporal Quint verification non-interactively with the TLC backend', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-temporal-'));
    const prime = String.fromCharCode(39);
    const response = [
      '```quint',
      'module verify {',
      '  var counter: int',
      `  action init = counter${prime} = 0`,
      `  action step = counter${prime} = counter + 1`,
      '  temporal propEventually = eventually(counter >= 0)',
      '}',
      '```',
    ].join('\n');
    fakeQuintVerify.mode = 'failed';

    try {
      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('failed');
      expect(result.quint.temporal).toEqual(['propEventually']);
      expect(result.quint.verify?.status).toBe('failed');
      expect(result.quint.verify?.message).not.toMatch(/Do you want to proceed/i);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.skipIf(!java17Available)('reports the TLC reason for a non-enumerable temporal model', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-tlc-diagnostic-'));
    const prime = String.fromCharCode(39);
    const response = [
      '```quint',
      'module verify {',
      '  var n: int',
      `  action init = n${prime} = 0`,
      '  action step = {',
      '    nondet value = Int.oneOf()',
      `    n${prime} = value`,
      '  }',
      '  temporal propEventually = eventually(n == 0)',
      '}',
      '```',
    ].join('\n');

    try {
      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('failed');
      expect(result.quint.verify?.status).toBe('failed');
      expect(result.quint.verify?.message).toMatch(/non-enumerable/i);
      expect(result.quint.verify?.message).not.toMatch(/Parsing file|Semantic processing of module|error: TLC error/);
      expect(result.message).toBe(result.quint.verify?.message);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('propagates every conventionally named Quint and Alloy target through the public runner', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-targets-'));
    const alloyFixture = buildAlloyFixture(directory);
    const originalJar = process.env.TAKT_ALLOY_JAR;
    const originalLog = process.env.TAKT_ALLOY_FIXTURE_LOG;
    process.env.TAKT_ALLOY_JAR = alloyFixture.jarPath;
    process.env.TAKT_ALLOY_FIXTURE_LOG = alloyFixture.logPath;
    fakeQuintVerify.mode = 'passed';

    const prime = String.fromCharCode(39);
    const response = [
      '```quint',
      'module helper {',
      '  val constant = true',
      '}',
      'module workflowModel {',
      '  var counter: int',
      `  action init = counter${prime} = 0`,
      `  action step = counter${prime} = counter`,
      '  val invSafe = counter >= 0',
      '  val invConsistent = counter <= 10',
      '  temporal propEventually = eventually(counter > 0)',
      '}',
      '```',
      '```alloy',
      'sig A {}',
      'check Safety for 1',
      'run Example for 1',
      'check Liveness for 1',
      '```',
    ].join('\n');

    try {
      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });
      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli)
      ));
      const runCall = quintCalls.find(({ args }) => args.includes('run'));
      const verifyCall = quintCalls.find(({ args }) => args.includes('verify'));

      expect(result.quint.invariants).toEqual(['invSafe', 'invConsistent']);
      expect(result.quint.temporal).toEqual(['propEventually']);
      expect(result.quint.run?.status).toBe('passed');
      expect(result.quint.verify?.status).toBe('passed');
      expect(result.javaMajorVersion).toBeGreaterThanOrEqual(17);
      expect(runCall?.args).toEqual(expect.arrayContaining(['run', '--main', 'workflowModel']));
      expect(runCall?.args.slice((runCall?.args.indexOf('--invariants') ?? -1) + 1))
        .toEqual(['invSafe', 'invConsistent']);
      expect(argumentAfter(verifyCall?.args ?? [], '--main')).toBe('workflowModel');
      expect(argumentAfter(verifyCall?.args ?? [], '--invariant')).toBe('invSafe,invConsistent');
      expect(argumentAfter(verifyCall?.args ?? [], '--temporal')).toBe('propEventually');
      expect(result.alloy).toMatchObject({
        status: 'passed',
        checks: [0, 2],
        commands: [
          { number: 0, type: 'check', label: 'Safety' },
          { number: 1, type: 'run', label: 'Example' },
          { number: 2, type: 'check', label: 'Liveness' },
        ],
      });
      const execInvocations = readAlloyFixtureInvocations(alloyFixture.logPath)
        .filter((args) => args.includes('exec'));
      expect(execInvocations.map((args) => argumentAfter(args, '--command'))).toEqual(['0', '2']);
      expect(execInvocations.filter((args) => argumentAfter(args, '--command') === '0')).toHaveLength(1);
      expect(execInvocations.filter((args) => argumentAfter(args, '--command') === '2')).toHaveLength(1);
      expect(execInvocations.some((args) => argumentAfter(args, '--command') === '1')).toBe(false);
      expect(readdirSync(join(directory, '.takt', 'runs'))
        .filter((name) => name.startsWith('verify-'))).toEqual([]);
    } finally {
      restoreEnvironmentVariable('TAKT_ALLOY_JAR', originalJar);
      restoreEnvironmentVariable('TAKT_ALLOY_FIXTURE_LOG', originalLog);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects Quint targets declared outside the selected main module before run and verify', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-target-scope-'));
    const response = [
      '```quint',
      'module helper {',
      '  val invHelper = true',
      '  temporal propHelper = eventually(true)',
      '}',
      'module workflowModel {',
      '  var counter: int',
      "  action init = counter' = 0",
      "  action step = counter' = counter",
      '}',
      '```',
    ].join('\n');

    try {
      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });
      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli)
      ));

      expect(result.verdict).toBe('error');
      expect(result.quint.parse?.status).toBe('passed');
      expect(result.quint.typecheck?.status).toBe('passed');
      expect(result.quint.run).toMatchObject({
        status: 'error',
        message: expect.stringContaining('helper::invHelper'),
      });
      expect(result.quint.run?.message).toContain('helper::propHelper');
      expect(quintCalls.some(({ args }) => args.includes('run'))).toBe(false);
      expect(quintCalls.some(({ args }) => args.includes('verify'))).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('does not infer a basename main when parsed modules have no executable actions', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-no-main-'));

    try {
      const result = await runFormalSpecVerification([
        '```quint',
        'module helper {',
        '  val constant = true',
        '}',
        'module properties {',
        '  val invSafe = true',
        '}',
        '```',
      ].join('\n'), directory, { modelCheckTimeoutSeconds: 300 });

      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const quintCalls = spawnedProcessCalls.filter(({ command, args }) => (
        command === process.execPath && args.includes(quintCli)
      ));

      expect(result.verdict).toBe('error');
      expect(result.quint.invariants).toEqual(['invSafe']);
      expect(result.quint.run).toMatchObject({
        status: 'error',
        message: 'Quint verification requires a module with action init and action step.',
      });
      expect(quintCalls.some(({ args }) => args.includes('run'))).toBe(false);
      expect(quintCalls.some(({ args }) => args.includes('verify'))).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('does not treat comments, non-convention names, or Alloy run commands as verification targets', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-targets-negative-'));
    const alloyFixture = buildAlloyFixture(directory);
    const originalJar = process.env.TAKT_ALLOY_JAR;
    const originalLog = process.env.TAKT_ALLOY_FIXTURE_LOG;
    process.env.TAKT_ALLOY_JAR = alloyFixture.jarPath;
    process.env.TAKT_ALLOY_FIXTURE_LOG = alloyFixture.logPath;

    const prime = String.fromCharCode(39);
    const response = [
      '```quint',
      'module workflowModel {',
      '  var counter: int',
      `  action init = counter${prime} = 0`,
      `  action step = counter${prime} = counter`,
      '  // val invComment = true',
      '  val safety = true',
      '}',
      '```',
      '```alloy',
      'sig A {}',
      'run Example for 1',
      '```',
    ].join('\n');

    try {
      const result = await runFormalSpecVerification(response, directory, { modelCheckTimeoutSeconds: 300 });
      const quintCli = require.resolve('@informalsystems/quint/dist/src/cli.js');
      const runCall = spawnedProcessCalls.find(({ command, args }) => (
        command === process.execPath && args.includes(quintCli) && args.includes('run')
      ));
      const invocations = readAlloyFixtureInvocations(alloyFixture.logPath);

      expect(result.quint.invariants).toEqual([]);
      expect(result.quint.temporal).toEqual([]);
      expect(runCall?.args).not.toContain('invComment');
      expect(runCall?.args).not.toContain('safety');
      expect(result.alloy).toMatchObject({
        status: 'error',
        commands: [{ number: 0, type: 'run', label: 'Example' }],
      });
      expect(invocations.some((args) => args.includes('exec'))).toBe(false);
    } finally {
      restoreEnvironmentVariable('TAKT_ALLOY_JAR', originalJar);
      restoreEnvironmentVariable('TAKT_ALLOY_FIXTURE_LOG', originalLog);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('runs Alloy checks through the public runner with Java 17 and removes its run workspace', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-alloy-'));
    const alloyFixture = buildAlloyFixture(directory);
    const originalJar = process.env.TAKT_ALLOY_JAR;
    const originalLog = process.env.TAKT_ALLOY_FIXTURE_LOG;
    process.env.TAKT_ALLOY_JAR = alloyFixture.jarPath;
    process.env.TAKT_ALLOY_FIXTURE_LOG = alloyFixture.logPath;

    try {
      const result = await runFormalSpecVerification([
        '```alloy',
        'sig A {}',
        'check Safety for 3',
        'check Liveness for 3',
        'run Report for 3',
        '```',
      ].join('\n'), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('passed');
      expect(result.javaMajorVersion).toBeGreaterThanOrEqual(17);
      expect(result.alloy).toMatchObject({ status: 'passed', checks: [0, 1] });
      expect(result.alloy.commands).toEqual([
        { number: 0, type: 'check', label: 'Safety' },
        { number: 1, type: 'check', label: 'Liveness' },
        { number: 2, type: 'run', label: 'Report' },
      ]);

      const invocations = readAlloyFixtureInvocations(alloyFixture.logPath);
      const javaCalls = spawnedProcessCalls.filter(({ command }) => command === 'java');
      expect(invocations.length).toBe(3);
      const commandCalls = javaCalls.filter(({ args }) => args.includes('commands'));
      const execCalls = javaCalls.filter(({ args }) => args.includes('exec'));
      expect(commandCalls).toHaveLength(1);
      expect(execCalls).toHaveLength(2);
      expect(commandCalls
        .every(({ args }) => args.includes(alloyFixture.jarPath))).toBe(true);
      expect(execCalls
        .every(({ args }) => args.includes(alloyFixture.jarPath))).toBe(true);
      expect(invocations.filter((args) => args.includes('exec'))
        .map((args) => argumentAfter(args, '--command'))).toEqual(['0', '1']);
      expect(invocations.filter((args) => args.includes('commands'))).toHaveLength(1);
      expect(readdirSync(join(directory, '.takt', 'runs')).filter((name) => name.startsWith('verify-'))).toEqual([]);
      expect(existsSync(join(directory, 'spec.als'))).toBe(false);
    } finally {
      restoreEnvironmentVariable('TAKT_ALLOY_JAR', originalJar);
      restoreEnvironmentVariable('TAKT_ALLOY_FIXTURE_LOG', originalLog);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('enumerates and executes checks at two-digit Alloy command indexes', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-alloy-two-digit-'));
    const alloyFixture = buildAlloyFixture(directory);
    const originalJar = process.env.TAKT_ALLOY_JAR;
    const originalLog = process.env.TAKT_ALLOY_FIXTURE_LOG;
    process.env.TAKT_ALLOY_JAR = alloyFixture.jarPath;
    process.env.TAKT_ALLOY_FIXTURE_LOG = alloyFixture.logPath;

    try {
      const result = await runFormalSpecVerification([
        '```alloy',
        'sig A {}',
        'check Check0 for 3',
        'run Run1 for 3',
        'check Check2 for 3',
        'run Run3 for 3',
        'check Check4 for 3',
        'run Run5 for 3',
        'check Check6 for 3',
        'run Run7 for 3',
        'check Check8 for 3',
        'run Run9 for 3',
        'check Check10 for 3',
        '```',
      ].join('\n'), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('passed');
      expect(result.alloy).toMatchObject({
        status: 'passed',
        checks: [0, 2, 4, 6, 8, 10],
        commands: [
          { number: 0, type: 'check', label: 'Check0' },
          { number: 1, type: 'run', label: 'Run1' },
          { number: 2, type: 'check', label: 'Check2' },
          { number: 3, type: 'run', label: 'Run3' },
          { number: 4, type: 'check', label: 'Check4' },
          { number: 5, type: 'run', label: 'Run5' },
          { number: 6, type: 'check', label: 'Check6' },
          { number: 7, type: 'run', label: 'Run7' },
          { number: 8, type: 'check', label: 'Check8' },
          { number: 9, type: 'run', label: 'Run9' },
          { number: 10, type: 'check', label: 'Check10' },
        ],
      });

      const invocations = readAlloyFixtureInvocations(alloyFixture.logPath);
      expect(invocations.filter((args) => args.includes('exec'))
        .map((args) => argumentAfter(args, '--command'))).toEqual(['0', '2', '4', '6', '8', '10']);
    } finally {
      restoreEnvironmentVariable('TAKT_ALLOY_JAR', originalJar);
      restoreEnvironmentVariable('TAKT_ALLOY_FIXTURE_LOG', originalLog);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('keeps an independent Alloy result after a real Quint parse failure', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-independent-'));
    const alloyFixture = buildAlloyFixture(directory);
    const originalJar = process.env.TAKT_ALLOY_JAR;
    const originalLog = process.env.TAKT_ALLOY_FIXTURE_LOG;
    process.env.TAKT_ALLOY_JAR = alloyFixture.jarPath;
    process.env.TAKT_ALLOY_FIXTURE_LOG = alloyFixture.logPath;

    try {
      const result = await runFormalSpecVerification([
        '```quint',
        'module invalid {',
        '```',
        '```alloy',
        'sig A {}',
        'check Safety for 1',
        '```',
      ].join('\n'), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('error');
      expect(result.quint.parse?.status).toBe('error');
      expect(result.alloy.status).toBe('passed');
      expect(result.javaMajorVersion).toBeGreaterThanOrEqual(17);
      expect(readAlloyFixtureInvocations(alloyFixture.logPath)
        .filter((args) => args.includes('exec'))).toHaveLength(1);
      expect(readdirSync(join(directory, '.takt', 'runs')).filter((name) => name.startsWith('verify-'))).toEqual([]);
    } finally {
      restoreEnvironmentVariable('TAKT_ALLOY_JAR', originalJar);
      restoreEnvironmentVariable('TAKT_ALLOY_FIXTURE_LOG', originalLog);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('terminates a verification process tree and cleans the run directory on abort', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'takt-formal-spec-abort-'));
    const hangingJava = installHangingJava(directory);
    const originalPath = process.env.PATH;
    process.env.PATH = `${hangingJava.binDirectory}${process.platform === 'win32' ? ';' : ':'}${originalPath ?? ''}`;
    const abortController = new AbortController();

    try {
      const verification = runFormalSpecVerification(validAlloyResponse(), directory, {
        abortSignal: abortController.signal,
        modelCheckTimeoutSeconds: 300,
      });
      setTimeout(() => abortController.abort(), 50);
      await expect(verification).rejects.toBeDefined();
      expect(readdirSync(join(directory, '.takt', 'runs')).filter((name) => name.startsWith('verify-'))).toEqual([]);
    } finally {
      restoreEnvironmentVariable('PATH', originalPath);
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
