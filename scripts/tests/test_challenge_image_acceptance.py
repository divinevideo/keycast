"""Pure Docker-boundary contracts: no daemon, credentials or services are used."""
import copy
import dataclasses
import hashlib
import re
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1] / 'challenge-image-acceptance.py'
module = None
if RUNNER.exists():
    loader = importlib.util.spec_from_file_location('challenge_image_acceptance', RUNNER)
    module = importlib.util.module_from_spec(loader)
    sys.modules[loader.name] = module
    loader.loader.exec_module(module)

DIGEST = 'sha256:' + 'a' * 64
DAEMON_ID = 'sha256:' + 'b' * 64
CLIENT_ID = 'sha256:' + 'c' * 64
DEP_ID = 'sha256:' + 'd' * 64


def spec_dict(directory):
    return dict(schema_version=1, source_sha='1' * 40, workflow_sha='1' * 40,
                tooling_sha='1' * 40, workflow_run=123, workflow_attempt=1,
                image_ref='ghcr.io/synthetic/keycast@' + DIGEST,
                platform_manifest_digest='sha256:' + 'e' * 64,
                registry_config_digest=DIGEST, daemon_image_id=DAEMON_ID,
                test_client_image_id=CLIENT_ID,
                dependencies={'postgres': 'postgres@' + DIGEST,
                              'redis': 'redis@' + DIGEST,
                              'relay_builder': 'ghcr.io/synthetic/relay_builder@' + DIGEST},
                evidence_dir=str(directory))


class DockerBoundary:
    """Models only local Docker CLI operations; unexpected commands fail the test."""
    def __init__(self, sabotage=None):
        self.calls = []
        self.containers = {}
        self.networks = {}
        self.sabotage = sabotage
        self.removed = []
        self.summary = {'schema_version': 1, 'cases': []}
        self.server_environment = None
        self.suite_exit_code = 0

    def __call__(self, argv, env, timeout):
        assert isinstance(argv, list) and all(isinstance(x, str) for x in argv)
        assert 0 < timeout <= 900
        self.calls.append((argv, env, timeout))
        if self.sabotage == 'timeout' and 'node_modules/@playwright/test/cli.js' in argv:
            raise subprocess.TimeoutExpired(argv, timeout, output='PRIVATE CHILD BODY')
        if self.sabotage == 'sigterm' and 'psql' in argv:
            os.kill(os.getpid(), signal.SIGTERM)
        code, output = 0, ''
        if argv[1:3] == ['image', 'inspect']:
            ref = argv[-1]
            ident = CLIENT_ID if ref == CLIENT_ID else DAEMON_ID if 'keycast@' in ref else DEP_ID
            if self.sabotage == 'wrong-image' and 'keycast@' in ref:
                ident = DEP_ID
            output = json.dumps([{'Id': ident, 'Os': 'linux', 'Architecture': 'amd64',
                                  'RepoDigests': [ref], 'Config': {'Env': []}}])
        elif argv[1:3] == ['network', 'create']:
            ident = 'f' * 64
            label = argv[argv.index('--label') + 1]
            self.networks[ident] = {'Id': ident, 'Name': argv[-1], 'Internal': True,
                                   'Labels': dict([label.split('=', 1)]), 'Containers': {}}
            output = ident
        elif argv[1:3] == ['network', 'inspect']:
            target = argv[-1]
            item = self.networks.get(target) or next((n for n in self.networks.values() if n['Name'] == target), None)
            if item:
                item = dict(item)
                if self.sabotage == 'foreign-network':
                    item['Labels'] = {}
                if self.sabotage == 'public-network':
                    item['Internal'] = False
                output = json.dumps([item])
            else:
                code, output = 1, '[]'
        elif argv[1] == 'create':
            name = argv[argv.index('--name') + 1]
            image_index = next(i for i, value in enumerate(argv) if value.startswith(('postgres@', 'redis@', 'ghcr.io/', 'sha256:')))
            ref = argv[image_index]
            network = argv[argv.index('--network') + 1]
            labels = dict([argv[argv.index('--label') + 1].split('=', 1)])
            ident = f'{len(self.containers) + 1:064x}'
            mounts = []
            tmpfs = {}
            mount_specs = []
            for i, value in enumerate(argv):
                if value == '--mount':
                    fields = dict(x.split('=', 1) for x in argv[i + 1].split(',') if '=' in x)
                    readonly = 'readonly' in argv[i + 1].split(',')
                    mounts.append({'Type': fields['type'], 'Source': fields.get('src', ''),
                                   'Destination': fields['dst'], 'Mode': '', 'RW': not readonly,
                                   'Propagation': ''})
                    mount_specs.append({'Type': fields['type'], 'Source': fields.get('src', ''),
                                        'Target': fields['dst'], 'ReadOnly': readonly})
                if value == '--tmpfs':
                    destination, _, options = argv[i + 1].partition(':')
                    # --tmpfs is HostConfig.Tmpfs, not the .Mounts list.
                    tmpfs[destination] = options
            effective_env = []
            for i, value in enumerate(argv):
                if value == '--env':
                    effective_env.append(argv[i + 1])
                if value == '--env-file':
                    effective_env.extend(Path(argv[i + 1]).read_text().splitlines())
            if name.endswith('-server'):
                self.server_environment = dict(entry.split('=', 1) for entry in effective_env)
            self.containers[ident] = {
                'Id': ident, 'Name': '/' + name,
                'Image': CLIENT_ID if ref == CLIENT_ID else DAEMON_ID if 'keycast@' in ref else DEP_ID,
                'Config': {'Labels': labels, 'Env': effective_env}, 'Mounts': mounts,
                'HostConfig': {'NetworkMode': network, 'PortBindings': {}, 'Privileged': False,
                               'PidMode': '', 'IpcMode': 'private', 'Binds': None,
                               'VolumesFrom': None, 'Devices': [], 'CapAdd': None,
                               'Tmpfs': tmpfs or None, 'Mounts': mount_specs or None},
                'State': {'Running': False},
                'NetworkSettings': {'Networks': {} if network.startswith('container:') else {self.networks[network]['Name']: {'NetworkID': ''}}, 'Ports': {}},
            }
            if '--cidfile' in argv:
                Path(argv[argv.index('--cidfile') + 1]).write_text(ident)
            output = ident
        elif argv[1] == 'inspect':
            target = argv[-1]
            item = self.containers.get(target) or next((c for c in self.containers.values() if c['Name'] == '/' + target), None)
            if item:
                item = json.loads(json.dumps(item))
                if self.sabotage == 'foreign-container':
                    item['Config']['Labels'] = {}
                if self.sabotage == 'volume':
                    item['Mounts'].append({'Type': 'volume', 'Source': '/old/data', 'Destination': '/data', 'RW': True})
                if self.sabotage == 'host-port':
                    item['HostConfig']['PortBindings'] = {'3000/tcp': [{'HostPort': '3000'}]}
                if self.sabotage == 'second-network':
                    item['NetworkSettings']['Networks']['bridge'] = {}
                if self.sabotage == 'container-image':
                    item['Image'] = DEP_ID
                output = json.dumps([item])
            else:
                code, output = 1, '[]'
        elif argv[1] == 'start':
            assert argv[-1] in self.containers
            self.containers[argv[-1]]['State']['Running'] = True
            for attachment in self.containers[argv[-1]]['NetworkSettings']['Networks'].values():
                attachment['NetworkID'] = self.containers[argv[-1]]['HostConfig']['NetworkMode']
        elif argv[1] == 'exec':
            if 'psql' in argv:
                output = '1\n'
            elif 'redis-cli' in argv:
                output = 'PONG\n'
            elif 'node_modules/@playwright/test/cli.js' in argv:
                code = self.suite_exit_code
            elif 'node' in argv:
                script = argv[-1]
                if 'generateSecretKey' in script and 'finalizeEvent' not in script:
                    output = '2' * 64
                elif 'readFileSync' in script:
                    output = json.dumps(self.summary)
            else:
                raise AssertionError(argv)
        elif argv[1] == 'wait':
            output = '0\n'
        elif argv[1] == 'rm':
            ident = argv[-1]
            if self.sabotage == 'cleanup':
                return subprocess.CompletedProcess(argv, 1, '', 'PRIVATE CHILD BODY')
            self.removed.append(ident)
            self.containers.pop(ident, None)
        elif argv[1:3] == ['network', 'rm']:
            self.removed.append(argv[-1])
            self.networks.pop(argv[-1], None)
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, code, output, 'PRIVATE CHILD BODY' if code else '')


class AcceptanceContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(module, 'isolated acceptance runtime is not implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'evidence'
        self.data = spec_dict(self.directory)

    def run_with(self, boundary=None):
        boundary = boundary or DockerBoundary()
        return module.run_acceptance(module.RunSpec.from_dict(self.data), boundary), boundary

    def test_fingerprint_allowlist_excludes_dsns_credentials_and_private_key_hashes(self):
        baseline, _ = self.run_with()
        self.data['evidence_dir'] = str(Path(self.temp.name) / 'changed')
        altered = {**module.APP_ENV, 'DATABASE_URL': 'postgres://synthetic:secret@foreign/db',
                   'REDIS_URL': 'redis://synthetic:secret@foreign',
                   'SERVER_NSEC': 'private-key', 'PRIVATE_KEY_HASH': 'private-key-hash',
                   'AWS_SECRET_ACCESS_KEY': 'credential'}
        digest = hashlib.sha256
        with patch.object(module, 'APP_ENV', altered), patch.object(module.hashlib, 'sha256', wraps=digest) as hashing:
            changed, _ = self.run_with()
        serialized = next(c.args[0] for c in hashing.call_args_list if b'app_environment' in c.args[0])
        settings = json.loads(serialized)['app_environment']
        self.assertEqual(set(settings), {'NODE_ENV', 'DISABLE_EMAILS', 'KMS_PROVIDER', 'USE_GCP_KMS',
            'MASTER_KEY_PATH', 'WEB_BUILD_DIR', 'APP_URL', 'ALLOWED_ORIGINS', 'ALLOWED_TENANT_DOMAINS',
            'BUNKER_RELAYS', 'SHOW_TEAMS_FUNCTIONALITY'})
        self.assertEqual(changed.configuration_fingerprint, baseline.configuration_fingerprint)
        self.assertNotIn(b'secret', serialized)
        self.assertNotIn(b'private-key', serialized)
        self.assertEqual(module.APP_ENV['DATABASE_URL'], module.DATABASE_URL)

    def test_tmpfs_hostconfig_shape_and_nullable_mount_absence_reach_suite(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def nullable(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1] == 'inspect' and reply.returncode == 0:
                data = json.loads(reply.stdout)
                if not data[0]['Mounts']:
                    data[0]['Mounts'] = None
                reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(nullable)
        self.assertEqual(result.failure, 'incomplete_case_set')
        self.assertTrue(any('node_modules/@playwright/test/cli.js' in a for a, _, _ in docker.calls))
        postgres = next(c for c in docker.calls if c[0][1] == 'create' and 'POSTGRES_DB=keycast_image_acceptance' in c[0])
        self.assertIn('/var/lib/postgresql/data:rw,noexec,nosuid,size=1g', postgres[0])

    def test_missing_changed_or_foreign_tmpfs_rejects_before_exec(self):
        variants = (None, {}, {'/var/lib/postgresql/data': ''},
                    {'/var/lib/postgresql/data': 'rw,noexec,nosuid,size=2g'},
                    {'/var/lib/postgresql/data': 'rw,noexec,nosuid,size=1g', '/foreign': 'rw'},
                    ['/var/lib/postgresql/data'])
        for index, tmpfs in enumerate(variants):
            with self.subTest(tmpfs=tmpfs):
                self.data['evidence_dir'] = str(Path(self.temp.name) / str(index))
                docker = DockerBoundary()
                original = docker.__class__.__call__
                def altered(argv, env, timeout):
                    reply = original(docker, argv, env, timeout)
                    if argv[1] == 'inspect' and reply.returncode == 0:
                        data = json.loads(reply.stdout)
                        data[0]['HostConfig']['Tmpfs'] = tmpfs
                        reply.stdout = json.dumps(data)
                    return reply
                result, _ = self.run_with(altered)
                self.assertFalse(result.passed)
                self.assertFalse(any(a[1] == 'exec' for a, _, _ in docker.calls))

    def test_stray_anonymous_volume_at_image_volume_path_is_rejected(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def anonymous_volume(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1] == 'inspect' and reply.returncode == 0:
                data = json.loads(reply.stdout)
                data[0]['Mounts'].append({
                    'Type': 'volume', 'Name': '9' * 64,
                    'Source': '/var/lib/docker/volumes/' + '9' * 64 + '/_data',
                    'Destination': '/var/lib/postgresql/data', 'Driver': 'local',
                    'Mode': '', 'RW': True, 'Propagation': ''})
                reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(anonymous_volume)
        self.assertFalse(result.passed)
        self.assertFalse(any(a[1] == 'exec' for a, _, _ in docker.calls))

    def test_emitted_server_environment_passes_actual_binary_startup_gates(self):
        # Execute current Rust gates, rather than a Python copy of their logic.
        root = RUNNER.parent.parent
        main_source = (root / 'keycast/src/main.rs').read_text()
        email_source = (root / 'api/src/email_service.rs').read_text()
        def item(source, declaration):
            begin = source.index(declaration)
            return source[begin:source.index('\n}', begin) + 2]
        harness = """
use std::env;
extern crate self as tracing;
#[macro_export] macro_rules! warn { ($($argument:tt)*) => {{}}; }
// These calls only emit warnings; none authorizes/rejects startup.
fn warn_atproto_control_plane_config() {}
"""
        enum_start = main_source.index('enum KmsProvider {')
        harness += main_source[main_source.rfind('#[derive(', 0, enum_start):enum_start]
        harness += item(main_source, 'enum KmsProvider {') + '\n'
        harness += item(main_source, 'fn resolve_kms_provider()') + '\n'
        harness += item(main_source, 'fn validate_environment()') + '\n'
        harness += 'mod keycast_api { pub mod email_service { use std::env;\n'
        harness += item(email_source, 'pub fn validate_email_configuration()') + '\n}}\n'
        harness += 'fn main() { std::process::exit(if validate_environment().is_ok() { 0 } else { 1 }); }\n'
        source = Path(self.temp.name) / 'startup_gates.rs'
        executable = Path(self.temp.name) / 'startup_gates'
        source.write_text(harness)
        compiler = shutil.which('rustc')
        self.assertIsNotNone(compiler, 'actual startup-gate regression requires the Rust toolchain')
        compiled = subprocess.run([compiler, '--edition=2021', '--crate-name', 'acceptance_startup_gates',
                                   str(source), '-o', str(executable)],
                                  env={**{k: os.environ[k] for k in ('RUSTUP_HOME', 'CARGO_HOME', 'RUSTUP_TOOLCHAIN') if k in os.environ},
                                       'HOME': str(Path.home()), 'PATH': os.environ.get('PATH', os.defpath)},
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        _, docker = self.run_with()
        self.assertIsNotNone(docker.server_environment)
        environment = docker.server_environment
        self.assertEqual(environment['NODE_ENV'], 'production')
        self.assertNotIn('SENDGRID_API_KEY', environment)
        checked = subprocess.run([str(executable)], env=environment,
                                 capture_output=True, timeout=5)
        self.assertEqual(checked.returncode, 0, 'actual binary startup gate rejects emitted server env')
        for override in (None, 'false', 'TRUE'):
            with self.subTest(override=override):
                rejected = dict(environment)
                rejected.pop('DISABLE_EMAILS', None)
                if override is not None:
                    rejected['DISABLE_EMAILS'] = override
                checked = subprocess.run([str(executable)], env=rejected,
                                         capture_output=True, timeout=5)
                self.assertEqual(checked.returncode, 1)

    def test_tag_only_release_and_each_dependency_rejected_before_docker(self):
        for key in ('image_ref', 'postgres', 'redis', 'relay_builder'):
            with self.subTest(key=key):
                data = spec_dict(self.directory)
                if key == 'image_ref':
                    data[key] = 'ghcr.io/synthetic/keycast:latest'
                else:
                    data['dependencies'][key] = 'synthetic:latest'
                with self.assertRaises(ValueError):
                    module.RunSpec.from_dict(data)

    def test_unknown_fields_and_production_url_rejected(self):
        for key, value in [('app_url', 'https://production.example'), ('expected_case_ids', ['anything']),
                           ('environment', {'DATABASE_URL': 'postgres://production.example/live'})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.RunSpec.from_dict({**self.data, key: value})

    def test_source_mismatch_and_invalid_id_rejected(self):
        for key, value in [('workflow_sha', '2' * 40), ('daemon_image_id', 'keycast:latest'),
                           ('workflow_attempt', 0), ('workflow_run', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.RunSpec.from_dict({**self.data, key: value})

    def test_wrong_pulled_daemon_id_stops_before_resources(self):
        result, docker = self.run_with(DockerBoundary('wrong-image'))
        self.assertFalse(result.passed)
        self.assertFalse(any(call[0][1] in ('create', 'exec') for call in docker.calls))

    def test_legitimate_daemon_id_differs_from_config_digest(self):
        result, docker = self.run_with()
        self.assertTrue(any('--migrate' in call[0] for call in docker.calls))
        self.assertFalse(result.passed)  # Future acceptance suite is absent.
        self.assertFalse(result.complete)
        self.assertTrue(result.cleanup['complete'])

    def test_foreign_ownership_and_storage_never_reach_fixture_or_migration(self):
        for sabotage in ('foreign-container', 'foreign-network', 'public-network', 'volume',
                         'host-port', 'second-network', 'container-image'):
            with self.subTest(sabotage=sabotage):
                self.data['evidence_dir'] = str(Path(self.temp.name) / sabotage)
                result, docker = self.run_with(DockerBoundary(sabotage))
                self.assertFalse(result.passed)
                self.assertFalse(any('--migrate' in call[0] or 'exec' == call[0][1] for call in docker.calls))

    def test_preexisting_name_collision_is_never_adopted_or_removed(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def collide(argv, env, timeout):
            if argv[1:3] == ['network', 'inspect'] and argv[-1].startswith('keycast-acceptance-'):
                return subprocess.CompletedProcess(argv, 0, json.dumps([{'Id': '9' * 64}]), '')
            return original(docker, argv, env, timeout)
        result, _ = self.run_with(collide)
        self.assertFalse(result.passed)
        self.assertEqual(docker.removed, [])

    def test_runtime_topology_timeouts_environment_and_secrets(self):
        with patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY': 'INHERITED_SECRET',
                                    'DATABASE_URL': 'postgres://production.example/live',
                                    'DOCKER_HOST': 'tcp://production.example:2375',
                                    'DOCKER_CONFIG': '/production/credentials'}):
            result, docker = self.run_with()
        creates = [argv for argv, _, _ in docker.calls if argv[1] == 'create']
        owner = next(a for a in creates if any(v.startswith('postgres@') for v in a))
        self.assertIn('--tmpfs', owner)
        client = next(a for a in creates if CLIENT_ID in a)
        self.assertTrue(any(v.startswith('/tmp:') for v in client))
        for argv, env, timeout in docker.calls:
            self.assertNotIn('INHERITED_SECRET', repr(env))
            self.assertNotIn('DOCKER_HOST', env)
            self.assertNotIn('DATABASE_URL', env)
            self.assertIn('DOCKER_CONFIG', env)
            self.assertNotEqual(env['DOCKER_CONFIG'], '/production/credentials')
            self.assertNotIn('--publish', argv)
            self.assertNotIn('-p', argv)
            self.assertNotIn('/var/run/docker.sock', repr(argv))
            self.assertNotIn('production.example', repr(argv))
            self.assertGreater(timeout, 0)
        for argv in creates:
            network = argv[argv.index('--network') + 1]
            if argv is not owner:
                self.assertRegex(network, r'^container:[0-9a-f]{64}$')
        migrate = next(a for a in creates if '--migrate' in a)
        self.assertEqual(migrate[migrate.index('--entrypoint') + 1], '/app/keycast')
        serving = next(a for a in creates if any(v.startswith('ghcr.io/synthetic/keycast@') for v in a) and '--migrate' not in a)
        self.assertNotIn('--entrypoint', serving)
        self.assertTrue(any('node_modules/@playwright/test/cli.js' in a and 'challenge-image.config.ts' in a for a, _, _ in docker.calls))
        self.assertTrue(any('psql' in a and 'SELECT 1' in a and '--host=localhost' in a and '--port=5432' in a for a, _, _ in docker.calls))
        self.assertTrue(any('redis-cli' in a and 'PING' in a for a, _, _ in docker.calls))
        self.assertFalse(list(self.directory.glob('.private-*')))
        self.assertNotIn('PRIVATE CHILD BODY', json.dumps(dataclasses.asdict(result)))

    def test_incomplete_duplicate_unknown_and_failed_cases_fail_closed(self):
        for cases in ([], [{'id': 'unknown', 'passed': True}],
                      [{'id': 'signing.http.definition', 'passed': True}] * 2,
                      [{'id': 'signing.http.definition', 'passed': False}]):
            with self.subTest(cases=cases):
                docker = DockerBoundary()
                docker.summary['cases'] = cases
                self.data['evidence_dir'] = str(Path(self.temp.name) / str(len(docker.calls)) / str(len(repr(cases))))
                result, _ = self.run_with(docker)
                self.assertFalse(result.passed)
                self.assertFalse(result.complete)

    def test_timeout_cleans_up_without_raw_output(self):
        result, docker = self.run_with(DockerBoundary('timeout'))
        self.assertFalse(result.passed)
        self.assertTrue(result.cleanup['complete'])
        self.assertGreater(len(docker.removed), 3)
        self.assertNotIn('PRIVATE CHILD BODY', json.dumps(dataclasses.asdict(result)))

    def test_sigterm_is_caught_and_cleanup_runs(self):
        result, docker = self.run_with(DockerBoundary('sigterm'))
        self.assertFalse(result.passed)
        self.assertTrue(result.cleanup['complete'])
        self.assertGreater(len(docker.removed), 3)
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_cleanup_failure_prevents_success_and_journal_can_be_retried(self):
        result, docker = self.run_with(DockerBoundary('cleanup'))
        self.assertFalse(result.passed)
        self.assertFalse(result.cleanup['complete'])
        docker.sabotage = None
        status = module.cleanup_owned(self.directory / 'ownership.json', docker)
        self.assertTrue(status['complete'])
        before = list(docker.removed)
        self.assertTrue(module.cleanup_owned(self.directory / 'ownership.json', docker)['complete'])
        self.assertEqual(before, docker.removed)

    def test_cleanup_uses_only_recorded_ids_in_consumer_owner_network_order(self):
        _, docker = self.run_with()
        journal = json.loads((self.directory / 'ownership.json').read_text())
        ids = [r['id'] for r in journal['resources']]
        self.assertEqual(set(docker.removed), set(ids))
        self.assertEqual(docker.removed[-1], next(r['id'] for r in journal['resources'] if r['kind'] == 'network'))
        self.assertEqual(docker.removed[-2], next(r['id'] for r in journal['resources'] if r['role'] == 'postgres'))
        self.assertFalse(any('--filter' in a for a, _, _ in docker.calls))

    def test_cleanup_rejects_unknown_journal_fields_and_foreign_labels(self):
        _, docker = self.run_with(DockerBoundary('cleanup'))
        journal_path = self.directory / 'ownership.json'
        journal = json.loads(journal_path.read_text())
        journal['unknown'] = True
        journal_path.write_text(json.dumps(journal))
        with self.assertRaises(ValueError):
            module.cleanup_owned(journal_path, docker)
        del journal['unknown']
        journal_path.write_text(json.dumps(journal))
        docker.sabotage = 'foreign-container'
        result = module.cleanup_owned(journal_path, docker)
        self.assertFalse(result['complete'])
        self.assertEqual(docker.removed, [])

    def test_all_transport_matrix_rows_are_mandatory_and_generic_slots_are_rejected(self):
        names = (
            'get_public_key', 'definition', 'entry', 'withdraw', 'result',
            'contest_include', 'contest_exclude',
            'denied_kind_0', 'denied_kind_1', 'denied_kind_4', 'denied_kind_21',
            'denied_kind_22', 'denied_kind_44', 'denied_kind_1059',
            'denied_kind_22242', 'denied_kind_27235', 'denied_kind_34235', 'denied_kind_34236',
            'unmarked_31923', 'unmarked_1111', 'unmarked_1985',
            'mismatched_contest_namespace', 'bad_embedded_snapshot',
            'nip04_encrypt', 'nip04_decrypt', 'nip44_encrypt', 'nip44_decrypt',
            'sign_canonical', 'nip17_wrap_batch', 'nip17_unwrap_batch',
            'empty_policy_control', 'and_policy_control',
        )
        expected = {f'signing.{transport}.{name}' for transport in ('http', 'nip46') for name in names}
        actual = [case for case in module.SUITE_CASE_IDS if case.startswith('signing.')]
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), 64)
        self.assertEqual(len(module.REQUIRED_CASE_IDS), 106)
        self.assertEqual(set(module.SUITE_CASE_IDS) - expected,
                         {'consent.authorize', 'consent.refresh', 'consent.empty-authorize', 'consent.empty-refresh',
                          'management.no-global-preset', 'management.creation-held', 'management.allowed-kinds-control', 'management.picker'}
                         | {f'config.{name}.{boundary}' for name in ('unknown_permission', 'allowed_kinds_string', 'challenge_null', 'challenge_unknown', 'challenge_json')
                            for boundary in ('http', 'detail', 'list', 'consent', 'exchange', 'refresh')})
        # An old aggregate cannot conceal a missing concrete transport row.
        docker = DockerBoundary()
        docker.summary['cases'] = [{'id': c, 'passed': True} for c in module.SUITE_CASE_IDS]
        docker.summary['cases'][0]['id'] = 'signing.http'
        result, _ = self.run_with(docker)
        self.assertFalse(result.complete)
        self.assertFalse(result.passed)

    def test_every_consent_boundary_is_mandatory_once_and_must_pass(self):
        for target in (case for case in module.SUITE_CASE_IDS if not case.startswith('signing.')):
            for change in ('missing', 'duplicate', 'skipped', 'failed'):
                with self.subTest(target=target, change=change):
                    self.data['evidence_dir'] = str(Path(self.temp.name) / target / change)
                    docker = DockerBoundary()
                    docker.summary['cases'] = [{'id': c, 'passed': True} for c in module.SUITE_CASE_IDS]
                    row = next(row for row in docker.summary['cases'] if row['id'] == target)
                    if change == 'missing':
                        docker.summary['cases'].remove(row)
                    elif change == 'duplicate':
                        docker.summary['cases'].append(dict(row))
                    elif change == 'skipped':
                        row['skipped'] = True
                    else:
                        row['passed'] = False
                    result, _ = self.run_with(docker)
                    self.assertFalse(result.passed)

    def test_all_source_owned_cases_must_execute_and_cleanup_to_pass(self):
        docker = DockerBoundary()
        docker.summary['cases'] = [{'id': case, 'passed': True} for case in module.SUITE_CASE_IDS]
        result, _ = self.run_with(docker)
        self.assertTrue(result.complete)
        self.assertTrue(result.passed)
        self.assertEqual(result.counts, {'expected': 106, 'executed': 106, 'passed': 106, 'failed': 0})
        self.data['evidence_dir'] = str(Path(self.temp.name) / 'failed-case')
        docker = DockerBoundary()
        docker.suite_exit_code = 1
        docker.summary['cases'] = [{'id': case, 'passed': case != 'signing.http.definition'} for case in module.SUITE_CASE_IDS]
        result, _ = self.run_with(docker)
        self.assertTrue(result.complete)
        self.assertFalse(result.passed)
        self.assertEqual(result.counts['failed'], 1)

    def test_nonzero_suite_exit_preserves_summary_and_independently_blocks_success(self):
        for failed_case in (False, True):
            with self.subTest(failed_case=failed_case):
                self.data['evidence_dir'] = str(Path(self.temp.name) / str(failed_case))
                docker = DockerBoundary()
                docker.suite_exit_code = 1
                docker.summary['cases'] = [{'id': case, 'passed': case != 'signing.http.definition' or not failed_case} for case in module.SUITE_CASE_IDS]
                result, _ = self.run_with(docker)
                self.assertTrue(result.complete)
                self.assertFalse(result.passed)
                self.assertEqual(result.counts['executed'], 106)
                self.assertEqual(result.counts['failed'], int(failed_case))
                self.assertEqual(dataclasses.asdict(result).get('suite_exit_code'), 1)
                self.assertEqual(result.failure, 'suite_failed')
                self.assertTrue(result.cleanup['complete'])
                self.assertNotIn('PRIVATE CHILD BODY', json.dumps(dataclasses.asdict(result)))

    def test_nonzero_suite_exit_attempts_invalid_summary_and_fails_closed(self):
        docker = DockerBoundary()
        docker.suite_exit_code = 1
        docker.summary['cases'] = [{'id': 'unknown', 'passed': True}]
        result, _ = self.run_with(docker)
        self.assertFalse(result.passed)
        self.assertFalse(result.complete)
        self.assertEqual(dataclasses.asdict(result).get('suite_exit_code'), 1)
        self.assertTrue(any('readFileSync' in repr(a) for a, _, _ in docker.calls))
        self.assertEqual(result.counts['executed'], 4)
        self.assertTrue(result.cleanup['complete'])

    def test_incomplete_suite_does_not_discard_executed_case_evidence(self):
        docker = DockerBoundary()
        docker.summary['cases'] = [{'id': 'signing.http.definition', 'passed': True}]
        docker.suite_exit_code = 1
        result, _ = self.run_with(docker)
        self.assertFalse(result.complete)
        self.assertFalse(result.passed)
        self.assertIn('signing.http.definition', result.executed_case_ids)

    def test_unexpected_image_environment_is_rejected_before_network(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def credentials(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1:3] == ['image', 'inspect']:
                data = json.loads(reply.stdout)
                data[0]['Config']['Env'] = ['AWS_SECRET_ACCESS_KEY=PRIVATE CHILD BODY']
                reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(credentials)
        self.assertFalse(result.passed)
        self.assertFalse(docker.networks)
        self.assertFalse(any('--migrate' in a for a, _, _ in docker.calls))

    def test_dependency_pulled_reference_must_match_requested_digest(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def wrong_reference(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1:3] == ['image', 'inspect'] and argv[-1].startswith('postgres@'):
                data = json.loads(reply.stdout)
                data[0]['RepoDigests'] = ['postgres@sha256:' + '9' * 64]
                reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(wrong_reference)
        self.assertFalse(result.passed)
        self.assertFalse(any(a[1:3] == ['network', 'create'] for a, _, _ in docker.calls))

    def test_hanging_real_executor_is_killed_and_diagnostics_remain_private(self):
        private = Path(self.temp.name) / 'private'
        private.mkdir(mode=0o700)
        execute = module.SubprocessExecutor(private)
        with self.assertRaises(subprocess.TimeoutExpired):
            execute([sys.executable, '-c', "import time;print('PRIVATE CHILD BODY',flush=True);time.sleep(10)"], {}, 0.05)
        self.assertEqual((private / 'child.out').stat().st_mode & 0o777, 0o600)
        self.assertEqual((private / 'child.err').stat().st_mode & 0o777, 0o600)

    def test_creation_timeout_after_daemon_create_recovers_recorded_owned_id(self):
        for kind in ('network', 'container'):
            with self.subTest(kind=kind):
                self.data['evidence_dir'] = str(Path(self.temp.name) / kind)
                docker = DockerBoundary()
                original = docker.__class__.__call__
                fired = False
                def interrupted(argv, env, timeout):
                    nonlocal fired
                    reply = original(docker, argv, env, timeout)
                    if not fired and ((kind == 'network' and argv[1:3] == ['network', 'create']) or
                                      (kind == 'container' and argv[1] == 'create')):
                        fired = True
                        raise subprocess.TimeoutExpired(argv, timeout)
                    return reply
                result, _ = self.run_with(interrupted)
                self.assertFalse(result.passed)
                self.assertTrue(result.cleanup['complete'])
                self.assertEqual(len(docker.removed), 1 if kind == 'network' else 2)
                journal = json.loads((Path(self.data['evidence_dir']) / 'ownership.json').read_text())
                self.assertEqual(set(docker.removed), {r['id'] for r in journal['resources']})

    def test_forged_pending_intent_and_foreign_cidfile_never_remove_resources(self):
        _, docker = self.run_with(DockerBoundary('cleanup'))
        path = self.directory / 'ownership.json'
        journal = json.loads(path.read_text())
        journal['pending'] = [{'kind': 'container', 'role': 'server', 'name': 'production-server'}]
        path.write_text(json.dumps(journal))
        with self.assertRaises(ValueError):
            module.cleanup_owned(path, docker)
        self.assertEqual(docker.removed, [])

    def test_foreign_recovery_cidfile_and_labels_cannot_grant_cleanup_ownership(self):
        for sabotage in ('cidfile', 'labels'):
            with self.subTest(sabotage=sabotage):
                self.data['evidence_dir'] = str(Path(self.temp.name) / sabotage)
                docker = DockerBoundary()
                original = docker.__class__.__call__
                fired = False
                def interrupted(argv, env, timeout):
                    nonlocal fired
                    reply = original(docker, argv, env, timeout)
                    if not fired and argv[1] == 'create':
                        fired = True
                        if sabotage == 'cidfile':
                            Path(argv[argv.index('--cidfile') + 1]).write_text('9' * 64)
                        else:
                            docker.containers[reply.stdout]['Config']['Labels'] = {}
                        raise subprocess.TimeoutExpired(argv, timeout)
                    return reply
                result, _ = self.run_with(interrupted)
                self.assertFalse(result.passed)
                self.assertFalse(result.cleanup['complete'])
                self.assertEqual(docker.removed, [])

    def test_cleanup_timeout_after_delete_remains_idempotent(self):
        _, docker = self.run_with(DockerBoundary('cleanup'))
        docker.sabotage = None
        original = docker.__class__.__call__
        fired = False
        def interrupted(argv, env, timeout):
            nonlocal fired
            reply = original(docker, argv, env, timeout)
            if not fired and argv[1] == 'rm':
                fired = True
                raise subprocess.TimeoutExpired(argv, timeout)
            return reply
        path = self.directory / 'ownership.json'
        status = module.cleanup_owned(path, interrupted)
        self.assertFalse(status['complete'])
        self.assertTrue(module.cleanup_owned(path, docker)['complete'])
        self.assertEqual(len(docker.removed), len(set(docker.removed)))

    def test_attestation_is_derived_after_ownership_and_before_suite(self):
        _, docker = self.run_with()
        handoffs = [a for a, _, _ in docker.calls if len(a) >= 2 and 'writeFileSync' in a[-2]]
        self.assertEqual(len(handoffs), 1)
        handoff = handoffs[0]
        attestation = json.loads(handoff[-1])
        self.assertEqual(set(attestation), {
            'schema_version', 'nonce', 'source_sha', 'daemon_image_id',
            'namespace_owner_id', 'client_id', 'database_url', 'base_url', 'relay_url'})
        self.assertEqual(attestation['schema_version'], 1)
        self.assertEqual(attestation['daemon_image_id'], DAEMON_ID)
        self.assertEqual(attestation['source_sha'], '1' * 40)
        self.assertRegex(attestation['nonce'], r'^[0-9a-f]{32}$')
        self.assertEqual(attestation['base_url'], 'http://localhost:3000')
        self.assertEqual(attestation['relay_url'], 'ws://localhost:8080')
        self.assertEqual(attestation['database_url'], 'postgres://postgres:acceptance@localhost:5432/keycast_image_acceptance')
        self.assertNotIn('SERVER_NSEC', repr(attestation))
        calls = [a for a, _, _ in docker.calls]
        self.assertLess(calls.index(handoff), next(i for i, a in enumerate(calls) if 'node_modules/@playwright/test/cli.js' in a))

    def test_suite_receives_only_owned_fixture_bootstrap_identity(self):
        _, docker = self.run_with()
        handoff = next(a for a, _, _ in docker.calls if len(a) >= 2 and 'writeFileSync' in a[-2])
        attestation = json.loads(handoff[-1])
        suite = next(a for a, _, _ in docker.calls if 'node_modules/@playwright/test/cli.js' in a)
        environment = dict(suite[i + 1].split('=', 1) for i, value in enumerate(suite) if value == '--env')
        self.assertEqual(environment, {
            'CHALLENGE_IMAGE_NONCE': attestation['nonce'],
            'CHALLENGE_IMAGE_SOURCE_SHA': attestation['source_sha'],
            'CHALLENGE_IMAGE_DAEMON_IMAGE_ID': attestation['daemon_image_id'],
            'CHALLENGE_IMAGE_NAMESPACE_OWNER_ID': attestation['namespace_owner_id'],
            'CHALLENGE_IMAGE_CLIENT_ID': attestation['client_id'],
            'BUNKER_RELAYS': 'ws://localhost:8080',
        })

    def test_cleanup_failed_full_suite_cannot_emit_passed_true(self):
        docker = DockerBoundary('cleanup')
        docker.summary['cases'] = [{'id': case, 'passed': True} for case in module.SUITE_CASE_IDS]
        result, _ = self.run_with(docker)
        self.assertTrue(result.complete)
        self.assertFalse(result.passed)
        self.assertFalse(result.cleanup['complete'])
        self.assertFalse(json.loads((self.directory / 'acceptance.json').read_text())['passed'])

    def test_unacknowledged_create_without_visible_resource_keeps_intent_and_fails_cleanup(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def interrupted(argv, env, timeout):
            if argv[1:3] == ['network', 'create']:
                raise subprocess.TimeoutExpired(argv, timeout)
            return original(docker, argv, env, timeout)
        result, _ = self.run_with(interrupted)
        self.assertFalse(result.passed)
        self.assertFalse(result.cleanup['complete'])
        journal = json.loads((self.directory / 'ownership.json').read_text())
        self.assertEqual(len(journal['pending']), 1)
        self.assertEqual(docker.removed, [])

    def test_late_client_ownership_failure_prevents_attestation_and_suite(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def foreign(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1] == 'inspect' and reply.returncode == 0:
                data = json.loads(reply.stdout)
                is_client = data[0]['Image'] == CLIENT_ID
                server_exists = any(c['Image'] == DAEMON_ID and not c['Name'].endswith('-migration') for c in docker.containers.values())
                if is_client and server_exists:
                    data[0]['Config']['Labels'] = {}
                    reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(foreign)
        self.assertFalse(result.passed)
        self.assertFalse(any('writeFileSync' in repr(a) or 'node_modules/@playwright/test/cli.js' in a for a, _, _ in docker.calls))

    def test_invalid_cli_input_exits_nonzero_without_diagnostics(self):
        path = Path(self.temp.name) / 'spec.json'
        path.write_text(json.dumps({**self.data, 'secret': 'PRIVATE CHILD BODY'}))
        child = subprocess.run([sys.executable, str(RUNNER), '--spec', str(path)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(child.returncode, 0)
        self.assertNotIn('PRIVATE CHILD BODY', child.stdout + child.stderr)
        self.assertNotIn('"passed": true', child.stdout)


ROOT = RUNNER.parent.parent
PYTHON_CONTRACT = "python3 -m unittest discover -s scripts/tests -p 'test_challenge_image_acceptance.py' -v"


def workflow_file(name):
    path = ROOT / '.github/workflows' / name
    if not path.exists():
        raise AssertionError(f'missing workflow contract: {name}')
    result = subprocess.run(['bun', '-e',
        'process.stdout.write(JSON.stringify(Bun.YAML.parse(await Bun.stdin.text())))'],
        input=path.read_text(), capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


class WorkflowContracts(unittest.TestCase):
    def check_workflow(self, workflow, publishing):
        self.assertEqual(set(workflow), {'name', 'on', 'permissions', 'jobs'})
        self.assertEqual(workflow['permissions'], {'contents': 'read', **({'packages': 'write'} if publishing else {})})
        self.assertEqual(set(workflow['on']), {'workflow_dispatch'} if publishing else {'pull_request'})
        if not publishing:
            self.assertEqual(workflow['on']['pull_request'], {'branches': ['main']})
        else:
            self.assertEqual(workflow['on']['workflow_dispatch']['inputs']['source_sha'],
                {'description': 'Full current main commit SHA (40 lowercase hex characters)', 'required': True, 'type': 'string'})
        self.assertEqual(set(workflow['jobs']), {'acceptance' if publishing else 'contracts'})
        job = next(iter(workflow['jobs'].values()))
        self.assertEqual(set(job), {'runs-on', 'timeout-minutes', 'steps'} | ({'if'} if publishing else set()))
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertTrue(type(job['timeout-minutes']) is int and 0 < job['timeout-minutes'] <= 60)
        for forbidden in ('services', 'environment', 'permissions', 'uses', 'continue-on-error'):
            self.assertNotIn(forbidden, job)
        steps = job['steps']
        checkouts = [s for s in steps if s.get('uses', '').startswith('actions/checkout@')]
        self.assertEqual(len(checkouts), 1)
        self.assertEqual(checkouts[0]['with']['persist-credentials'], False)
        uses = [s.get('uses') for s in steps if 'uses' in s]
        allowed = {'actions/checkout@v6', 'oven-sh/setup-bun@v2', 'actions-rust-lang/setup-rust-toolchain@v1'}
        if publishing:
            allowed |= {'docker/setup-buildx-action@v3', 'docker/build-push-action@v6', 'docker/login-action@v3', 'actions/upload-artifact@v4'}
        self.assertTrue(set(uses) <= allowed)
        self.assertEqual(uses, ['actions/checkout@v6', 'oven-sh/setup-bun@v2',
            *(['docker/setup-buildx-action@v3', 'docker/login-action@v3', 'docker/build-push-action@v6',
               'docker/build-push-action@v6', 'actions/upload-artifact@v4'] if publishing else ['actions-rust-lang/setup-rust-toolchain@v1'])])
        for step in steps:
            self.assertNotIn('continue-on-error', step)
            self.assertNotIn('services', step)
            text = json.dumps(step)
            self.assertIsNone(re.search(r'cloudbuild|build-test-push|bun run deploy|gcloud|id-token|repository_dispatch|gh workflow|IAM|secrets\.(?!GITHUB_TOKEN)', text, re.I))
        bun = next(s for s in steps if s.get('uses') == 'oven-sh/setup-bun@v2')
        self.assertEqual(bun['with'], {'bun-version': '1.3.10'})
        if not publishing:
            self.assertEqual(next(s['with'] for s in steps if s.get('uses') == 'actions-rust-lang/setup-rust-toolchain@v1'), {'toolchain': '1.93.0'})
            self.assertEqual([s['run'] for s in steps if 'run' in s],
                [PYTHON_CONTRACT, 'bun install --frozen-lockfile', 'bun test helpers/challenge-image.test.ts'])
            self.assertEqual([s.get('working-directory') for s in steps if 'run' in s], [None, 'e2e', 'e2e'])
            self.assertFalse(any('if' in s or 'env' in s for s in steps))
            return
        self.assertEqual(job['if'], "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'")
        by_id = {s['id']: s for s in steps if 'id' in s}
        for ident in ('identity', 'source', 'release', 'client', 'spec', 'accept', 'cleanup', 'evidence'):
            self.assertIn(ident, by_id)
        order = [s.get('id', s.get('uses')) for s in steps]
        self.assertLess(order.index('identity'), order.index('actions/checkout@v6'))
        self.assertLess(order.index('source'), order.index('docker/login-action@v3'))
        self.assertEqual(checkouts[0]['with']['ref'], '${{ inputs.source_sha }}')
        self.assertEqual(checkouts[0]['with']['fetch-depth'], 0)
        for ident in ('release', 'client'):
            self.assertEqual(by_id[ident]['env'], {'BUILDX_METADATA_PROVENANCE': 'max',
                'DOCKER_BUILD_RECORD_UPLOAD': 'false', 'DOCKER_BUILD_SUMMARY': 'false'})
        release = by_id['release']['with']
        self.assertEqual(release, {'context': '${{ runner.temp }}/challenge-source', 'file': '${{ runner.temp }}/challenge-source/Dockerfile',
            'platforms': 'linux/amd64', 'push': True, 'provenance': 'mode=max',
            'tags': 'ghcr.io/divinevideo/keycast:acceptance-${{ inputs.source_sha }}-${{ github.run_id }}-${{ github.run_attempt }}'})
        self.assertEqual(by_id['client']['with'], {'context': '${{ runner.temp }}/challenge-source',
            'file': '${{ runner.temp }}/challenge-source/e2e/Dockerfile.acceptance', 'platforms': 'linux/amd64',
            'load': True, 'push': False, 'labels': 'video.divine.keycast.role=test-tooling', 'provenance': False})
        self.assertEqual([s.get('id') for s in steps if 'run' in s], ['identity', 'source', 'spec', None, 'accept', 'cleanup', 'evidence'])
        self.assertEqual(next(s['run'] for s in steps if 'run' in s and 'id' not in s), 'docker logout ghcr.io')
        self.assertFalse(any('if' in by_id[k] for k in ('identity', 'source', 'release', 'client', 'spec', 'accept')))
        self.assertEqual(by_id['accept']['run'], 'python3 scripts/challenge-image-acceptance.py --spec "$RUNNER_TEMP/run-spec.json" > "$RUNNER_TEMP/acceptance-cli.json"')
        self.assertEqual(by_id['cleanup']['if'], 'always()')
        self.assertEqual(by_id['evidence']['if'], 'always()')
        self.assertLess(order.index('cleanup'), order.index('evidence'))
        uploads = [s for s in steps if s.get('uses') == 'actions/upload-artifact@v4']
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]['with']['path'].splitlines(),
            ['${{ runner.temp }}/challenge-public/summary.json', '${{ runner.temp }}/challenge-public/artifact.json'])
        self.assertEqual(uploads[0]['with']['retention-days'], 90)
        self.assertEqual(uploads[0]['with']['if-no-files-found'], 'error')
        self.assertEqual(uploads[0]['if'], 'always() && steps.evidence.outcome == \'success\'')

    def test_read_only_pr_workflow_semantics(self):
        self.check_workflow(workflow_file('challenge-image-contracts.yaml'), False)

    def test_manual_candidate_workflow_semantics(self):
        self.check_workflow(workflow_file('challenge-image-acceptance.yaml'), True)

    def test_workflow_mutations_fail_closed(self):
        original = workflow_file('challenge-image-acceptance.yaml')
        mutations = [lambda w: w['on'].update(push={}), lambda w: w['permissions'].update({'id-token': 'write'}),
            lambda w: w['jobs']['acceptance'].update(services={}), lambda w: w['jobs']['acceptance'].update({'if': 'true'}),
            lambda w: w['jobs']['acceptance']['steps'].append({'run': 'gcloud builds submit --config cloudbuild.yaml'}),
            lambda w: w['jobs']['acceptance']['steps'].append({'run': 'gh workflow run build-test-push.yaml'}),
            lambda w: w['jobs']['acceptance']['steps'].append({'run': 'echo ${{ secrets.PRODUCTION_KEY }}'}),
            lambda w: next(s for s in w['jobs']['acceptance']['steps'] if s.get('id') == 'accept').update({'continue-on-error': True}),
            lambda w: next(s for s in w['jobs']['acceptance']['steps'] if s.get('uses') == 'actions/upload-artifact@v4')['with'].update(path='${{ runner.temp }}/**'),
            lambda w: next(s for s in w['jobs']['acceptance']['steps'] if s.get('id') == 'release')['with'].update(tags='ghcr.io/divinevideo/keycast:latest')]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                changed = copy.deepcopy(original)
                mutate(changed)
                with self.assertRaises(AssertionError):
                    self.check_workflow(changed, True)

    def test_pr_mutations_cannot_add_credentials_or_skip_contracts(self):
        original = workflow_file('challenge-image-contracts.yaml')
        for mutate in (lambda w: w.update(env={'TOKEN': '${{ secrets.GITHUB_TOKEN }}'}),
            lambda w: w['jobs']['contracts'].update(services={}),
            lambda w: w['jobs']['contracts']['steps'][-1].update({'if': 'false'}),
            lambda w: w['jobs']['contracts']['steps'].append({'uses': 'docker/login-action@v3'}),
            lambda w: w['permissions'].update(packages='write')):
            changed = copy.deepcopy(original); mutate(changed)
            with self.assertRaises(AssertionError):
                self.check_workflow(changed, False)

    def inline_python(self, ident):
        steps = workflow_file('challenge-image-acceptance.yaml')['jobs']['acceptance']['steps']
        script = next(s['run'] for s in steps if s.get('id') == ident)
        self.assertTrue(script.startswith("python3 - <<'PY'\n"))
        return script.split('\n', 1)[1].rsplit('\nPY', 1)[0]

    def test_identity_script_rejects_nonmain_mismatches_and_untrusted_workflow_path(self):
        code = self.inline_python('identity')
        baseline = {'SOURCE_SHA': '1' * 40, 'GITHUB_SHA': '1' * 40, 'WORKFLOW_SHA': '1' * 40,
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_WORKFLOW_REF': 'divinevideo/keycast/.github/workflows/challenge-image-acceptance.yaml@refs/heads/main',
            'GITHUB_REPOSITORY': 'divinevideo/keycast'}
        for override in ({}, {'GITHUB_REF': 'refs/heads/topic'}, {'GITHUB_SHA': '2' * 40}, {'WORKFLOW_SHA': '2' * 40},
            {'SOURCE_SHA': 'main'}, {'GITHUB_EVENT_NAME': 'pull_request'}, {'GITHUB_WORKFLOW_REF': baseline['GITHUB_WORKFLOW_REF'].replace('@refs/heads/main', '@refs/heads/topic')}):
            result = subprocess.run([sys.executable, '-c', code], env={**os.environ, **baseline, **override}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode == 0, not override, override)

    def test_source_script_rejects_dirty_mismatched_or_advanced_main_and_excludes_ignored_files(self):
        code = self.inline_python('source')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'repo'; repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=repo, text=True,
                    env={**os.environ, 'GIT_AUTHOR_NAME': 'Synthetic', 'GIT_AUTHOR_EMAIL': 'synthetic@example.test',
                         'GIT_COMMITTER_NAME': 'Synthetic', 'GIT_COMMITTER_EMAIL': 'synthetic@example.test'}, timeout=10).strip()
            git('init', '-q')
            for name in ('Dockerfile', 'e2e/Dockerfile.acceptance', 'Cargo.lock', 'web/bun.lockb', 'keycast-login/bun.lock',
                'e2e/bun.lock', '.dockerignore', '.github/workflows/challenge-image-acceptance.yaml',
                'core/tests/fixtures/challenges/v1/events.json'):
                file = repo / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_text('synthetic')
            (repo / '.gitignore').write_text('ignored-local-secret\n')
            git('add', '.'); git('commit', '-qm', 'synthetic source')
            head = git('rev-parse', 'HEAD'); git('update-ref', 'refs/remotes/origin/main', head)
            (repo / 'ignored-local-secret').write_text('PRIVATE CHILD BODY')
            baseline = {'SOURCE_SHA': head, 'GITHUB_SHA': head, 'WORKFLOW_SHA': head,
                'GITHUB_WORKFLOW_REF': 'divinevideo/keycast/.github/workflows/challenge-image-acceptance.yaml@refs/heads/main',
                'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
            for i, overrides in enumerate(({}, {'SOURCE_SHA': '2' * 40}, {'WORKFLOW_SHA': '2' * 40})):
                temp = root / str(i); temp.mkdir()
                result = subprocess.run([sys.executable, '-c', code], cwd=repo,
                    env={**os.environ, **baseline, **overrides, 'RUNNER_TEMP': str(temp)}, capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, not overrides)
                if not overrides:
                    self.assertFalse((temp / 'challenge-source/ignored-local-secret').exists())
                    self.assertEqual(json.loads((temp / 'build-record.json').read_text())['checkout_head'], head)
            (repo / 'Cargo.lock').write_text('dirty')
            result = subprocess.run([sys.executable, '-c', code], cwd=repo,
                env={**os.environ, **baseline, 'RUNNER_TEMP': str(root)}, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            git('checkout', '--', 'Cargo.lock')
            (repo / 'Dockerfile').write_text('advanced')
            git('add', 'Dockerfile'); git('commit', '-qm', 'synthetic advance')
            git('update-ref', 'refs/remotes/origin/main', git('rev-parse', 'HEAD'))
            git('checkout', '-q', head)
            result = subprocess.run([sys.executable, '-c', code], cwd=repo,
                env={**os.environ, **baseline, 'RUNNER_TEMP': str(root)}, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)

    def test_spec_adapter_accepts_provenance_index_metadata_without_single_manifest_config_digest(self):
        code = self.inline_python('spec')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'challenge-source').mkdir(); (root / 'challenge-source/Cargo.lock').write_text('synthetic lock')
            record = dict(source_sha='1' * 40, workflow_sha='1' * 40, tooling_sha='1' * 40,
                workflow_run=123, workflow_attempt=1, input_hashes={'Cargo.lock': hashlib.sha256(b'synthetic lock').hexdigest()})
            def raw(data):
                value = json.dumps(data)
                return 'sha256:' + hashlib.sha256(value.encode()).hexdigest(), value + '\n'
            platform_digest, platform_raw = raw({'config': {'digest': DIGEST}})
            attestation_digest, attestation_raw = raw({'config': {'digest': DEP_ID}, 'layers': [{'digest': DIGEST}]})
            index_digest, index_raw = raw({'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [
                {'digest': platform_digest, 'platform': {'architecture': 'amd64', 'os': 'linux'}},
                {'digest': attestation_digest, 'annotations': {'vnd.docker.reference.type': 'attestation-manifest', 'vnd.docker.reference.digest': platform_digest}}]})
            metadata = {'containerimage.digest': index_digest,
                'containerimage.descriptor': {'mediaType': 'application/vnd.oci.image.index.v1+json', 'digest': index_digest},
                'buildx.build.provenance': {'materials': [{'uri': 'pkg:docker/synthetic@1', 'digest': {'sha256': 'a' * 64}}]}}
            calls = []
            def docker(args, **_kwargs):
                calls.append(args)
                self.assertEqual(args[0], 'docker')
                if args[1:4] == ['buildx', 'imagetools', 'inspect']:
                    if '--format' in args:
                        return json.dumps(metadata)
                    return {index_digest: index_raw, platform_digest: platform_raw,
                            attestation_digest: attestation_raw}[args[4].rsplit('@', 1)[1]]
                if args[1] == 'pull':
                    return ''
                if args[1:3] == ['image', 'inspect']:
                    ref = args[-1]
                    if ref == CLIENT_ID:
                        return json.dumps([{'Id': CLIENT_ID, 'Architecture': 'amd64', 'Os': 'linux',
                                            'Config': {'Labels': {'video.divine.keycast.role': 'test-tooling'}}}])
                    if ref.startswith('ghcr.io/divinevideo/keycast@'):
                        return json.dumps([{'Id': DAEMON_ID}])
                    return json.dumps([{'RepoDigests': [ref.rsplit(':', 1)[0] + '@' + DEP_ID]}])
                raise AssertionError(args)
            environment = {'RUNNER_TEMP': directory, 'RELEASE_DIGEST': index_digest, 'CLIENT_ID': CLIENT_ID,
                'RELEASE_METADATA': json.dumps(metadata), 'CLIENT_METADATA': json.dumps(metadata)}
            self.assertNotIn('containerimage.config.digest', metadata)
            mutations = [
                ('valid-provenance-index', lambda m: None),
                ('missing-descriptor', lambda m: m.pop('containerimage.descriptor')),
                ('missing-descriptor-digest', lambda m: m['containerimage.descriptor'].pop('digest')),
                ('mismatched-descriptor-digest', lambda m: m['containerimage.descriptor'].update(digest=platform_digest)),
                ('mismatched-descriptor-media-type', lambda m: m['containerimage.descriptor'].update(mediaType='application/vnd.oci.image.manifest.v1+json')),
                ('missing-metadata-digest', lambda m: m.pop('containerimage.digest')),
                ('mismatched-metadata-digest', lambda m: m.update({'containerimage.digest': platform_digest})),
                ('tag-only-release', lambda m: None),
            ]
            for name, mutate in mutations:
                with self.subTest(metadata=name):
                    changed = copy.deepcopy(metadata); mutate(changed)
                    (root / 'build-record.json').write_text(json.dumps(record))
                    (root / 'run-spec.json').unlink(missing_ok=True)
                    with patch.dict(os.environ, {**environment, 'RELEASE_METADATA': json.dumps(changed),
                        **({'RELEASE_DIGEST': 'latest'} if name == 'tag-only-release' else {})}), \
                        patch('subprocess.check_output', side_effect=docker), patch('subprocess.run'):
                        if name != 'valid-provenance-index':
                            with self.assertRaises((AssertionError, KeyError)):
                                exec(compile(code, '<workflow-spec>', 'exec'), {})
                            self.assertFalse((root / 'run-spec.json').exists())
                        else:
                            try:
                                exec(compile(code, '<workflow-spec>', 'exec'), {})
                            except (AssertionError, KeyError) as error:
                                self.fail(f'valid provenance-index metadata without single-manifest config digest was rejected: {error!r}')
                            spec = json.loads((root / 'run-spec.json').read_text())
                            self.assertEqual(spec['image_ref'], 'ghcr.io/divinevideo/keycast@' + index_digest)
                            self.assertEqual(spec['platform_manifest_digest'], platform_digest)
                            self.assertEqual(spec['registry_config_digest'], DIGEST)
                            self.assertEqual(spec['daemon_image_id'], DAEMON_ID)
                            self.assertNotEqual(spec['daemon_image_id'], spec['registry_config_digest'])
                            self.assertTrue(all('@sha256:' in ref for ref in spec['dependencies'].values()))
                            saved = json.loads((root / 'build-record.json').read_text())
                            self.assertEqual(saved['registry_index']['manifests'][1]['digest'], attestation_digest)
                            self.assertEqual(saved['release_buildx_metadata']['containerimage.descriptor']['digest'], index_digest)
                            self.assertNotIn('containerimage.config.digest', saved['release_buildx_metadata'])
            self.assertFalse(any(args[1:3] == ['network', 'create'] for args in calls))

    def test_sanitized_evidence_requires_exact_cases_exit_and_cleanup(self):
        code = self.inline_python('evidence')
        # Execute the actual publishing adapter with synthetic Task 1 outputs.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = spec_dict(root / 'challenge-runtime')
            identity = {k: v for k, v in spec.items() if k != 'evidence_dir'}
            result = dict(schema_version=1, complete=True, passed=True, artifact_identity=identity,
                configuration_fingerprint='a' * 64, expected_case_ids=list(module.REQUIRED_CASE_IDS),
                executed_case_ids=list(module.REQUIRED_CASE_IDS), counts={'expected': 106, 'executed': 106, 'passed': 106, 'failed': 0},
                suite_exit_code=0, cleanup={'complete': True, 'removed': 6, 'failed': 0}, failure=None)
            (root / 'challenge-runtime').mkdir()
            (root / 'run-spec.json').write_text(json.dumps(spec))
            (root / 'build-record.json').write_text(json.dumps({'schema_version': 1,
                **{key: '1' * 40 for key in ('source_sha', 'github_sha', 'workflow_sha', 'checkout_head', 'tooling_sha')},
                'workflow_run': 123, 'workflow_attempt': 1, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
                'workflow_ref': 'divinevideo/keycast/.github/workflows/challenge-image-acceptance.yaml@refs/heads/main',
                'fixture_policy_hashes': {'synthetic': 'a' * 64}}))
            (root / 'cleanup.json').write_text(json.dumps({'schema_version': 1, 'cleanup': result['cleanup']}))
            for name, mutate in [('valid', lambda r: None), ('empty', lambda r: r.update(executed_case_ids=[])),
                ('alias', lambda r: r['executed_case_ids'].__setitem__(4, 'signing.http')),
                ('duplicate', lambda r: r['executed_case_ids'].append(r['executed_case_ids'][0])),
                ('expected', lambda r: r.update(expected_case_ids=['signing.http'])),
                ('skipped', lambda r: r.update(skipped=1)), ('failed', lambda r: r['counts'].update(failed=1)),
                ('exit', lambda r: r.update(suite_exit_code=1)), ('cleanup', lambda r: r['cleanup'].update(complete=False)),
                ('before-complete', lambda r: r.update(complete=False)), ('mismatch', lambda r: r['artifact_identity'].update(tooling_sha='2' * 40)),
                ('secret', lambda r: r.update(raw_log='PRIVATE CHILD BODY'))]:
                altered = copy.deepcopy(result)
                mutate(altered)
                (root / 'challenge-runtime/acceptance.json').write_text(json.dumps(altered))
                process = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                    env={**os.environ, 'RUNNER_TEMP': directory, 'ACCEPT_OUTCOME': 'success', 'CLEANUP_OUTCOME': 'success'},
                    capture_output=True, timeout=5)
                self.assertEqual(process.returncode == 0, name == 'valid', (name, process.stderr))
                if name == 'valid':
                    summary = json.loads((root / 'challenge-public/summary.json').read_text())
                    artifact = json.loads((root / 'challenge-public/artifact.json').read_text())
                    self.assertEqual(summary['executed_case_ids'], list(module.REQUIRED_CASE_IDS))
                    self.assertEqual(summary['suite_exit_code'], 0)
                    self.assertTrue(summary['cleanup']['complete'])
                    self.assertEqual(artifact['run_spec'], spec)
                    self.assertNotIn('PRIVATE CHILD BODY', json.dumps([summary, artifact]))
            # A separate failed final cleanup must block even if the runner had succeeded.
            (root / 'challenge-runtime/acceptance.json').write_text(json.dumps(result))
            (root / 'cleanup.json').write_text(json.dumps({'schema_version': 1, 'cleanup': {'complete': False, 'removed': 0, 'failed': 1}}))
            process = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                env={**os.environ, 'RUNNER_TEMP': directory, 'ACCEPT_OUTCOME': 'success', 'CLEANUP_OUTCOME': 'success'}, capture_output=True, timeout=5)
            self.assertNotEqual(process.returncode, 0)
            (root / 'cleanup.json').write_text(json.dumps({'schema_version': 1, 'cleanup': result['cleanup']}))
            for outcome in ('skipped', 'failure', ''):
                process = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                    env={**os.environ, 'RUNNER_TEMP': directory, 'ACCEPT_OUTCOME': outcome, 'CLEANUP_OUTCOME': 'success'}, capture_output=True, timeout=5)
                self.assertNotEqual(process.returncode, 0)


if __name__ == '__main__':
    unittest.main()
