#!/usr/bin/env python3
"""Bounded, owned release-image acceptance. This module never deploys or publishes.

Prepare/pull all digest references and build the client before invoking this runner.
Registry index/manifests/blobs remain the promotion object; Docker IDs are local
execution identities only. RunSpec never selects acceptance cases or endpoints.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import asdict, dataclass, fields
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
from typing import Callable

SCHEMA_VERSION = 1
LABEL = 'video.divine.keycast.acceptance'
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
RESOURCE_ID = re.compile(r'[0-9a-f]{64}\Z')
REFERENCE = re.compile(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
# Later acceptance slices extend this source contract, never a caller's RunSpec.
REQUIRED_CASE_IDS = (
    'runtime.ownership', 'runtime.dependencies', 'runtime.migrations', 'runtime.health',
    'signing.http', 'signing.nip46', 'consent.authorize', 'consent.refresh',
    'management.creation-held',
)
SUITE_CASE_IDS = REQUIRED_CASE_IDS[4:]
HOST_ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin', 'LANG': 'C.UTF-8'}
DATABASE_URL = 'postgres://postgres:acceptance@localhost:5432/keycast_image_acceptance'
APP_ENV = {
    'NODE_ENV': 'production', 'DISABLE_EMAILS': 'true',
    'KMS_PROVIDER': 'file', 'USE_GCP_KMS': 'false',
    'MASTER_KEY_PATH': '/app/master.key', 'WEB_BUILD_DIR': '/app/web',
    'APP_URL': 'http://localhost:3000', 'ALLOWED_ORIGINS': 'http://localhost:3000',
    'ALLOWED_TENANT_DOMAINS': 'localhost', 'BUNKER_RELAYS': 'ws://localhost:8080',
    'DATABASE_URL': DATABASE_URL, 'REDIS_URL': 'redis://localhost:6379',
    'SHOW_TEAMS_FUNCTIONALITY': 'true',
}
BASE_IMAGE_ENV = {'PATH', 'HOME', 'HOSTNAME', 'LANG', 'LC_ALL', 'BUN_ENV'}
Executor = Callable[[list[str], dict[str, str], float], subprocess.CompletedProcess]


class AcceptanceError(Exception):
    """A fixed diagnostic category; never include child output or key material."""


class Cancelled(AcceptanceError):
    pass


def require(condition: bool, category: str = 'ownership_validation') -> None:
    if not condition:
        raise AcceptanceError(category)


def exact_keys(value: dict, names) -> None:
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('invalid fields')


@dataclass(frozen=True)
class RunSpec:
    schema_version: int
    source_sha: str
    workflow_sha: str
    tooling_sha: str
    workflow_run: int
    workflow_attempt: int
    image_ref: str
    platform_manifest_digest: str
    registry_config_digest: str
    daemon_image_id: str
    test_client_image_id: str
    dependencies: dict[str, str]
    evidence_dir: str

    def __post_init__(self):
        def valid(pattern, value):
            return isinstance(value, str) and pattern.fullmatch(value) is not None
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError('invalid schema')
        if not all(valid(SHA, s) for s in (self.source_sha, self.workflow_sha, self.tooling_sha)):
            raise ValueError('invalid source')
        if not self.source_sha == self.workflow_sha == self.tooling_sha:
            raise ValueError('unequal source')
        if any(type(x) is not int or x < 1 for x in (self.workflow_run, self.workflow_attempt)):
            raise ValueError('invalid workflow identity')
        if not valid(REFERENCE, self.image_ref):
            raise ValueError('release image must be digest pinned')
        if not all(valid(DIGEST, s) for s in (self.platform_manifest_digest,
                    self.registry_config_digest, self.daemon_image_id, self.test_client_image_id)):
            raise ValueError('invalid image identity')
        exact_keys(self.dependencies, ('postgres', 'redis', 'relay_builder'))
        if not all(valid(REFERENCE, ref) for ref in self.dependencies.values()):
            raise ValueError('dependency image must be digest pinned')
        if not isinstance(self.evidence_dir, str) or not Path(self.evidence_dir).is_absolute():
            raise ValueError('absolute evidence directory required')
        if any(c in self.evidence_dir for c in ('\n', '\r', ',', '\x00')):
            raise ValueError('invalid evidence directory')

    @classmethod
    def from_dict(cls, value: dict) -> RunSpec:
        exact_keys(value, (f.name for f in fields(cls)))
        return cls(**value)


@dataclass(frozen=True)
class AcceptanceResult:
    schema_version: int
    complete: bool
    passed: bool
    artifact_identity: dict
    configuration_fingerprint: str
    expected_case_ids: tuple[str, ...]
    executed_case_ids: tuple[str, ...]
    counts: dict[str, int]
    suite_exit_code: int | None
    cleanup: dict
    failure: str | None


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as file:
        json.dump(value, file, sort_keys=True)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


class SubprocessExecutor:
    """Explicit environment, argv only, private diagnostics and process-group timeout."""
    def __init__(self, directory: Path):
        self.directory = directory

    def __call__(self, argv: list[str], env: dict[str, str], timeout: float):
        output_path, error_path = (self.directory / n for n in ('child.out', 'child.err'))
        def diagnostic(path):
            return os.fdopen(os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w+b')
        with diagnostic(output_path) as out, diagnostic(error_path) as err:
            process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                process.wait(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                raise
            out.seek(0)
            body = out.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise AcceptanceError('child_output_budget')
            return subprocess.CompletedProcess(argv, process.returncode, body.decode('utf-8'), '')


class Runtime:
    def __init__(self, spec: RunSpec, execute: Executor | None):
        self.spec = spec
        self.evidence = Path(spec.evidence_dir)
        # Exclusive directory creation prevents adopting an old journal or volume.
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.nonce = secrets.token_hex(16)
        self.private = self.evidence / ('.private-' + self.nonce)
        self.private.mkdir(mode=0o700)
        (self.private / 'docker-config').mkdir(mode=0o700)
        self.execute = execute or SubprocessExecutor(self.private)
        self.journal_path = self.evidence / 'ownership.json'
        self.journal = {'schema_version': 1, 'nonce': self.nonce,
                        'resources': [], 'pending': [], 'private_dir': str(self.private)}
        self.save()
        self.deadline = time.monotonic() + 900
        self.images = {}
        self.network = ''
        self.owner = ''
        self.suite_exit_code = None

    def save(self):
        write_json(self.journal_path, self.journal)

    def call(self, args: list[str], timeout: float = 5, check: bool = True):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'acceptance_timeout')
        response = self.execute(['docker', *args], {**HOST_ENV, 'DOCKER_CONFIG': str(self.private / 'docker-config')}, min(timeout, remaining))
        if check:
            require(response.returncode == 0, 'child_failed')
        return response

    def inspect(self, kind: str, ident: str, optional: bool = False):
        args = ['network', 'inspect', ident] if kind == 'network' else ['inspect', ident]
        response = self.call(args, check=not optional)
        if response.returncode:
            # Only explicit daemon not-found replies are absence. A Docker outage
            # is not proof there was no preexisting name. JSON [] is test-boundary
            # representation; the Docker CLI also supplies [] on real absence.
            if response.stdout.strip() == '[]':
                return None
            raise AcceptanceError('inspect_failed')
        data = json.loads(response.stdout)
        require(isinstance(data, list) and len(data) == 1)
        return data[0]

    def absent(self, kind: str, name: str):
        # Docker inspect on an absent object returns JSON [] and a nonzero exit.
        require(self.inspect(kind, name, optional=True) is None, 'resource_collision')

    def record(self, kind: str, ident: str, role: str):
        require(RESOURCE_ID.fullmatch(ident) is not None, 'invalid_resource_id')
        self.journal['resources'].append({'kind': kind, 'id': ident, 'role': role, 'removed': False})
        self.journal['pending'] = [p for p in self.journal['pending'] if p['role'] != role]
        self.save()  # Exact IDs are durable before start, exec, mount or network use.

    def check_network(self):
        item = self.inspect('network', self.network)
        require(item['Id'] == self.network and item.get('Internal') is True)
        require(item.get('Labels', {}).get(LABEL) == self.nonce)
        allowed = {r['id'] for r in self.journal['resources'] if r['kind'] == 'container'}
        require(set(item.get('Containers', {})) <= allowed)

    def check_container(self, ident: str, image_id: str, role: str, active: bool = False):
        self.check_network()
        item = self.inspect('container', ident)
        require(item['Id'] == ident and item['Image'] == image_id)
        require(item.get('Config', {}).get('Labels', {}).get(LABEL) == self.nonce)
        host = item['HostConfig']
        mode = self.network if role == 'postgres' else 'container:' + self.owner
        require(host.get('NetworkMode') == mode)
        require(not host.get('PortBindings') and not host.get('Privileged'))
        require(host.get('PidMode', '') == '' and host.get('IpcMode', 'private') == 'private')
        require(not any(host.get(k) for k in ('Binds', 'VolumesFrom', 'Devices', 'CapAdd')))
        net = item['NetworkSettings']
        attachments = net.get('Networks', {})
        if role == 'postgres':
            network_name = self.inspect('network', self.network)['Name']
            require(set(attachments) == {network_name})
            network_id = attachments[network_name].get('NetworkID')
            require(network_id == self.network if active else network_id in ('', self.network))
        else:
            require(not attachments)
        require(not any(net.get('Ports', {}).values()))
        # CLI --tmpfs is represented by HostConfig.Tmpfs, separately from
        # .Mounts (bind/volume/explicit --mount entries). Validate both channels.
        expected_tmpfs = {
            'postgres': {'/var/lib/postgresql/data': 'rw,noexec,nosuid,size=1g'},
            'redis': {'/data': 'rw,noexec,nosuid,size=64m'},
            'client': {'/tmp': 'rw,nosuid,size=1g'},
        }.get(role, {})
        tmpfs = host.get('Tmpfs')
        if tmpfs is None:
            tmpfs = {}
        require(isinstance(tmpfs, dict) and tmpfs == expected_tmpfs)
        expected_mounts = {'/app/master.key': 'bind'} if role in ('migration', 'server') else {}
        mounts = item.get('Mounts')
        if mounts is None:
            mounts = []
        require(isinstance(mounts, list) and len(mounts) == len(expected_mounts))
        for mount in mounts:
            require(expected_mounts.get(mount['Destination']) == mount['Type'])
            if mount['Type'] == 'bind':
                require(mount.get('Source') == str(self.private / 'master.key') and mount.get('RW') is False)
        allowed = set(APP_ENV) | {'SERVER_NSEC'} if role in ('migration', 'server') else set()
        if role == 'postgres':
            allowed = {'POSTGRES_DB', 'POSTGRES_PASSWORD', 'PGDATA'}
        if role == 'relay':
            allowed = {'IDLE_TIMEOUT'}
        effective = dict(entry.split('=', 1) for entry in item['Config'].get('Env', []))
        for key in effective:
            require(key in allowed | BASE_IMAGE_ENV | self.images[image_id], 'unexpected_container_environment')
        expected_env = self.application_environment if role in ('migration', 'server') else {
            'postgres': {'POSTGRES_DB': 'keycast_image_acceptance', 'POSTGRES_PASSWORD': 'acceptance',
                         'PGDATA': '/var/lib/postgresql/data/pgdata'},
            'relay': {'IDLE_TIMEOUT': '0'},
        }.get(role, {})
        require(all(effective.get(k) == v for k, v in expected_env.items()), 'container_environment_mismatch')

    def create(self, role: str, image_ref: str, extra: list[str], command: list[str] = ()):
        name = 'keycast-acceptance-' + self.nonce + '-' + role
        self.absent('container', name)
        self.journal['pending'].append({'kind': 'container', 'name': name, 'role': role})
        self.save()
        mode = self.network if role == 'postgres' else 'container:' + self.owner
        args = ['create', '--name', name, '--cidfile', str(self.private / (role + '.cid')), '--label', LABEL + '=' + self.nonce,
                '--network', mode, '--log-driver', 'none', '--pull', 'never',
                '--platform', 'linux/amd64', *extra, image_ref, *command]
        ident = self.call(args, timeout=15).stdout.strip()
        self.record('container', ident, role)
        image_id = self.spec.daemon_image_id if role in ('migration', 'server') else self.spec.test_client_image_id if role == 'client' else self.dependency_ids['relay_builder' if role == 'relay' else role]
        self.check_container(ident, image_id, role)
        return ident

    def start(self, ident: str):
        self.call(['start', ident], timeout=15)

    def probe(self, args: list[str], budget: float, expected: str | None = None):
        until = min(time.monotonic() + budget, self.deadline)
        # Both wall clock and a finite iteration count bound a misbehaving clock.
        for _ in range(int(budget * 2) + 1):
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            response = self.call(args, timeout=min(5, remaining), check=False)
            if response.returncode == 0 and (expected is None or response.stdout.strip() == expected):
                return
            time.sleep(min(0.5, max(0, until - time.monotonic())))
        raise AcceptanceError('readiness_timeout')

    def prepare_images(self):
        self.dependency_ids = {}
        refs = [('release', self.spec.image_ref), ('client', self.spec.test_client_image_id), *self.spec.dependencies.items()]
        for role, ref in refs:
            rows = json.loads(self.call(['image', 'inspect', ref]).stdout)
            require(isinstance(rows, list) and len(rows) == 1, 'image_inspection')
            item = rows[0]
            require(item.get('Os') == 'linux' and item.get('Architecture') == 'amd64', 'image_platform')
            ident = item.get('Id', '')
            require(DIGEST.fullmatch(ident) is not None, 'image_identity')
            if role in ('release', 'client'):
                require(ident == (self.spec.daemon_image_id if role == 'release' else ref), 'image_identity')
            else:
                self.dependency_ids[role] = ident
            if role != 'client':
                digest = ref.split('@', 1)[1]
                require(any(isinstance(d, str) and d.endswith('@' + digest) for d in item.get('RepoDigests', [])), 'image_reference')
            # Image defaults are part of the immutable configuration, but may not
            # carry service credentials/integrations into the acceptance runtime.
            defaults = set()
            for entry in item.get('Config', {}).get('Env', []):
                key = entry.split('=', 1)[0]
                require(key in BASE_IMAGE_ENV | set(APP_ENV) | {
                    'PG_MAJOR', 'PG_VERSION', 'PG_SHA256', 'PGDATA', 'GOSU_VERSION',
                    'REDIS_VERSION', 'REDIS_DOWNLOAD_URL', 'REDIS_DOWNLOAD_SHA',
                    'PLAYWRIGHT_BROWSERS_PATH', 'BUN_INSTALL', 'NODE_VERSION', 'YARN_VERSION',
                }, 'unsafe_image_environment')
                defaults.add(key)
            self.images[ident] = self.images.get(ident, set()) | defaults

    def execute_suite(self):
        # Playwright must retain its real nonzero failure exit. Independently
        # read its sanitized summary even on failure; neither signal overrides
        # the other. Future suites always attempt that fixed summary in teardown.
        response = self.call(['exec', '-w', '/e2e', self.client, 'node',
                   'node_modules/@playwright/test/cli.js', 'test', '--config',
                   'challenge-image.config.ts'], timeout=600, check=False)
        self.suite_exit_code = response.returncode
        # The suite writes ONLY this allowlisted aggregate in the client tmpfs.
        # No Playwright reports or child output are promotion evidence.
        summary = json.loads(self.call(['exec', '-w', '/e2e', self.client, 'node', '-e',
            "process.stdout.write(require('node:fs').readFileSync('/tmp/challenge-image-summary.json','utf8'))"]).stdout)
        exact_keys(summary, ('schema_version', 'cases'))
        require(type(summary['schema_version']) is int and summary['schema_version'] == 1, 'suite_schema')
        require(isinstance(summary['cases'], list), 'suite_schema')
        cases = {}
        for item in summary['cases']:
            exact_keys(item, ('id', 'passed'))
            require(isinstance(item['id'], str) and item['id'] in SUITE_CASE_IDS and
                    item['id'] not in cases and type(item['passed']) is bool, 'suite_cases')
            cases[item['id']] = item['passed']
        return cases

    def run(self, cases: dict[str, bool]):
        self.prepare_images()  # All references already pulled; never resolve tags here.
        name = 'keycast-acceptance-' + self.nonce
        self.absent('network', name)
        self.journal['pending'].append({'kind': 'network', 'name': name, 'role': 'network'})
        self.save()
        self.network = self.call(['network', 'create', '--internal', '--label',
                                  LABEL + '=' + self.nonce, name], timeout=15).stdout.strip()
        self.record('network', self.network, 'network')
        self.check_network()
        self.owner = self.create('postgres', self.spec.dependencies['postgres'], [
            '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,size=1g',
            '--env', 'POSTGRES_DB=keycast_image_acceptance', '--env', 'POSTGRES_PASSWORD=acceptance',
            '--env', 'PGDATA=/var/lib/postgresql/data/pgdata'])
        redis = self.create('redis', self.spec.dependencies['redis'], ['--tmpfs', '/data:rw,noexec,nosuid,size=64m'], ['redis-server', '--save', '', '--appendonly', 'no'])
        relay = self.create('relay', self.spec.dependencies['relay_builder'], ['--env', 'IDLE_TIMEOUT=0'])
        self.client = self.create('client', self.spec.test_client_image_id, ['--tmpfs', '/tmp:rw,nosuid,size=1g'], ['sleep', 'infinity'])
        cases['runtime.ownership'] = True
        for ident in (self.owner, redis, relay, self.client):
            self.start(ident)
        self.check_container(self.owner, self.dependency_ids['postgres'], 'postgres', active=True)
        self.check_container(redis, self.dependency_ids['redis'], 'redis', active=True)
        self.check_container(relay, self.dependency_ids['relay_builder'], 'relay', active=True)
        self.check_container(self.client, self.spec.test_client_image_id, 'client', active=True)
        self.probe(['exec', '--env', 'PGPASSWORD=acceptance', self.owner, 'psql', '--host=localhost', '--port=5432', '-U', 'postgres', '-d', 'keycast_image_acceptance', '-At', '-v', 'ON_ERROR_STOP=1', '-c', 'SELECT 1'], 60, '1')
        self.probe(['exec', redis, 'redis-cli', 'PING'], 60, 'PONG')
        self.probe(['exec', '-w', '/e2e', self.client, 'node', '--input-type=module', '-e', RELAY_PROBE], 60)
        cases['runtime.dependencies'] = True
        key = self.call(['exec', '-w', '/e2e', self.client, 'node', '--input-type=module', '-e',
                         "import {generateSecretKey} from 'nostr-tools/pure'; process.stdout.write(Buffer.from(generateSecretKey()).toString('hex'));"]).stdout.strip()
        require(re.fullmatch('[0-9a-f]{64}', key) is not None, 'key_generation')
        private_write(self.private / 'master.key', base64.b64encode(secrets.token_bytes(32)).decode() + '\n')
        self.application_environment = {**APP_ENV, 'SERVER_NSEC': key}
        private_write(self.private / 'server.env', '\n'.join(k + '=' + v for k, v in self.application_environment.items()) + '\n')
        mounts = ['--env-file', str(self.private / 'server.env'), '--mount',
                  'type=bind,src=' + str(self.private / 'master.key') + ',dst=/app/master.key,readonly']
        migration = self.create('migration', self.spec.image_ref, [*mounts, '--entrypoint', '/app/keycast'], ['--migrate'])
        self.start(migration)
        require(self.call(['wait', migration], timeout=120).stdout.strip() == '0', 'migration_failed')
        cases['runtime.migrations'] = True
        # The embedded migration seeds its historical tenant. Only localhost is
        # provisioned here; no development accounts, grants, keys or presets.
        self.call(['exec', '--env', 'PGPASSWORD=acceptance', self.owner, 'psql', '--host=localhost', '--port=5432', '-U', 'postgres', '-d', 'keycast_image_acceptance',
                   '-v', 'ON_ERROR_STOP=1', '-c',
                   "INSERT INTO tenants(domain,name,settings) VALUES ('localhost','Synthetic acceptance','{}') ON CONFLICT (domain) DO UPDATE SET settings='{}'"])
        server = self.create('server', self.spec.image_ref, mounts)
        self.start(server)
        self.probe(['exec', '-w', '/e2e', self.client, 'node', '-e', HEALTH_PROBE], 90)
        cases['runtime.health'] = True
        # Recheck the full namespace immediately before fixture/signing requests.
        for resource in self.journal['resources']:
            if resource['kind'] == 'container':
                role = resource['role']
                ident = self.spec.daemon_image_id if role in ('server', 'migration') else self.spec.test_client_image_id if role == 'client' else self.dependency_ids['relay_builder' if role == 'relay' else role]
                self.check_container(resource['id'], ident, role, active=True)
        # Trusted runner handoff, not independent cryptographic ownership proof.
        # The client validates this strict schema/config and current_database()
        # before fixture writes. No caller-selected endpoints enter this file.
        attestation = {'schema_version': 1, 'nonce': self.nonce,
                       'source_sha': self.spec.source_sha, 'daemon_image_id': self.spec.daemon_image_id,
                       'namespace_owner_id': self.owner, 'client_id': self.client,
                       'database_url': DATABASE_URL, 'base_url': APP_ENV['APP_URL'],
                       'relay_url': APP_ENV['BUNKER_RELAYS']}
        self.call(['exec', '-w', '/e2e', self.client, 'node', '-e',
            "require('node:fs').writeFileSync('/tmp/challenge-image-ownership.json',process.argv[1],{mode:0o600,flag:'wx'})",
            json.dumps(attestation, sort_keys=True)])
        cases.update(self.execute_suite())


RELAY_PROBE = """
import WebSocket from 'ws';
import dns from 'node:dns';
dns.setDefaultResultOrder('ipv4first');
import {generateSecretKey, finalizeEvent} from 'nostr-tools/pure';
const event = finalizeEvent({kind:1,created_at:Math.floor(Date.now()/1000),tags:[],content:'synthetic acceptance probe'},generateSecretKey());
const ws = new WebSocket('ws://localhost:8080');
const timer = setTimeout(()=>{ws.terminate();process.exit(1)},4500);
ws.on('error',()=>{clearTimeout(timer);process.exit(1)});
ws.on('open',()=>ws.send(JSON.stringify(['REQ','acceptance-probe',{ids:[event.id]}])));
ws.on('message',(raw)=>{try{const message=JSON.parse(raw.toString());
if(message[0]==='EOSE') ws.send(JSON.stringify(['EVENT',event]));
if(message[0]==='EVENT' && message[1]==='acceptance-probe' && message[2]?.id===event.id){clearTimeout(timer);ws.close();process.exit(0)}
}catch{process.exit(1)}});
"""
HEALTH_PROBE = """
require('node:dns').setDefaultResultOrder('ipv4first');
(async()=>{for(const path of ['/healthz/startup','/healthz/ready']){
const response=await fetch('http://localhost:3000'+path,{signal:AbortSignal.timeout(2000)});
if(!response.ok)process.exit(1);await response.arrayBuffer();}process.exit(0)})().catch(()=>process.exit(1));
"""


def private_write(path: Path, body: str):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as file:
        file.write(body)


def load_journal(path: Path):
    journal = json.loads(path.read_text())
    exact_keys(journal, ('schema_version', 'nonce', 'resources', 'pending', 'private_dir'))
    if type(journal['schema_version']) is not int or journal['schema_version'] != 1 or not isinstance(journal['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', journal['nonce']):
        raise ValueError('invalid ownership journal')
    if journal['private_dir'] != str(path.parent / ('.private-' + journal['nonce'])):
        raise ValueError('invalid private directory')
    if not isinstance(journal['resources'], list):
        raise ValueError('invalid resources')
    seen = set()
    resource_roles = set()
    for resource in journal['resources']:
        exact_keys(resource, ('kind', 'id', 'role', 'removed'))
        if (resource['kind'] not in ('network', 'container') or
            not isinstance(resource['id'], str) or not RESOURCE_ID.fullmatch(resource['id']) or
            resource['id'] in seen or type(resource['removed']) is not bool or
            resource['role'] not in ('network', 'postgres', 'redis', 'relay', 'client', 'migration', 'server')):
            raise ValueError('invalid owned resource')
        if (resource['role'] in resource_roles or
            (resource['kind'] == 'network') != (resource['role'] == 'network')):
            raise ValueError('invalid resource role')
        resource_roles.add(resource['role'])
        seen.add(resource['id'])
    if not isinstance(journal['pending'], list):
        raise ValueError('invalid pending resources')
    roles = set()
    for pending in journal['pending']:
        exact_keys(pending, ('kind', 'role', 'name'))
        role = pending['role']
        if role not in ('network', 'postgres', 'redis', 'relay', 'client', 'migration', 'server') or role in roles or role in resource_roles:
            raise ValueError('invalid pending role')
        roles.add(role)
        kind = 'network' if role == 'network' else 'container'
        name = 'keycast-acceptance-' + journal['nonce'] + ('' if role == 'network' else '-' + role)
        if pending['kind'] != kind or pending['name'] != name:
            raise ValueError('invalid pending intent')
    return journal


def cleanup_owned(path: Path, execute: Executor | None = None) -> dict:
    """Idempotently delete exact journal IDs; never enumerate by label or name."""
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in previous:
        signal.signal(sig, signal.SIG_IGN)
    try:
        return _cleanup_owned(path, execute)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _cleanup_owned(path: Path, execute: Executor | None = None) -> dict:
    path = Path(path).absolute()
    journal = load_journal(path)
    private = Path(journal['private_dir'])
    if private.is_symlink():
        raise ValueError('invalid private directory')
    private.mkdir(mode=0o700, exist_ok=True)
    config = private / 'docker-config'
    if config.is_symlink():
        raise ValueError('invalid Docker config directory')
    config.mkdir(mode=0o700, exist_ok=True)
    execute = execute or SubprocessExecutor(private)
    deadline = time.monotonic() + 90
    failed = 0
    removed = 0
    def call(args):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'cleanup_timeout')
        return execute(['docker', *args], {**HOST_ENV, 'DOCKER_CONFIG': str(config)}, min(5, remaining))
    # A durable intent supports recovery across daemon-create/CLI acknowledgment.
    # Inspect only its exact random name/cidfile, record a verified full ID, then
    # remove only by that journaled ID. Never enumerate by label or delete by name.
    for pending in list(journal['pending']):
        try:
            args = ['network', 'inspect', pending['name']] if pending['kind'] == 'network' else ['inspect', pending['name']]
            reply = call(args)
            if reply.returncode:
                require(reply.stdout.strip() == '[]', 'cleanup_recovery_inspect')
                # A killed CLI may still have a daemon-side create in flight.
                # Absence at this instant cannot prove it will never materialize.
                # Preserve the exact intent for the workflow's cleanup retry.
                raise AcceptanceError('unacknowledged_creation')
            else:
                rows = json.loads(reply.stdout)
                require(isinstance(rows, list) and len(rows) == 1)
                item = rows[0]
                ident = item.get('Id', '')
                require(isinstance(ident, str) and RESOURCE_ID.fullmatch(ident) is not None)
                labels = item.get('Labels', {}) if pending['kind'] == 'network' else item.get('Config', {}).get('Labels', {})
                require(labels.get(LABEL) == journal['nonce'])
                expected_name = pending['name'] if pending['kind'] == 'network' else '/' + pending['name']
                require(item.get('Name') == expected_name)
                if pending['kind'] == 'network':
                    require(item.get('Internal') is True)
                else:
                    cidfile = private / (pending['role'] + '.cid')
                    require(not cidfile.is_symlink())
                    if cidfile.exists():
                        require(cidfile.read_text().strip() == ident, 'cleanup_cidfile')
                require(all(r['id'] != ident for r in journal['resources']))
                journal['resources'].append({'kind': pending['kind'], 'id': ident, 'role': pending['role'], 'removed': False})
            journal['pending'].remove(pending)
            write_json(path, journal)
        except (AcceptanceError, OSError, ValueError, KeyError, subprocess.SubprocessError):
            failed += 1
    resources = sorted(journal['resources'], key=lambda r: 2 if r['kind'] == 'network' else 1 if r['role'] == 'postgres' else 0)
    for resource in resources:
        if resource['removed']:
            continue
        # Retain namespace owner/network if a consumer could not be destroyed.
        if failed and (resource['role'] == 'postgres' or resource['kind'] == 'network'):
            continue
        try:
            args = ['network', 'inspect', resource['id']] if resource['kind'] == 'network' else ['inspect', resource['id']]
            reply = call(args)
            if reply.returncode:
                require(reply.stdout.strip() == '[]', 'cleanup_inspect_failed')
            else:
                rows = json.loads(reply.stdout)
                require(isinstance(rows, list) and len(rows) == 1)
                item = rows[0]
                labels = item.get('Labels', {}) if resource['kind'] == 'network' else item.get('Config', {}).get('Labels', {})
                require(item.get('Id') == resource['id'] and labels.get(LABEL) == journal['nonce'])
                args = ['network', 'rm', resource['id']] if resource['kind'] == 'network' else ['rm', '--force', '--volumes', resource['id']]
                require(call(args).returncode == 0, 'cleanup_remove_failed')
            resource['removed'] = True
            removed += 1
            write_json(path, journal)
        except (AcceptanceError, OSError, ValueError, KeyError, subprocess.SubprocessError):
            failed += 1
    # No recursive deletion or caller-selected paths. Destroy only known ephemeral
    # files. A failed Docker cleanup still removes signing material and diagnostics.
    for name in ('master.key', 'server.env', 'child.out', 'child.err', 'postgres.cid',
                 'redis.cid', 'relay.cid', 'client.cid', 'migration.cid', 'server.cid'):
        try:
            (private / name).unlink(missing_ok=True)
        except OSError:
            failed += 1
    try:
        config.rmdir()
    except OSError:
        failed += 1
    try:
        private.rmdir()
    except OSError:
        failed += 1
    complete = failed == 0 and not journal['pending'] and all(r['removed'] for r in resources)
    return {'complete': complete, 'removed': removed, 'failed': failed}


def run_acceptance(spec: RunSpec, execute: Executor | None = None) -> AcceptanceResult:
    # Validate again, including callers constructing/mutating dataclass dictionaries.
    spec = RunSpec.from_dict(asdict(spec))
    cases = {}
    runtime = None
    failure = None
    cleanup = {'complete': False, 'removed': 0, 'failed': 0}
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    def cancel(_signum, _frame):
        raise Cancelled('cancelled')
    for sig in previous:
        signal.signal(sig, cancel)
    try:
        runtime = Runtime(spec, execute)
        runtime.run(cases)
    except (KeyboardInterrupt, Cancelled):
        failure = 'cancelled'
    except subprocess.TimeoutExpired:
        failure = 'child_timeout'
    except AcceptanceError as error:
        failure = str(error)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        failure = 'invalid_runtime_or_child_result'
    finally:
        # A second SIGTERM cannot interrupt the bounded cleanup phase. A hosted
        # workflow always-step repeats --cleanup if the process is forcibly killed.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if runtime is not None:
                cleanup = cleanup_owned(runtime.journal_path, runtime.execute)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    suite_exit_code = runtime.suite_exit_code if runtime is not None else None
    complete = failure is None and set(cases) == set(REQUIRED_CASE_IDS)
    passed = complete and suite_exit_code == 0 and all(cases.values()) and cleanup['complete']
    if failure is None:
        if suite_exit_code is not None and suite_exit_code != 0:
            failure = 'suite_failed'
        elif not complete:
            failure = 'incomplete_case_set'
    identity = asdict(spec)
    del identity['evidence_dir']
    configuration = {'app_environment': APP_ENV, 'generated_server_key': True,
                     'namespace': 'internal-postgres-owner', 'platform': 'linux/amd64',
                     'dependencies': spec.dependencies, 'required_cases': REQUIRED_CASE_IDS}
    fingerprint = hashlib.sha256(json.dumps(configuration, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    result = AcceptanceResult(1, complete, passed, identity, fingerprint, REQUIRED_CASE_IDS,
        tuple(case for case in REQUIRED_CASE_IDS if case in cases),
        {'expected': len(REQUIRED_CASE_IDS), 'executed': len(cases),
         'passed': sum(v is True for v in cases.values()), 'failed': sum(v is False for v in cases.values())},
        suite_exit_code, cleanup, failure)
    if runtime is not None:
        write_json(runtime.evidence / 'acceptance.json', asdict(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--spec', type=Path)
    group.add_argument('--cleanup', type=Path)
    args = parser.parse_args()
    try:
        if args.cleanup:
            result = cleanup_owned(args.cleanup)
            print(json.dumps({'schema_version': 1, 'cleanup': result}, sort_keys=True))
            return 0 if result['complete'] else 1
        spec = RunSpec.from_dict(json.loads(args.spec.read_text()))
        result = run_acceptance(spec)
        print(json.dumps(asdict(result), sort_keys=True))
        return 0 if result.passed else 1
    except (OSError, ValueError, AcceptanceError, subprocess.SubprocessError):
        print('Acceptance input or cleanup failed.', file=__import__('sys').stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
