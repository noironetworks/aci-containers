"""Exercise the checked-in workflow conditions and source guards without credentials or tags.

Run: python3 -m unittest discover -s tests/ci -p 'test_*.py' -v
Requires PyYAML. Fixtures never call a real git, Docker, registry, or Actions API.
"""
import ast
import copy
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TOKEN = re.compile(r"'(?:[^']|'')*'|[A-Za-z_][\w-]*(?:\.[\w-]+)+|&&|\|\||!(?!=)|\btrue\b|\bfalse\b")


def evaluate(expression, context):
    """Small fail-closed evaluator for this workflow's boolean Actions expressions."""
    def resolve(path):
        value = context
        for part in path.split('.'):
            if not isinstance(value, dict):
                return ''
            value = value.get(part, '')
        return value
    def translate(match):
        token = match[0]
        if token.startswith("'"):
            return token
        return {'&&': ' and ', '||': ' or ', '!': ' not ', 'true': 'True', 'false': 'False'}.get(token, f'resolve({token!r})')
    expression = str(expression).strip().removeprefix('${{').removesuffix('}}').strip()
    translated = TOKEN.sub(translate, expression)
    tree = ast.parse(translated.strip(), mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Call, ast.Name,
               ast.Load, ast.Constant, ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise AssertionError(f'Unsupported workflow condition: {ast.dump(node)}')
        if isinstance(node, ast.Name) and node.id not in {'resolve', 'startsWith', 'success', 'always', 'cancelled'}:
            raise AssertionError(f'Unsupported workflow function: {node.id}')
    return bool(eval(compile(tree, '<workflow>', 'eval'), {'__builtins__': {}}, {
        'resolve': resolve, 'startsWith': lambda text, prefix: text.startswith(prefix),
        'success': lambda: context.get('_success', True), 'always': lambda: True,
        'cancelled': lambda: context.get('_cancelled', False),
    }))


class WorkflowPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.travis = yaml.safe_load((ROOT / '.travis.yml').read_text())
        files = [p for p in (ROOT / '.github/workflows').glob('*') if p.name in {
            'opflex-images.yml', 'aci-containers-images.yml', 'acc-provision-tag-publish.yml'}]
        cls.workflow = yaml.safe_load(files[0].read_text()) if files else None
        cls.workflow_text = files[0].read_text() if files else ''
        cls.repo = {'OpFlex CI': 'opflex', 'aci-containers CI': 'aci-containers', 'acc-provision CI': 'acc-provision'}[cls.workflow['name']] if cls.workflow else 'acc-provision-operator'

    def context(self, event='push', ref='refs/heads/topic', canonical=True, deleted=False):
        return {'github': {'event_name': event, 'ref': ref,
                'repository': f'noironetworks/{self.repo}' if canonical else f'fork/{self.repo}',
                'event': {'deleted': deleted}}, 'needs': {}}

    def selected(self, job, context):
        # Actions adds success() unless an explicit status function appears.
        needs = job.get('needs', [])
        if isinstance(needs, str):
            needs = [needs]
        prerequisites = all(context.get('needs', {}).get(n, {}).get('result') == 'success' for n in needs)
        return prerequisites and evaluate(job.get('if', 'success()'), context)

    def test_travis_is_unconditionally_retired(self):
        self.assertEqual(self.travis['if'], 'false')
        for provider in ['gha', 'travis', '', 'unexpected']:
            self.assertFalse(evaluate(self.travis['if'], {'env': {'CI_PROVIDER': provider}}))

    def test_retired_operator_has_no_image_producer(self):
        if self.workflow:
            return
        workflows = ROOT / '.github/workflows'
        self.assertFalse(any(workflows.glob('*')))

    def test_provider_selector_and_retagger_removed(self):
        self.assertNotIn('select-ci-provider', self.workflow_text)
        self.assertFalse((ROOT / '.github/workflows/push-git-tag.yaml').exists())

    def test_unit_test_event_matrix_has_no_secrets(self):
        if not self.workflow:
            return
        job_id = 'run-unit-tests' if self.repo == 'acc-provision' else 'unit-tests'
        unit = self.workflow['jobs'][job_id]
        self.assertEqual(unit['name'], {'acc-provision': 'Lint and unit tests', 'opflex': 'OpFlex unit tests', 'aci-containers': 'aci-containers unit tests'}[self.repo])
        self.assertNotIn('secrets.', str(unit))
        for event, ref, canonical, deleted, expected in [
            ('pull_request', 'refs/pull/3/merge', True, False, True),
            ('pull_request', 'refs/pull/3/merge', False, False, True),
            ('push', 'refs/heads/topic', True, False, True),
            ('push', 'refs/heads/topic', False, False, True),
            ('push', 'refs/heads/topic', True, True, False),
            ('push', 'refs/tags/6.1.1.8', True, False, False),
        ]:
            with self.subTest(event=event, ref=ref, canonical=canonical, deleted=deleted):
                self.assertEqual(self.selected(unit, self.context(event, ref, canonical, deleted)), expected)

    def test_publish_event_and_dependency_matrix(self):
        if not self.workflow:
            return
        jobs = self.workflow['jobs']
        entry = jobs['validate-source' if self.repo == 'opflex' else 'build-and-publish']
        for event, ref, canonical, deleted, expected in [
            ('push', 'refs/tags/6.1.1.8', True, False, True),
            ('push', 'refs/tags/6.1.1.8', False, False, False),
            ('push', 'refs/tags/6.1.1.8', True, True, False),
            ('push', 'refs/heads/topic', True, False, False),
            ('pull_request', 'refs/pull/3/merge', True, False, False),
        ]:
            self.assertEqual(self.selected(entry, self.context(event, ref, canonical, deleted)), expected)
        if self.repo == 'opflex':
            ctx = self.context(ref='refs/tags/6.1.1.8')
            for source, base, expected in [('success', 'success', True), ('failure', 'success', False), ('success', 'failure', False), ('success', 'skipped', False)]:
                ctx['needs'] = {'validate-source': {'result': source}, 'build-base': {'result': base}}
                self.assertEqual(self.selected(jobs['build-runtime'], ctx), expected)

    def test_release_not_cancelled_and_tests_cancelled(self):
        if not self.workflow:
            return
        if self.repo == 'acc-provision':
            self.assertTrue(self.workflow['jobs']['run-unit-tests']['concurrency']['cancel-in-progress'])
            self.assertFalse(self.workflow['jobs']['build-and-publish']['concurrency']['cancel-in-progress'])
        else:
            policy = self.workflow['concurrency']['cancel-in-progress']
            self.assertTrue(evaluate(policy, self.context()))
            self.assertFalse(evaluate(policy, self.context(ref='refs/tags/6.1.1.8')))

    def test_actual_shell_blocks_parse(self):
        if not self.workflow:
            return
        for job in self.workflow['jobs'].values():
            for step in job['steps']:
                if 'run' in step:
                    script = re.sub(r'\$\{\{.*?\}\}', 'fixture', step['run'])
                    result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, f"{step['name']}: {result.stderr}")

    def test_actual_source_validation_guards(self):
        if not self.workflow:
            return
        jobs = self.workflow['jobs']
        job = jobs['validate-source' if self.repo == 'opflex' else 'build-and-publish']
        guards = [s['run'] for s in job['steps'] if 'run' in s and any(marker in s['run'] for marker in ['Trigger tag is the plain', 'tagged_commit=', 'git cat-file -t'])]
        self.assertTrue(guards)
        with tempfile.TemporaryDirectory() as directory:
            fakegit = Path(directory) / 'git'
            fakegit.write_text('''#!/bin/bash
case "$1" in
 fetch) exit 0 ;;
 cat-file) printf '%s\\n' "${FIXTURE_TAG_TYPE:-tag}" ;;
 rev-parse)
  case "$2" in
   HEAD) printf '%s\\n' "${FIXTURE_HEAD:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" ;;
   refs/remotes/*) printf '%s\\n' "${FIXTURE_SOURCE:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" ;;
   *) printf '%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
  esac ;;
 *) echo "Unexpected git operation: $*" >&2; exit 99 ;;
esac
''')
            fakegit.chmod(0o755)
            for tag, kind, head, source, expected in [
                ('6.1.1.8', 'tag', 'a'*40, 'a'*40, True),
                ('bad', 'tag', 'a'*40, 'a'*40, False),
                ('6.1.1.8-opflex-build-base', 'tag', 'a'*40, 'a'*40, False),
                ('6.1.1.8', 'commit', 'a'*40, 'a'*40, False),
                ('6.1.1.8', 'tag', 'b'*40, 'a'*40, False),
                ('6.1.1.8', 'tag', 'a'*40, 'b'*40, False),
            ]:
                env = {**os.environ, 'PATH': directory + os.pathsep + os.environ['PATH'], 'GITHUB_REF_NAME': tag,
                       'UPSTREAM_ID': '81c2369', 'SKIP_CICD_STATUS': 'false', 'SOURCE_BRANCH': 'fixture-branch',
                       'CI_EVIDENCE_MODE': 'prepared-v1', 'EXPECTED_OPFLEX_BASE_DIGEST': 'sha256:' + 'e' * 64,
                       'SAFE_TAG': tag, 'GITHUB_ENV': directory + '/env', 'GITHUB_OUTPUT': directory + '/out',
                       'GITHUB_RUN_NUMBER': '123', 'GITHUB_REPOSITORY': f'noironetworks/{self.repo}',
                       'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_RUN_ID': '123', 'RUNNER_TEMP': directory,
                       'FIXTURE_TAG_TYPE': kind, 'FIXTURE_HEAD': head, 'FIXTURE_SOURCE': source}
                result = subprocess.run(['bash', '-c', '\n'.join(guards)], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, expected, f'{tag}/{kind}/{head}/{source}: {result.stdout} {result.stderr}')

if __name__ == '__main__':
    unittest.main()
