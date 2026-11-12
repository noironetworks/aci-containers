"""Exercise the actual prepared ACI workflow source gate before privileged steps."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]

class ACIInputGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.job=yaml.safe_load((ROOT/'.github/workflows/aci-containers-images.yml').read_text())['jobs']['build-and-publish']
        cls.guard=next(step for step in cls.job['steps'] if step['name']=='Validate release source and prepare compatibility environment')

    def run_guard(self,expected,mode='prepared-v1'):
        with tempfile.TemporaryDirectory(prefix='aci-input-guard-') as directory:
            directory=Path(directory)
            git=directory/'git'
            git.write_text('#!'+sys.executable+'\nimport json,os,sys\n'
                'with open(os.environ["FIXTURE_GIT_CALLS"],"a") as stream: stream.write(json.dumps(sys.argv[1:])+"\\n")\n'
                'if sys.argv[1] == "cat-file": print("tag")\n'
                'elif sys.argv[1] == "rev-parse": print("a"*40)\n')
            git.chmod(0o755)
            env={**os.environ,'PATH':str(directory)+os.pathsep+os.environ['PATH'],
                'CI_EVIDENCE_MODE':mode,'GITHUB_REF_NAME':'6.1.1.8','UPSTREAM_ID':'81c2369',
                'SKIP_CICD_STATUS':'false','SOURCE_BRANCH':'fixture-branch','GITHUB_ENV':str(directory/'env'),
                'GITHUB_RUN_NUMBER':'123','GITHUB_REPOSITORY':'noironetworks/aci-containers',
                'GITHUB_SERVER_URL':'https://github.com','GITHUB_RUN_ID':'7654321','RUNNER_TEMP':str(directory),
                'FIXTURE_GIT_CALLS':str(directory/'git-calls'),'FIXTURE_DIR':str(directory)}
            env.pop('EXPECTED_OPFLEX_BASE_DIGEST',None)
            if expected is not None: env['EXPECTED_OPFLEX_BASE_DIGEST']=expected
            # This sentinel models default success()-guarded later workflow steps.
            # The exact checked-in source gate executes before either can run.
            after='\ntouch "${FIXTURE_DIR}/credentials"\ntouch "${FIXTURE_DIR}/build"\nprintf "%s" "${EXPECTED_OPFLEX_BASE_DIGEST:-}" > "${FIXTURE_DIR}/forwarded"\n'
            result=subprocess.run(['bash','-c',self.guard['run']+after],env=env,capture_output=True,text=True,timeout=10)
            return {'code':result.returncode,'output':result.stdout+result.stderr,
                    'credentials':(directory/'credentials').exists(),'build':(directory/'build').exists(),
                    'git':(directory/'git-calls').exists(),
                    'forwarded':(directory/'forwarded').read_text() if (directory/'forwarded').exists() else None}

    def test_explicit_owner_digest_is_required_before_credentials_or_build(self):
        variable='MMR611_OPFLEX_BASE_DIGEST' if 'mmr-6.1.1' in self.job['env']['SOURCE_BRANCH'] else 'MASTER_OPFLEX_BASE_DIGEST'
        self.assertEqual(self.job['env']['EXPECTED_OPFLEX_BASE_DIGEST'],'${{ vars.'+variable+' }}')
        for value in (None,'','a'*64,'sha256:'+'a'*63,'sha256:'+'G'*64,'sha256:'+'a'*64+'\nother'):
            with self.subTest(value=value):
                result=self.run_guard(value)
                self.assertNotEqual(result['code'],0)
                self.assertFalse(result['credentials']);self.assertFalse(result['build']);self.assertFalse(result['git'])
                self.assertIn('require the approved EXPECTED_OPFLEX_BASE_DIGEST',result['output'])

    def test_approved_digest_is_forwarded_unchanged_after_actual_source_validation(self):
        expected='sha256:'+'d'*64
        result=self.run_guard(expected)
        self.assertEqual(result['code'],0,result['output'])
        self.assertTrue(result['credentials']);self.assertTrue(result['build']);self.assertTrue(result['git'])
        self.assertEqual(result['forwarded'],expected)

    def test_gate_precedes_real_registry_and_shared_builder_steps_and_preserves_legacy_adapter(self):
        steps=self.job['steps'];guard=steps.index(self.guard)
        auth=next(i for i,step in enumerate(steps) if step['name']=='Authenticate to image registries')
        build=next(i for i,step in enumerate(steps) if 'build-push-aci-containers-images.sh' in step.get('run',''))
        self.assertLess(guard,auth);self.assertLess(guard,build)
        self.assertNotIn('always()',str(steps[auth].get('if','')))
        self.assertNotIn('always()',str(steps[build].get('if','')))
        legacy=self.run_guard(None,mode='')
        self.assertEqual(legacy['code'],0,legacy['output'])

if __name__=='__main__':unittest.main()
