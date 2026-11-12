"""Credential and failure-boundary tests for the actual workflow callers."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]

class CallerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path=next(p for p in (ROOT/'.github/workflows').glob('*') if p.name in ('opflex-images.yml','aci-containers-images.yml','acc-provision-tag-publish.yml'))
        cls.workflow=yaml.safe_load(cls.path.read_text())
        cls.acc=cls.path.name.startswith('acc-provision')

    def test_exact_cicd_pin_required_and_checked_before_credentials(self):
        text=self.path.read_text()
        self.assertNotIn('CICD_BRANCH',text)
        pins=[]
        for env in [self.workflow.get('env',{})]+[job.get('env',{}) for job in self.workflow['jobs'].values()]:
            if 'CICD_COMMIT' in env:
                pins.append(env['CICD_COMMIT'])
        self.assertTrue(any(p=='REVIEWED_CICD_COMMIT_REQUIRED' or re.fullmatch('[0-9a-f]{40}',p) for p in pins))
        for job in self.workflow['jobs'].values():
            reviewed=False
            for step in job['steps']:
                run=step.get('run','')
                if 'fetch --depth=1 origin "${CICD_COMMIT}"' in run:
                    self.assertIn('^[0-9a-f]{40}$',run)
                    self.assertIn('rev-parse HEAD)',run)
                    self.assertIn('== "${CICD_COMMIT}"',run)
                    reviewed=True
                if 'secrets.' in str(step.get('env',{})):
                    self.assertTrue(reviewed,step['name'])

    def test_evidence_retains_api_run_id_number_and_attempt_separately(self):
        text=self.path.read_text()
        self.assertIn('--run-id "${GITHUB_RUN_ID}"',text)
        self.assertNotIn('--run-id "${GITHUB_RUN_NUMBER}"',text)
        self.assertIn('--run-number "${GITHUB_RUN_NUMBER}" --run-attempt "${GITHUB_RUN_ATTEMPT}"',text)

    def test_status_writer_has_only_status_credential_and_no_build_scanner(self):
        found=0
        for job in self.workflow['jobs'].values():
            self.assertNotIn('secrets.',str(job.get('env',{})))
            for step in job['steps']:
                env=step.get('env',{})
                if 'TRAVIS_TAGGER' in env:
                    found+=1
                    self.assertEqual(set(env),{'TRAVIS_TAGGER'})
                    run=step['run']
                    self.assertIn('ci_evidence.py" publish',run)
                    self.assertNotRegex(run,r'trivy|docker|setup\.py|build-push|push-to-cicd-status')
                    self.assertNotIn('continue-on-error',step)
                    self.assertNotIn('||',run)
        self.assertEqual(found,1)

    def test_image_failure_prefix_is_prepared_and_published(self):
        if self.acc:return
        from test_workflow_policy import evaluate
        build=self.workflow['jobs']['build-runtime' if 'opflex' in self.path.name else 'build-and-publish']
        prepare=next(s for s in build['steps'] if s['name']=='Prepare immutable image evidence')
        publish=next(s for s in build['steps'] if s['name']=='Publish prepared image status')
        # Supply real hashFiles result through a zero-arg fixture function after extracting its actual call.
        expression=re.sub(r"hashFiles\('[^']+'\)","'metadata-present'",prepare['if'])
        self.assertTrue(evaluate(expression,{'_success':False}))
        expression=re.sub(r"hashFiles\('[^']+'\)","''",prepare['if'])
        self.assertFalse(evaluate(expression,{'_success':False}))
        context={'_success':False,'env':{'SKIP_CICD_STATUS':'false'},'steps':{'evidence':{'outputs':{'prepared':'true'}}}}
        self.assertTrue(evaluate(publish['if'],context))
        context['steps']['evidence']['outputs']['prepared']=''
        self.assertFalse(evaluate(publish['if'],context))
        self.assertNotIn('env',prepare)
        for step in build['steps']:
            if 'build-push-' in step.get('run',''):
                self.assertIn('SKIP_CICD_STATUS=true',step['run'])
                self.assertNotIn('TRAVIS_TAGGER',str(step))
        cleanup=next(i for i,s in enumerate(build['steps']) if s['name']=='Remove registry credentials')
        self.assertLess(cleanup,build['steps'].index(prepare))

    def test_acc_jobs_isolate_build_upload_status_and_require_production_policy(self):
        if not self.acc:return
        jobs=self.workflow['jobs']
        builder=jobs['build-and-publish']
        self.assertNotIn('secrets.',str(builder))
        self.assertNotIn('TRAVIS_BUILD_USER',str(builder))
        self.assertEqual(builder['env']['ACC_PUBLICATION_MODE'],'${{ vars.ACC_PUBLICATION_MODE }}')
        authorize=next(s for s in builder['steps'] if s['name']=='Verify production publication prerequisites')
        self.assertIn('release_policy.py" authorize',authorize['run'])
        self.assertIn('--lock ci/release-inputs.json',authorize['run'])
        self.assertIn('--public-key "${PUBLICKEYFILE}"',authorize['run'])
        self.assertIn('inspect-inputs',authorize['run'])
        upload=jobs['upload-package']
        self.assertEqual(upload['needs'],'build-and-publish')
        self.assertNotIn('setup.py',str(upload))
        secret_steps=[s for s in upload['steps'] if 'secrets.' in str(s.get('env',{}))]
        self.assertEqual(len(secret_steps),2)
        for step,index in zip(secret_steps,['testpypi','pypi']):
            self.assertEqual(set(step['env']),{'TWINE_USERNAME','TWINE_PASSWORD'})
            self.assertIn(f"== '{index}'",step['if'])
            self.assertIn('release_policy.py" upload',step['run'])
        self.assertIn('--authorization',secret_steps[1]['run'])
        self.assertEqual(set(jobs['publish-status']['needs']),{'build-and-publish','upload-package'})

    def test_pin_placeholder_and_wrong_checkout_fail_before_credentials(self):
        run=next(s['run'] for job in self.workflow['jobs'].values() for s in job['steps'] if 'run' in s and 'CICD_COMMIT must pin' in s['run'])
        start=run.index('cicd_dir=')
        script=run[start:]
        # Trim release checks after the exact-SHA verification; they are tested separately.
        script=script.split('cicd_release=',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            fake=Path(directory)/'git'
            fake.write_text('#!/bin/bash\nif [[ "$*" == *"rev-parse HEAD"* ]]; then echo "${OBSERVED_SHA}"; fi\n')
            fake.chmod(0o755)
            for requested,observed,expected in [('REVIEWED_CICD_COMMIT_REQUIRED','a'*40,False),('a'*40,'b'*40,False),('a'*40,'a'*40,True)]:
                result=subprocess.run(['bash','-Eeuo','pipefail','-c',script],env={**os.environ,'PATH':directory+os.pathsep+os.environ['PATH'],'RUNNER_TEMP':directory,'CICD_COMMIT':requested,'OBSERVED_SHA':observed,'GITHUB_ENV':directory+'/env','GITHUB_OUTPUT':directory+'/out'},capture_output=True,text=True)
                self.assertEqual(result.returncode==0,expected,result.stdout+result.stderr)

    def test_acc_package_builder_produces_versioned_bytes_before_upload(self):
        if not self.acc:return
        helper=ROOT/'.github/scripts/prepare-acc-package.py'
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory);provision=repo/'provision';(provision/'acc_provision').mkdir(parents=True)
            (provision/'acc_provision/__init__.py').write_text('')
            (provision/'setup.py').write_text("from setuptools import setup\nsetup(name='acc_provision',\n    version='6.1.1.8',\n    packages=['acc_provision'],package_data={'acc_provision':['versions.yaml']})\n")
            versions=provision/'acc_provision/versions.yaml';versions.write_text('versions:\n  active:\n    opflex_agent_version: 6.1.1.8.81c2369\n')
            route=repo/'route.json';route.write_text(json.dumps({'mode':'preview','legacy_adapter':False,'version':'6.1.1.8.dev55','index':'testpypi','development':True}))
            result=subprocess.run(['python3',str(helper),'--repo',str(repo),'--route',str(route),'--release-tag','6.1.1.8','--upstream-id','81c2369','--artifact-dir',str(repo/'artifacts'),'--output',str(repo/'built.json')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            built=json.loads((repo/'built.json').read_text())
            with tarfile.open(built['artifact']) as archive:
                pkginfo=archive.extractfile(next(p for p in archive.getnames() if p.endswith('/PKG-INFO'))).read().decode()
                pins=archive.extractfile(next(p for p in archive.getnames() if p.endswith('/versions.yaml'))).read().decode()
            self.assertIn('Version: 6.1.1.8.dev55',pkginfo)
            self.assertIn('6.1.1.8.81c2369.z',pins)

    def test_image_builds_select_prepared_evidence_with_fatal_scan_policy(self):
        if self.acc:
            return
        builders = [job for job in self.workflow['jobs'].values()
                    if any('${CICD_DIR}/travis/build-push-' in step.get('run', '') for step in job['steps'])]
        self.assertTrue(builders)
        for job in builders:
            self.assertEqual(job['env']['CI_EVIDENCE_MODE'], 'prepared-v1')
            self.assertEqual(job['env']['CI_SCAN_POLICY'], 'fatal')

    def test_status_publisher_scope_comes_from_trusted_caller_identity(self):
        job, publisher = next((job, step) for job in self.workflow['jobs'].values() for step in job['steps']
                              if 'TRAVIS_TAGGER' in step.get('env', {}))
        run = publisher['run']
        for option in ('release-tag', 'kind', 'stream', 'source-repository', 'source-sha', 'cicd-sha', 'run-id', 'run-attempt', 'images'):
            self.assertIn('--expected-' + option, run)
        self.assertIn('--expected-source-repository "${GITHUB_REPOSITORY}"', run)
        self.assertIn('--expected-source-sha "${TRAVIS_COMMIT}"', run)
        self.assertIn('--expected-cicd-sha "${CICD_COMMIT}"', run)
        self.assertIn('--expected-run-id "${GITHUB_RUN_ID}"', run)
        if self.acc:
            builder = self.workflow['jobs']['build-and-publish']
            self.assertEqual(builder['outputs']['source-sha'], '${{ steps.source.outputs.source_sha }}')
            source = next(step for step in builder['steps'] if step.get('id') == 'source')
            self.assertIn('source_sha=${tagged_commit}', source['run'])
            self.assertEqual(job['env']['TRAVIS_COMMIT'], '${{ needs.build-and-publish.outputs.source-sha }}')
            self.assertIn('--expected-kind package', run)
            self.assertIn("outputs.package-index == 'pypi'", job['env']['EXPECTED_STATUS_STREAM'])
            self.assertIn("|| ''", job['env']['EXPECTED_STATUS_IMAGES'])
        else:
            self.assertIn('--expected-kind images', run)
            self.assertIn('--expected-stream "${TRAVIS_TAG}.z"', run)
            images = re.search(r'--expected-images "([^"]+)"', run)[1].split(',')
            self.assertEqual(len(images), 1 if 'opflex' in self.path.name else 8)
            self.assertNotIn('$', ','.join(images))

    def test_prepared_scanner_does_not_execute_the_unverified_trivy_installer(self):
        if self.acc:
            return
        self.assertNotIn('https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh', self.path.read_text())

if __name__=='__main__':unittest.main()
