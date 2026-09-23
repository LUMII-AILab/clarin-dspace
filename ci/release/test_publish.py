import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import backend_image as m
ROOT=Path(__file__).resolve().parents[2]

class PublishTests(unittest.TestCase):
    def test_publication_copies_once_and_refuses_moved_tag_or_denied_registry(self):
        # Exercise the real publisher shell; replace external processes, never a live registry.
        harness = r"""
python3() { printf 'inspect\n' >> "$TRACE"; }
docker() {
  case " $* " in
    *" login "*) cat >/dev/null ;;
    *" list-tags "*)
      if [ "$CASE" = denied ]; then return 1; fi
      if [ "$CASE" = malformed ]; then printf bad-json; return 0; fi
      if [[ "$CASE" = absent* ]]; then echo "name unknown" >&2; return 1; fi
      if [ "$CASE" = new ]; then printf '{"Tags":[]}';
      else printf '{"Tags":["%s"]}' "$TAG"; fi ;;
    *" inspect "*)
      if [ "$CASE" = moved ]; then printf other; else printf index; fi ;;
    *" copy "*) printf 'copy\n' >> "$TRACE" ;;
  esac
}
export -f python3 docker
bash "$PUBLISHER"
"""
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'output/evidence').mkdir(parents=True)
            (root/'output/evidence/inputs.json').write_text(json.dumps(m.toolchain()))
            # output was created above
            for case, code, copies in [('new',0,1),('same',0,0),('moved',1,0),('denied',1,0),('malformed',None,0),('absent',1,0),('absent-bootstrap',0,1)]:
                trace=root/'trace';trace.write_text('')
                env=dict(os.environ,CASE=case,TRACE=str(trace),PUBLISHER=str(ROOT/'ci/release/publish.sh'),
                         GHCR_TOKEN='private-test-sentinel',GHCR_USER='fixture',
                         ALLOW_NEW_PACKAGE='true' if case == 'absent-bootstrap' else 'false',
                         EXPECTED_DIGEST='sha256:'+hashlib.sha256(b'index').hexdigest(),
                         IMAGE=m.toolchain()['image'],TAG='sha-'+'a'*40)
                result=subprocess.run(['bash','-c',harness],cwd=root,env=env,capture_output=True,text=True)
                if code is None:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertEqual(result.returncode,code,result.stderr)
                self.assertEqual(trace.read_text().splitlines().count('copy'),copies)
                self.assertIn('inspect',trace.read_text())
                self.assertNotIn('private-test-sentinel',result.stdout+result.stderr+trace.read_text())

    def test_partial_report_upload_resumes_draft_without_overwriting_assets(self):
        import publish_report
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'release.json').write_text('{"verified":true}')
            (root/'https.json').write_text('{"passed":true}')
            record=dict(repository='owner/app',version='sha-'+'a'*40,source='a'*40)
            state={'draft':True, 'assets':{'release.json':(root/'release.json').read_bytes()}}
            calls=[]
            def gh(*args):
                calls.append(args)
                if args[0]=='api' and '/git/matching-refs/' in args[1]: return '[]'
                if args[:2]==('api','--paginate'): return record['version']+'\t1'
                if args==('api','repos/owner/app/releases/1'):
                    return json.dumps(dict(tag_name=record['version'],target_commitish=record['source'],
                                          draft=state['draft'],assets=[{'name':name} for name in state['assets']]))
                if args[:2]==('release','upload'):
                    p=Path(args[-1]); self.assertNotIn(p.name,state['assets']);state['assets'][p.name]=p.read_bytes()
                elif args[:2]==('release','download'):
                    name=args[args.index('--pattern')+1]
                    (Path(args[-1])/name).write_bytes(state['assets'][name])
                elif args[:2]==('release','edit'): state['draft']=False
                elif args[0]=='api' and '/commits/' in args[1]: return json.dumps({'sha':record['source']})
                return ''
            with patch.object(publish_report,'command',side_effect=gh):
                publish_report.publish(record,root)
                self.assertFalse(state['draft'])
                self.assertEqual(len([c for c in calls if c[:2]==('release','upload')]),1)
                calls.clear()
                publish_report.publish(record,root)
                self.assertFalse(any(c[:2]==('release','upload') for c in calls))
                state['assets']['release.json']=b'changed'
                with self.assertRaises(ValueError): publish_report.publish(record,root)

    def test_new_draft_uses_creation_response_when_release_list_is_stale(self):
        import publish_report
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'release.json').write_text('{"verified":true}')
            record=dict(repository='owner/app',version='sha-'+'a'*40,source='a'*40)
            calls=[]
            def gh(*args):
                calls.append(args)
                if args[0]=='api' and '/git/matching-refs/' in args[1]: return '[]'
                if args[:2]==('api','--paginate'): return ''  # Listing remains stale.
                if args[:3]==('api','--method','POST'):
                    self.assertIn('draft=true',args)
                    return json.dumps(dict(id=1,tag_name=record['version'],
                                           target_commitish=record['source'],draft=True,assets=[]))
                if args[:2]==('release','download'):
                    (Path(args[-1])/'release.json').write_bytes((root/'release.json').read_bytes())
                if args[0]=='api' and '/commits/' in args[1]:
                    return json.dumps({'sha':record['source']})
                return ''
            with patch.object(publish_report,'command',side_effect=gh):
                publish_report.publish(record,root)
            self.assertEqual(sum(c[:2]==('api','--paginate') for c in calls),1)
            self.assertTrue(any(c[:2]==('release','upload') for c in calls))
            self.assertTrue(any(c[:2]==('release','edit') for c in calls))


    def test_existing_wrong_git_tag_stops_before_release_writes(self):
        import publish_report
        calls=[]
        def gh(*args):
            calls.append(args)
            if '/git/matching-refs/' in args[1]:
                return json.dumps([{'ref':'refs/tags/sha-'+'a'*40}])
            return json.dumps({'sha':'b'*40})
        with patch.object(publish_report, 'command', side_effect=gh):
            with self.assertRaises(ValueError):
                publish_report.publish(dict(repository='owner/app', version='sha-'+'a'*40, source='a'*40))
        self.assertEqual(len(calls),2)
        self.assertTrue(all(c[0]=='api' and '--method' not in c for c in calls))
