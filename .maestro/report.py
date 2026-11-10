"""Builds report.html from a Maestro run, and the flow table on the GitHub run page.

    python .maestro/report.py maestro-output

Reads <output>/report.xml (--format junit) and <output>/debug/<flow>/ (--debug-output with
--flatten-debug-output). report.html links to the recordings and screenshots next to it, so open
it from the unzipped maestro-results download.

A flow is also marked failed if the app crashed or froze (ANR) during it, by its phone log; the
script then exits with an error.
"""
import html
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

out = Path(sys.argv[1])
report = out / 'report.xml'
APP_ID = 'io.ooru.credissuerwallet'

STEP_TEXT = {
    'launchAppCommand': lambda c: 'Open the app' + (' (fresh install)' if c.get('clearState') else ''),
    'stopAppCommand': lambda c: 'Close the app',
    'tapOnElement': lambda c: f'Tap "{c["selector"].get("textRegex", "")}"',
    'inputTextCommand': lambda c: f'Type "{c["text"]}"',
    'assertConditionCommand': lambda c: (
        f'See "{c["condition"]["visible"].get("textRegex", "")}"' if c['condition'].get('visible')
        else f'Don\'t see "{c["condition"]["notVisible"].get("textRegex", "")}"'),
    'scrollUntilVisible': lambda c: f'Scroll to "{c["selector"].get("textRegex", "")}"',
    'takeScreenshotCommand': lambda c: f'Screenshot {c["path"]}',
    'startRecordingCommand': lambda c: 'Start recording',
    'stopRecordingCommand': lambda c: 'Stop recording',
}


def steps(flow_dir):
    path = flow_dir / 'commands.json'
    if not path.exists():
        return []
    result = []
    for entry in json.loads(path.read_text(encoding='utf8')):
        name, args = next(((k, v) for k, v in entry['command'].items() if v is not None), (None, None))
        if name in STEP_TEXT:
            try:
                text = STEP_TEXT[name](args)
            except (KeyError, TypeError, AttributeError):
                text = name
            result.append((text, entry.get('metadata', {}).get('status', '')))
    return result


def app_problem(flow_dir):
    """The first crash or ANR of the app in the flow's phone log, or ''."""
    path = flow_dir / 'logs' / 'device-logcat.txt'
    if not path.exists():
        return ''
    lines = path.read_text(encoding='utf8', errors='replace').splitlines()
    for i, line in enumerate(lines):
        if f'ANR in {APP_ID}' in line:
            return 'App not responding (ANR)'
        if 'FATAL EXCEPTION' in line and any(f'Process: {APP_ID},' in l for l in lines[i + 1:i + 3]):
            cause = lines[i + 2].split('AndroidRuntime:', 1)[-1].strip() if i + 2 < len(lines) else ''
            return 'App crashed' + (f': {cause}' if cause else '')
    return ''


def link(path):
    return quote(path.relative_to(out).as_posix())


flows = []
if report.exists():
    for case in ET.parse(report).getroot().iter('testcase'):
        failure = case.find('failure')
        message = ''
        if failure is not None:
            lines = (failure.get('message') or failure.text or 'failed').strip().splitlines()
            message = lines[0] if lines else 'failed'
        flow_dir = out / 'debug' / case.get('name')
        problem = app_problem(flow_dir)
        if problem:
            message = problem + (f' ({message})' if message else '')
        flows.append({
            'name': case.get('name'),
            'passed': failure is None and not problem,
            'crashed': bool(problem),
            'message': message,
            'time': float(case.get('time', 0)),
            'videos': sorted(flow_dir.glob('startRecording/*.mp4')),
            # Ours first, in order, then the ones Maestro takes when a step fails.
            'images': sorted(flow_dir.glob('takeScreenshot/*.png')) + sorted(flow_dir.glob('screenshots/*.png')),
            'steps': steps(flow_dir),
        })

passed = sum(f['passed'] for f in flows)
title = f'UI tests: {passed} of {len(flows)} flows passed' if flows else 'UI tests did not run'

summary = os.environ.get('GITHUB_STEP_SUMMARY')
if summary:
    lines = [f'### {title}', '']
    if flows:
        lines += ['| Flow | Result | Time |', '|---|---|---|']
        lines += [f'| {f["name"]} | {"✅ passed" if f["passed"] else "❌ " + f["message"]} | {f["time"]:.0f} s |'
                  for f in flows]
        lines += ['', 'The report with each flow\'s recording and screenshots: `report.html` in the '
                      '**maestro-results** download below.']
    with open(summary, 'a', encoding='utf8') as f:
        f.write('\n'.join(lines) + '\n')

e = html.escape
parts = [f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{e(title)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; color: #1b1b1f; }}
table {{ border-collapse: collapse; margin-bottom: 32px; }}
td, th {{ border: 1px solid #ccc; padding: 6px 12px; text-align: left; }}
.pass {{ color: #137333; }} .fail {{ color: #c5221f; }}
section {{ border-top: 1px solid #ddd; padding-top: 16px; margin-top: 24px; }}
.media {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-start; }}
.media figure {{ margin: 0; }} .media figcaption {{ font-size: 13px; color: #555; }}
video, .media img {{ height: 480px; border: 1px solid #ccc; border-radius: 8px; }}
li.FAILED {{ color: #c5221f; font-weight: bold; }} li.SKIPPED {{ color: #888; }}
</style></head><body>
<h1>{e(title)}</h1>
<table><tr><th>Flow</th><th>Result</th><th>Time</th></tr>''']
for i, f in enumerate(flows):
    result = '<span class="pass">✅ passed</span>' if f['passed'] else f'<span class="fail">❌ {e(f["message"])}</span>'
    parts.append(f'<tr><td><a href="#flow{i}">{e(f["name"])}</a></td><td>{result}</td><td>{f["time"]:.0f} s</td></tr>')
parts.append('</table>')
for i, f in enumerate(flows):
    parts.append(f'<section id="flow{i}"><h2>{"✅" if f["passed"] else "❌"} {e(f["name"])}</h2>')
    if not f['passed']:
        parts.append(f'<p class="fail">{e(f["message"])}</p>')
    parts.append('<div class="media">')
    for video in f['videos']:
        parts.append(f'<figure><video controls preload="metadata" src="{link(video)}"></video>'
                     f'<figcaption>Recording</figcaption></figure>')
    for image in f['images']:
        parts.append(f'<figure><a href="{link(image)}"><img src="{link(image)}" alt=""></a>'
                     f'<figcaption>{e(image.stem)}</figcaption></figure>')
    parts.append('</div>')
    if f['steps']:
        parts.append(f'<details><summary>Steps ({len(f["steps"])})</summary><ol>')
        parts += [f'<li class="{e(status)}">{e(text)}</li>' for text, status in f['steps']]
        parts.append('</ol></details>')
    parts.append('</section>')
parts.append('</body></html>')
out.mkdir(parents=True, exist_ok=True)
(out / 'report.html').write_text('\n'.join(parts), encoding='utf8')
print(title)
crashed = [f['name'] for f in flows if f['crashed']]
if crashed:
    sys.exit('The app crashed or froze in: ' + ', '.join(crashed))
