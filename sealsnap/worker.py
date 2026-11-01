import json
import sys


def main():
    # No capture import or subprocess before the parent attaches the Job and closes stdin.
    raw = sys.stdin.buffer.read(16385)
    try:
        if len(raw) > 16384:
            raise ValueError()
        job = json.loads(raw)
        if type(job) is not dict or set(job) != {'url', 'output'}:
            raise ValueError()
        from .capture import capture
        result = capture(job['url'], job['output'])
        code = 0
    except Exception as e:
        from .network import SnapshotError
        result = {'ok': False, 'error': str(e) if isinstance(e, SnapshotError) else type(e).__name__}
        code = 2
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False).encode('utf-8'))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
