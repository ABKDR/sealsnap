import argparse
import json
from pathlib import Path
from .network import SnapshotError


def main():
    parser = argparse.ArgumentParser(description='Пассивный веб-снимок и проверка пакета. Windows + Edge.')
    sub = parser.add_subparsers(dest='command', required=True)
    cap = sub.add_parser('capture')
    cap.add_argument('url')
    cap.add_argument('--output', default=str(Path(__file__).resolve().parent.parent / 'captures'))
    ver = sub.add_parser('verify')
    ver.add_argument('directory')
    ver.add_argument('--expected-sha256')
    sub.add_parser('gui')
    args = parser.parse_args()
    try:
        if args.command == 'gui':
            from .gui import main as gui
            gui()
            return 0
        if args.command == 'capture':
            from .process import run_capture
            result = run_capture(args.url, args.output)
        else:
            from .bundle import verify
            result = verify(args.directory, args.expected_sha256)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (SnapshotError, OSError) as e:
        print(json.dumps({'ok': False, 'error': str(e)}, ensure_ascii=False))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
