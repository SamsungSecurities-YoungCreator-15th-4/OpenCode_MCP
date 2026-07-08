"""pytest 부트스트랩.

이 파일이 레포 루트에 있으면 pytest가 루트를 sys.path에 올려, tests/ 아래
테스트가 `compliance` 패키지를 import할 수 있다.

이전에는 루트의 test_client.py가 수집되며 루트를 sys.path에 넣는 역할을 겸했는데,
그 수동 검증 스크립트를 scripts/check_client.py로 옮기면서(이슈 #4) 이 conftest가
그 역할을 대신한다. (별도 로직 없음 — 존재만으로 충분.)
"""
