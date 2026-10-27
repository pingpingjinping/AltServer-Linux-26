# AltServer / Anisette 상태와 SideStore 조사 — 2026-10-25 KST

## 유지할 운영 상태

- 사용자 확인: 수정한 AltServer와 fresh-header Anisette 브리지가 systemd에서 active + enabled.
- 영구 서비스: `altserver.service`, `anisette-keeper-v3.service`.
- 영구 실행 파일/브리지/격리된 상태: `/opt/altserver-keeper-v3/`.
- AltServer의 Anisette 주소: loopback 16971. netmuxd 주소: loopback 27015.
- 브리지는 격리된 Anisette 상태로 `https://ani3.stikstore.app/v3/get_headers`를 요청한다.
- 기존 Keeper 보험은 별도로 보존. 자동 갱신은 끈 채 수동 갱신만 사용한다.
- 불필요해진 `anisette-keeper-auth-trial`, `anisette-keeper-v3-backend` 컨테이너는 중지했으며 삭제하지 않았다.
- 실제 재부팅 후 검증은 아직 하지 않았다. enabled 확인과 재부팅 검증은 다르다.
- 대시보드 PR 27은 2026-10-24 12:54:03 UTC 머지 확인. 사용자는 적용 완료라고 답했다. API/UI 결과를 별도로 재수집하지는 않았다.
- 대시보드 Actions 미실행 원인은 계정 결제/지출 한도 안내였다. 코드 테스트 실패로 판정하지 않는다.
- 지속성 설치 시점 코드: `8b1f900da7e3761fda3bbc21145c7c33a538abe5`.

## 현재 실험과 롤백

- 현재 상태를 유지하고, 10월 29~30일에 기존 Keeper만으로 갱신한 뒤 새 만료일을 확인한다.
- 11월 1일에는 기존 10월 31일 만료 시점을 지난 앱이 실행되는지 확인한다.
- 실험 중 AltStore로 추가 갱신하면 Keeper만의 효과와 구분할 수 없다.
- 기존 Keeper의 프로필 발급/설치와 만료 이후 실행 보장은 구분한다. 후자는 아직 확인 전이다.
- `keeper-v3-persist.py rollback`은 **영구 설치를 되돌리는 명령**이다. 설치한 부팅 세션에서는 이전 임시 시험 구성을 복구하고, 재부팅 후에는 원래 기본 서비스 설정/활성화 상태를 복구한다. 무조건 실험 이전 원본 바이너리로 돌아가는 명령은 아니다.
- 이번 조사는 소스와 공개 이슈를 읽고 기록하는 작업이며 Pi 서비스, 계정, 프로필, Keeper 상태를 바꾸지 않았다.

## 실제 로그로 확인한 사항

1. 실제 AltStore 갱신 성공과 HTTP 503 실패가 번갈아 발생했다. 성공 후 프로필 생성/만료일과 앱 실행을 확인했다.
2. 실패 로그: Anisette 수신 후 인증 HTTP 200 → 200 → 503. 성공 로그: 대응하는 세 요청이 200 → 200 → 200, 이후 계정 인증 및 프로필 갱신 완료.
3. 세 번째 요청을 `apptokens`로 보는 것은 소스 순서와 로그를 대조한 **추론**이다. 요청 본문의 작업 이름을 직접 기록한 것은 아니다.
4. 성공과 실패 모두 초기 Anisette 수신은 한 번이었다. 실패 시에만 데이터 재요청이 빠졌다는 증거는 없다.
5. 비교한 인증 연결은 모두 새 연결/TLS 1.3이었다. 이 두 기록의 실패를 오래된 연결 재사용 또는 TLS handshake 실패로 설명할 근거는 없다.
6. 과거 ProxyPin CONNECT/-2/인증서 오류는 별도 관측이다. 이후 네이티브 로그의 실제 HTTP 503과 섞지 않는다. 사용자는 이미 캡처 중지와 인증서 설정을 확인했다.
7. Keeper RPC 20초 캐시는 실제 확인했으나, 이를 우회한 fresh 모드에서도 503이 남았다.
8. 제공자에 Python 기본 User-Agent로 요청하면 403, 제공자 UA로 요청하면 200이었다. 이 문제는 수정됐다. 해당 403/local 502는 Apple 인증 503과 별개다.
9. 브리지의 validated/HTTP 200은 형식 검증과 데이터 공급 성공일 뿐, Apple 인증 성공을 뜻하지 않는다.
10. 일정한 대기 간격으로 항상 성공한다는 결과는 없다. Apple 전체 장애나 계정 제한을 확정하지 않는다.

## SideStore에서 확인한 코드와 공개 수정

조사 기준: SideStore develop `d97ec133719d79916675bdaf722b82a8d091d545`, 그 하위 SideSign `752d1ef602aa792a432ffa1e71646dc1ecf7363c`.

### 현재 코드

- SideSign `Authentication.swift`는 전달받은 같은 `anisetteData`와 `clientDictionary`로 init, complete, apptokens를 처리한다. apptokens 직전 새 Anisette를 받는 경로가 해당 함수에는 없다.
- `AnisetteDataManager.swift`는 원격 서버 URL/식별자가 같으면 캐시를 재사용한다. `Constants.Anisette.remoteCacheDuration`은 30초다.
- 따라서 “OTP/Anisette를 요청마다 새로 받아야 하므로 현재 AltStore가 틀렸다”는 결론을 SideStore 코드에서 얻을 수 없다.
- GrandSlam의 Client-Info는 Anisette 데이터에서, User-Agent는 별도 GrandSlam 설정에서 온다. 브리지 제공자 UA와 폰이 Apple로 보내는 UA는 같은 설정이 아니다.
- 현재 sendAuthenticationRequest에는 일반 HTTP 429/503 backoff 재시도가 없다. Connection: close는 이미 존재한다.

소스:
- [인증 흐름](https://github.com/SideStore/SideSign/blob/752d1ef602aa792a432ffa1e71646dc1ecf7363c/Sources/DeveloperPortal/Authentication.swift#L280)
- [원격 캐시](https://github.com/SideStore/SideSign/blob/752d1ef602aa792a432ffa1e71646dc1ecf7363c/Sources/Anisette/AnisetteDataManager.swift#L414)
- [30초 설정](https://github.com/SideStore/SideSign/blob/752d1ef602aa792a432ffa1e71646dc1ecf7363c/Sources/Constants.swift#L159)

### 수정안의 상태를 구분

- [SideStore 0.7.0-alpha](https://github.com/SideStore/SideStore/releases/tag/0.7.0-alpha): 릴리스 설명에 기존 503 로그인 문제를 다루는 임시 버전이라고 명시. 이것이 모든 현재 503을 해결한다는 뜻은 아니다.
- [SideSign #5](https://github.com/SideStore/SideSign/pull/5): 2026-10-13 머지. `au` 없이 오는 409 2FA 응답 처리. 작성자가 별도로 Android client-info와 ADI 구현 관련 경험을 보고했으나, ADI 지문 판별을 이번 환경에서 입증한 것은 아니다.
- [SideStore #1683](https://github.com/SideStore/SideStore/pull/1683), [SideSign #8](https://github.com/SideStore/SideSign/pull/8): 조사 시점 **open, 미머지**. Windows 계열 client-info/akd UA, Windows ADI 서버, 429/503 재시도, 2FA 처리를 함께 바꾸는 제안이다. 공식 해결 완료로 취급하지 않는다.
- #8 실제 diff: 429 또는 503이면 같은 요청을 2초/5초 뒤 최대 두 번 추가 전송한다. Anisette를 다시 받거나 SRP 전체를 새로 시작하는 재시도는 아니다.
- #8의 ephemeral URLSession이 연결 재사용을 완전히 막는다고 단정하지 않는다. 게다가 우리 비교 로그는 이미 새 연결이다.
- [SideStore #1618](https://github.com/SideStore/SideStore/pull/1618): 오래된 Xcode Client-Info override 제거 제안. 조사 시점 closed, 미머지. 현재 우리 브리지 응답은 akd이므로 그대로 적용할 해결책으로 보지 않는다.
- [SideStore #1647](https://github.com/SideStore/SideStore/issues/1647), [#1558](https://github.com/SideStore/SideStore/issues/1558): 관련 로그인 실패 보고. -80045, 2FA 문제, 초기 503, apptokens 503을 동일 원인이라고 합치지 않는다.

## 다음 조사 우선순위

| 우선순위 | 후보 | Pi만으로 가능한 범위 | 판단 기준 |
| --- | --- | --- | --- |
| 1 | 실제 Anisette 생성 방식과 Client-Info 조합 | 별도 격리 상태/시험 브리지에서 비교 가능. 기존 Keeper와 현재 영구 상태는 보존 | Client-Info만 바꾸는 실험과 실제 제공자/ADI 구현을 바꾸는 실험을 분리. 연속 성공/실패 횟수와 시각으로 비교 |
| 2 | 세 번째 인증 요청의 데이터/헤더와 제한적 재시도 | 폰 AltStore가 Apple에 직접 요청하므로 Pi의 C++ 인증 코드만 바꿔서는 폰 요청이 바뀌지 않음 | 가능하면 인증 단계명·HTTP 코드·소요시간만 계측. 본문/계정/토큰/OTP는 기록하지 않음 |
| 3 | apptokens 전 데이터 갱신이라는 Keeper와의 차이 | Keeper Rust는 get_app_token에서 데이터 생성기를 호출. 폰 경로 변경에는 앱 쪽 작업 필요 | 생성기 호출이 항상 다른 OTP를 뜻하지 않으며, SideSign도 같은 데이터를 재사용하므로 아직 가설 |
| 4 | 409 2FA 처리 | 주로 폰 인증 라이브러리 변경 | 현재 재갱신 실패의 직접 증거가 없어 낮은 우선순위 |

### Pi에 추가할 수 있는 진단

- 브리지 요청마다 순번, 공급자 응답 소요시간, 직전 OTP와 동일한지(boolean)만 기록하면 폰 시도와 대조하기 쉽다.
- OTP 자체, 지속 가능한 OTP 해시, machine ID, adi.pb, Apple ID/암호/세션 토큰은 저장하지 않는다.
- fresh 모드의 Client-Time은 브리지가 현재 UTC로 생성한다. 따라서 이 시간이 새롭다는 사실만으로 공급자 OTP의 실제 생성 시각/신선도를 증명할 수 없다.
- 원격 제공자 자체의 캐싱은 여전히 가능하다. 동일 OTP 관측만으로 그것이 인증 실패 원인이라고 결론 내리지 않는다.
- 이번에는 진단 코드도 적용하지 않았다. 현재 Keeper 단독 만료 실험을 보존한다.

## 재개할 때의 결론

SideStore에서 더 조사할 단서는 찾았다. 가장 유용한 것은 인증 신원/생성 방식 조합과 클라이언트의 apptokens 처리다. 단순 대기 시간, netmuxd 재시작, 로컬 HTTP 200만으로는 원인이 좁혀지지 않는다. 현재 동작하는 구성은 유지하고, 이후 실험을 한다면 별도 상태에서 변수 하나씩 비교한다.
