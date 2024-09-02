프로젝트 로직 설명

1. 회원가입 (User Registration)

	•	클라이언트 요청: 사용자가 /join 엔드포인트로 HTTP POST 요청을 보내어 회원가입을 시도합니다. 요청 본문에는 사용자 이름과 비밀번호가 포함된 JoinDTO 객체가 전달됩니다.
	•	컨트롤러: JoinController 클래스의 joinProcess 메서드가 호출됩니다. 이 메서드는 JoinDTO 객체를 파라미터로 받아, 로그를 남기고, JoinService의 joinService 메서드를 호출합니다.
	•	서비스: JoinService의 joinService 메서드는 다음과 같은 작업을 수행합니다:
	•	사용자 이름이 데이터베이스에 존재하는지 확인합니다.
	•	사용자 이름이 존재하지 않으면, 비밀번호를 암호화한 후 UserEntity 객체를 생성합니다.
	•	이 객체를 데이터베이스에 저장합니다.

2. 로그인 및 JWT 발급 (Login and JWT Generation)

	•	클라이언트 요청: 사용자가 로그인 시도 시, /login 엔드포인트로 HTTP POST 요청을 보냅니다. 요청 본문에는 사용자 이름과 비밀번호가 포함됩니다.
	•	필터: LoginFilter 클래스의 attemptAuthentication 메서드는 사용자 이름과 비밀번호를 추출하고, AuthenticationManager를 사용하여 인증을 시도합니다.
	•	인증 성공: 인증이 성공하면 successfulAuthentication 메서드가 호출됩니다. 이 메서드는 JWT 토큰을 생성하고, 응답 헤더에 Authorization 필드로 추가합니다.
	•	JWT Util: JWTUtil 클래스는 JWT 토큰을 생성하고, 유효성 검사 및 정보 추출을 담당합니다.

3. 요청 인증 (Request Authentication)

	•	클라이언트 요청: 인증이 필요한 엔드포인트로 요청이 들어옵니다. 요청 헤더에 Authorization 필드에 Bearer <token> 형식으로 JWT 토큰이 포함되어 있어야 합니다.
	•	필터: JWTFilter 클래스가 요청을 가로채고, JWT 토큰을 검증합니다.
	•	토큰이 유효하지 않거나 만료되었으면 요청을 거부합니다.
	•	유효한 토큰이면, 토큰에서 사용자 이름과 역할을 추출하고, 이를 기반으로 CustomUserDetails 객체를 생성합니다.
	•	UsernamePasswordAuthenticationToken을 생성하여 SecurityContextHolder에 설정합니다.

4. 관리자 엔드포인트 (Admin Endpoint)

	•	클라이언트 요청: 인증된 사용자가 /admin 엔드포인트로 HTTP GET 요청을 보냅니다.
	•	컨트롤러: AdminController 클래스의 adminP 메서드가 호출됩니다. 이 메서드는 현재 인증된 사용자의 정보를 SecurityContextHolder를 통해 조회합니다.
	•	사용자의 이름과 역할을 로그로 남깁니다.
	•	"admin Controller" 문자열을 반환합니다.
