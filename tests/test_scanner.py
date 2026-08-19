"""Self-test for EnvGuard scanner. Run: python -m pytest test_scanner.py or python test_scanner.py"""

from envguard.scanner import scan_text, shannon_entropy


def test_aws_key_detected():
    key = "AKIA" + "IOSFODNN" + "7EXAMPLE"  # 16 chars after AKIA
    text = f'AWS_KEY = "{key}"'
    findings = scan_text(text, "test.py")
    assert any(f.pattern_id == "aws-access-token" for f in findings)


def test_github_pat_detected():
    token = "ghp_" + "aB3dE5fG7hI9jK1lMnOpQrStUvWxYz012345"  # 36 mixed chars
    text = f'GITHUB_TOKEN = "{token}"'
    findings = scan_text(text, ".env")
    assert any(f.pattern_id == "github-pat" for f in findings)


def test_openai_key_detected():
    # Construct at runtime to avoid triggering GitHub push protection
    key = "sk-" + "aB3dE5fG7hI9jK1lMnOp" + "T3BlbkFJ" + "QrStUvWxYz0123456789"
    text = f'OPENAI_KEY = "{key}"'
    findings = scan_text(text, "config.py")
    assert any(f.pattern_id == "openai-api-key" for f in findings), \
        f"Expected openai-api-key, got: {[f.pattern_id for f in findings]}"


def test_private_key_detected():
    # Real PEM blocks span multiple lines — scan_text does a full-text scan for private-key
    text = "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 100 + "\n-----END RSA PRIVATE KEY-----"
    findings = scan_text(text, "id_rsa")
    assert any(f.pattern_id == "private-key" for f in findings), \
        f"Expected private-key, got: {[f.pattern_id for f in findings]}"


def test_jwt_detected():
    # Construct a fake JWT at runtime to avoid push protection
    import base64, json
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234567890", "name": "Test User"}).encode()).rstrip(b"=").decode()
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    token = f"{header}.{payload}.{sig}"
    text = f'token = "{token}"'
    findings = scan_text(text, "auth.py")
    assert any(f.pattern_id == "jwt" for f in findings)


def test_no_false_positive_on_plain_text():
    text = "This is a normal line of code without any secrets."
    findings = scan_text(text, "readme.md")
    assert len(findings) == 0


def test_entropy_calculation():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0
    assert shannon_entropy("abcd") == 2.0


def test_entropy_filters_low_entropy_matches():
    # Generic text that won't match any pattern = no findings
    text = "password = hello"
    findings = scan_text(text, "config.py")
    # "hello" won't match any specific pattern, so this should be clean
    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_aws_key_detected,
        test_github_pat_detected,
        test_openai_key_detected,
        test_private_key_detected,
        test_jwt_detected,
        test_no_false_positive_on_plain_text,
        test_entropy_calculation,
        test_entropy_filters_low_entropy_matches,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__} — {e}")
    print(f"\n{passed}/{len(tests)} passed")
    exit(0 if passed == len(tests) else 1)
