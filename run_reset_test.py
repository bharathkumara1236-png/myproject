from app import app
from modules.auth import create_user, create_otp

# create a test user
create_user('testuser','TestPass123','testuser@example.com','+10000000000')

with app.test_client() as c:
    # set reset session
    with c.session_transaction() as sess:
        sess['reset_identifier'] = 'testuser@example.com'
        sess['reset_method'] = 'email'

    # create OTP and verify via endpoint
    code = create_otp('testuser@example.com', method='email')

    resp = c.post('/reset/verify', data={'otp': code, 'password': 'NewPass123', 'confirm': 'NewPass123'})
    print('Status:', resp.status_code)
    print(resp.data.decode('utf-8')[:800])
