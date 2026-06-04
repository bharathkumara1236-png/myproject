from app import app

with app.test_client() as c:
    with c.session_transaction() as sess:
        sess['user'] = 'tester'
    resp = c.post('/webscan', data={'url': 'example.com'})
    print('Status:', resp.status_code)
    data = resp.data.decode('utf-8')
    found = 'Results:' in data or 'Open Ports' in data
    print('Contains results section:', found)
    # print only the web results portion
    start = data.find('<h4>Results:')
    if start != -1:
        print(data[start:start+800])
    else:
        print('Results section not found in rendered HTML')
