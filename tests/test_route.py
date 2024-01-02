def test_home(client):
    response = client.get("/")
    assert response.status_code==200 and b"<title>Home Page</title>" in response.data
def test_listfiles(client):
    response = client.get("/listfiles/1")
    assert response.status_code==200
def test_files(client):
    response = client.get("/files/123")
    assert response.status_code==302 and b"error=No file at the url" in response.data