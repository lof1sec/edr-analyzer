from app.models import GraphViewState


def test_saved_view_lifecycle(admin_client, db_session):
    client = admin_client
    missing = client.get('/api/graph/999999/view')
    assert missing.status_code == 404
    from app.models import Dataset

    dataset = Dataset(name='View test')
    db_session.add(dataset)
    db_session.commit()
    path = f'/api/graph/{dataset.id}/view'
    assert client.get(path).json() == {'view': None}
    view = {
        'rangeFrom': 10, 'rangeTo': 20, 'globalSearch': 'needle',
        'hiddenEventTypes': ['ProcessCreated'], 'hiddenUsers': ['alice'],
        'hiddenPids': ['42@host'], 'hiddenElements': ['edge_1'],
    }
    assert client.put(path, json=view).status_code == 200
    assert client.get(path).json()['view'] == view
    view['hiddenElements'] = ['edge_2']
    assert client.put(path, json=view).status_code == 200
    assert client.get(path).json()['view'] == view
    assert client.delete(path).status_code == 204
    assert client.get(path).json() == {'view': None}
    assert db_session.query(GraphViewState).count() == 0


def test_saved_view_rejects_invalid_input(admin_client, db_session):
    from app.models import Dataset

    dataset = Dataset(name='Validation test')
    db_session.add(dataset)
    db_session.commit()
    path = f'/api/graph/{dataset.id}/view'
    assert admin_client.put(path, json={'rangeFrom': 20, 'rangeTo': 10}).status_code == 422
    assert admin_client.put(path, json={'hiddenElements': ['']}).status_code == 422
    assert admin_client.put(path, json={'unexpected': 'field'}).status_code == 422
    assert admin_client.get(path).json() == {'view': None}
