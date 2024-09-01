import datetime
from rest_framework import exceptions
from jwt import JWT
from jwt.jwk import OctetJWK

jwt_instance = JWT()

# Create key objects
access_key = OctetJWK(key=b'access_secret', kid='access-key')
refresh_key = OctetJWK(key=b'refresh_secret', kid='refresh-key')

def create_access_token(id):
    return jwt_instance.encode({
        'user_id': id,
        'exp': int((datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).timestamp()),  # timestamp w sekundach
        'iat': int(datetime.datetime.utcnow().timestamp())  # timestamp w sekundach
    }, access_key, alg='HS256')

def decode_access_token(token):
    try:
        payload = jwt_instance.decode(token, access_key, do_verify=True)
        if payload is None:
            raise exceptions.AuthenticationFailed('Invalid token')
        return payload['user_id']
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise exceptions.AuthenticationFailed('Unauthenticated')

def create_refresh_token(id):
    return jwt_instance.encode({
        'user_id': id,
        'exp': int((datetime.datetime.utcnow() + datetime.timedelta(days=7)).timestamp()),  # timestamp w sekundach
        'iat': int(datetime.datetime.utcnow().timestamp())  # timestamp w sekundach
    }, refresh_key, alg='HS256')

def decode_refresh_token(token):
    try:
        payload = jwt_instance.decode(token, refresh_key, do_verify=True)
        if payload is None:
            raise exceptions.AuthenticationFailed('Invalid token')
        return payload['user_id']
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise exceptions.AuthenticationFailed('Unauthenticated')