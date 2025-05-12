from django.contrib.auth import get_user_model
from chat.models import User


def store_public_key(username: str, public_key: str) -> bool:
    # this will store the public key that is generated from at the start
    try:
        user = User.objects.get(username=username)
        user.public_key = public_key
        user.save()
        return True
    except User.DoesNotExist:
        return False
def get_public_key(username: str) -> str:
    # just gets the public key of the other user from the database, no need to exchange through the net
    try:
        user = User.objects.get(username=username)
        return user.public_key
    except User.DoesNotExist:
        return None
def has_public_key(username: str) -> bool:
    # checks if a user has a public key
    try:
        user = User.objects.get(username=username)
        return bool(user.public_key)
    except User.DoesNotExist:
        return False
