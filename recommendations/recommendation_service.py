# Microservice-1: recommendations
from concurrent import futures
import random
import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode
import grpc

from recommendations_pb2 import (
    BookCategory,
    BookRecommendation,
    RecommendationResponse,
)
import recommendations_pb2_grpc

_USERPOOL_ID = '<_USERPOOL_ID>'
_APP_CLIENT_ID = '<_APP_CLIENT_ID>'

books_by_category = {
    BookCategory.MYSTERY: [
        BookRecommendation(id=1, title="The Maltese Falcon"),
        BookRecommendation(id=2, title="Murder on the Orient Express"),
        BookRecommendation(id=3, title="The Hound of the Baskervilles"),
    ],
    BookCategory.SCIENCE_FICTION: [
        BookRecommendation(
            id=4, title="The Hitchhiker's Guide to the Galaxy"
        ),
        BookRecommendation(id=5, title="Ender's Game"),
        BookRecommendation(id=6, title="The Dune Chronicles"),
    ],
    BookCategory.SELF_HELP: [
        BookRecommendation(
            id=7, title="The 7 Habits of Highly Effective People"
        ),
        BookRecommendation(
            id=8, title="How to Win Friends and Influence People"
        ),
        BookRecommendation(id=9, title="Man's Search for Meaning"),
    ],
}

# recommendations micro-service

def verify_token(token):

    region = 'us-east-2'
    userpool_id = _USERPOOL_ID
    app_client_id = _APP_CLIENT_ID
    keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
    with urllib.request.urlopen(keys_url) as f:
      response = f.read()
    keys = json.loads(response.decode('utf-8'))['keys']

    #event['token']
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['client_id'] != app_client_id:
        print('Token was not issued for this audience')
        return False
    # now we can use the claims
    #print(claims)
    return True
        

class RecommendationService(
    recommendations_pb2_grpc.RecommendationsServicer
):
    def Recommend(self, request, context):

        metadata = dict(context.invocation_metadata())
        auth_token = metadata.get('authorization', '')
        is_valid_token = verify_token(auth_token)
        if not is_valid_token:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "User Not Authrized ")

        books_for_category = books_by_category[request.category]
        num_results = min(request.max_results, len(books_for_category))
        books_to_recommend = random.sample(
            books_for_category, num_results
        )

        return RecommendationResponse(recommendations=books_to_recommend)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    recommendations_pb2_grpc.add_RecommendationsServicer_to_server(
        RecommendationService(), server
    )
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Server started, listening on 50051")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
