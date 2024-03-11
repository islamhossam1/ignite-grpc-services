# marketplace/marketplace.py
import os

from flask import Flask, render_template
import grpc
import requests
from recommendations_pb2 import BookCategory, RecommendationRequest
from recommendations_pb2_grpc import RecommendationsStub

_CLIENT_ID =  '<_CLIENT_ID>'
_CLIENT_SECRET = '<_CLIENT_SECRET>'
_TOKEN_ENDPOINT = '<_TOKEN_ENDPOINT>'
_SCOPE = '<_SCOPE>'

app = Flask(__name__)
recommendations_host = os.getenv("RECOMMENDATIONS_HOST", "localhost")
recommendations_channel = grpc.insecure_channel(
    f"{recommendations_host}:50051"
)
recommendations_client = RecommendationsStub(recommendations_channel)



def get_access_token(client_id, client_secret, token_endpoint, scope):
   
    # Encode the client credentials in base64 format
    credentials = requests.auth._basic_auth_str(client_id, client_secret)

    # Set the headers and the payload for the request
    headers = {
        "Authorization": credentials,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = {"grant_type": "client_credentials", "scope": scope}

    # Send a POST request to the token endpoint
    response = requests.post(token_endpoint, headers=headers, data=payload)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the response as JSON
        data = response.json()
        # Get the access token from the response
        access_token = data["access_token"]
        # Return the access token
        return access_token
    else:
        # Return None to indicate failure
        return None
    
def get_token_data():
        # Example usage of the function
        # Define the client ID and client secret
        client_id = _CLIENT_ID#os.environ["CLIENT_ID"]
        # print("client_id", client_id)
        client_secret = _CLIENT_SECRET#os.environ["CLIENT_SECERT"]

        # Define the token endpoint and the scope
        token_endpoint = _TOKEN_ENDPOINT#os.environ["COGNITO_TOKEN_ENDPOINT"]
        scope = _SCOPE

        # Call the function and print the result
        access_token = get_access_token(client_id, client_secret, token_endpoint, scope)
        if access_token is not None:
            print("Access token: generated")
            return access_token
        else:
            print("Error: Failed to get access token")



def recommend_books():
    recommendations_request = RecommendationRequest(
        user_id=1, category=BookCategory.MYSTERY, max_results=3
    )
    try:
        auth_token = get_token_data()
        custom_headers = [('authorization', auth_token)]
        recommendations_response = recommendations_client.Recommend(
        recommendations_request, metadata=custom_headers
    )
    except grpc.RpcError as rpc_error:
        return rpc_error
    else:
        return recommendations_response
    
@app.route("/")
def render_homepage():
    recommendations_response = recommend_books()
    return render_template(
        "homepage.html",
        recommendations=recommendations_response.recommendations,
    )

if __name__ == '__main__':  
   app.run()