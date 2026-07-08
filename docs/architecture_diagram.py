#!/usr/bin/env python3
"""Regenerate docs/ARCHITECTURE.png for the OAuth 2.0 Token Exchange sample.

Renders the RFC 8693 token-exchange flow (see the blog post / README):
client -> External IdP (user token) -> API Gateway (+ Lambda authorizer / SSM)
-> TokenExchange Lambda (verify) -> Service pool custom-auth + PreTokenGeneration
(delegation claims) -> exchanged token -> downstream resource.

Run:  env -u PYTHONPATH ~/acote-scan-venv/bin/python docs/architecture_diagram.py
Requires: diagrams (pip) + graphviz `dot` on PATH.
"""
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import Lambda
from diagrams.aws.network import APIGateway
from diagrams.aws.security import Cognito
from diagrams.aws.management import SystemsManagerParameterStore
from diagrams.aws.general import Client, GenericSamlToken

graph_attr = {
    "fontsize": "16",
    "labelloc": "t",
    "pad": "0.5",
    "nodesep": "0.6",
    "ranksep": "0.9",
    "bgcolor": "white",
    "splines": "spline",
}

with Diagram(
    "OAuth 2.0 Token Exchange on Amazon Cognito",
    filename="docs/ARCHITECTURE",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
):
    client = Client("Client / Service\n(acts on behalf of user)")

    with Cluster("Amazon Cognito"):
        ext_idp = Cognito("External IdP\nuser pool")
        svc_pool = Cognito("Service\nuser pool")

    with Cluster("Token exchange endpoint (serverless)"):
        apigw = APIGateway("API Gateway\n/v1/token-exchange")
        authorizer = Lambda("Lambda authorizer\n(client creds)")
        ssm = SystemsManagerParameterStore("Parameter Store\n(client secrets)")
        exchange = Lambda("TokenExchange Lambda\n(verify w/ aws-jwt-verify)")

        with Cluster("Custom auth + triggers"):
            pretoken = Lambda("PreTokenGeneration\n(delegation claims)")
            challenge = Lambda("Define / Create /\nVerify challenge")

    downstream = GenericSamlToken("Downstream API\n(reads exchanged token)")

    # 1. Authenticate the user against the external IdP -> user token
    client >> Edge(label="1. authenticate -> user token", color="darkgreen") >> ext_idp

    # 2. Exchange request -> API GW; authorizer validates client creds from SSM
    client >> Edge(label="2. RFC 8693 exchange request", color="black") >> apigw
    apigw >> Edge(label="validate client", style="dashed") >> authorizer
    authorizer >> Edge(style="dashed") >> ssm

    # 3. Verify the user token against the external IdP
    apigw >> Edge(label="3. invoke", color="black") >> exchange
    exchange >> Edge(label="verify JWKS", style="dashed", color="firebrick") >> ext_idp

    # 4. Mint delegated token: custom auth flow + PreTokenGeneration claims
    exchange >> Edge(label="4. custom auth flow", color="darkblue") >> svc_pool
    svc_pool >> Edge(style="dashed") >> challenge
    svc_pool >> Edge(label="attach custom claims\n+ scopes", style="dashed") >> pretoken

    # 5. Client uses exchanged token downstream (service sub + user context)
    exchange >> Edge(label="exchanged token", color="darkblue") >> client
    client >> Edge(label="5. call with delegated token", color="darkgreen") >> downstream

print("Wrote docs/ARCHITECTURE.png")
