import os
import sys
import grpc
from concurrent import futures

sys.path.append(os.path.join(os.path.dirname(__file__), 'generated'))
import storage_pb2
import storage_pb2_grpc

from auth import verify_token
from logger import audit_logger
from interceptors import SecurityInterceptor

CERT_DIR = os.environ.get("CERT_DIR", "certs")
GATEWAY_PORT = os.environ.get("GATEWAY_PORT", "50051")
STORAGE_ADDR = os.environ.get("STORAGE_ADDR", "storage-service:50052")

class GatewayServicer(storage_pb2_grpc.SecureStorageServiceServicer):
    def __init__(self):
        with open(os.path.join(CERT_DIR, "ca.crt"), "rb") as f: ca_cert = f.read()
        with open(os.path.join(CERT_DIR, "gateway.crt"), "rb") as f: client_cert = f.read()
        with open(os.path.join(CERT_DIR, "gateway.key"), "rb") as f: client_key = f.read()

        self.upstream_creds = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert
        )

    def _forward_metadata(self, context):
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", "")
        payload = verify_token(token) or {}
        user = payload.get("sub", "unknown")
        role = payload.get("role", "GUEST")
        return [("authorization", token)], user, role

    def UploadFile(self, request, context):
        fwd_meta, user, role = self._forward_metadata(context)
        audit_logger.log(user, role, "GATEWAY_FORWARD_UPLOAD", request.filename, "ALLOW", f"Forwarding to {STORAGE_ADDR}")
        try:
            with grpc.secure_channel(STORAGE_ADDR, self.upstream_creds) as channel:
                stub = storage_pb2_grpc.SecureStorageServiceStub(channel)
                return stub.UploadFile(request, metadata=fwd_meta, timeout=5)
        except grpc.RpcError as e:
            context.abort(e.code(), e.details())

    def DownloadFile(self, request, context):
        fwd_meta, user, role = self._forward_metadata(context)
        audit_logger.log(user, role, "GATEWAY_FORWARD_DOWNLOAD", request.filename, "ALLOW", f"Forwarding to {STORAGE_ADDR}")
        try:
            with grpc.secure_channel(STORAGE_ADDR, self.upstream_creds) as channel:
                stub = storage_pb2_grpc.SecureStorageServiceStub(channel)
                return stub.DownloadFile(request, metadata=fwd_meta, timeout=5)
        except grpc.RpcError as e:
            context.abort(e.code(), e.details())

def serve():
    with open(os.path.join(CERT_DIR, "gateway.key"), "rb") as f: private_key = f.read()
    with open(os.path.join(CERT_DIR, "gateway.crt"), "rb") as f: cert_chain = f.read()
    with open(os.path.join(CERT_DIR, "ca.crt"), "rb") as f: ca_cert = f.read()

    server_creds = grpc.ssl_server_credentials(
        [(private_key, cert_chain)],
        root_certificates=ca_cert,
        require_client_auth=True
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), interceptors=[SecurityInterceptor()])
    storage_pb2_grpc.add_SecureStorageServiceServicer_to_server(GatewayServicer(), server)
    server.add_secure_port(f"[::]:{GATEWAY_PORT}", server_creds)
    print(f"Secure Gateway Service running on port {GATEWAY_PORT} -> upstream {STORAGE_ADDR}...", flush=True)
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
