# UAS Distributed Computing Security Model (DCSM - KP R)
**Migrasi & Pengamanan Layanan gRPC Terdistribusi pada Kubernetes (Minikube + Calico)**

## 1. Arsitektur Layanan
- **`gateway-service` (`gateway:1.0`, port `50051`)**: Pintu masuk klien dengan autentikasi mTLS, validasi token JWT (`HS256`), dan penerusan permintaan melalui saluran mTLS internal.
- **`storage-service` (`storage:1.0`, port `50052`)**: Layanan penyimpanan terisolasi dengan kontrol akses berbasis peran (`PUBLIC`/`SECRET`), verifikasi integritas file **SHA-256**, dan *Structured JSON Audit Log*.

## 2. Kontrol Keamanan Kubernetes (`namespace: dcsm-uas`)
1. **RBAC *Least Privilege* (`k8s/01-rbac.yaml`)**: `ServiceAccount` terpisah (`sa-gateway`, `sa-storage`) dengan `automountServiceAccountToken: false` serta `Role`/`RoleBinding` minimal tanpa `cluster-admin`.
2. **Container Hardening & Resource Limits (`k8s/02-deployments.yaml`)**: Eksekusi non-root (`UID 10001`), `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, dan volume `emptyDir` khusus data/log.
3. **Network Isolation (`k8s/03-networkpolicy.yaml`)**: Kebijakan `default-deny-ingress` yang ditegakkan oleh **CNI Calico**, hanya membuka jalur `gateway -> storage:50052` dan `client (access=gateway-client) -> gateway:50051`.
4. **Secrets Management**: Kunci `JWT_SECRET_KEY` dan sertifikat mTLS dikelola melalui objek Kubernetes `Secret` tanpa nilai *plaintext* di dalam image maupun manifest YAML.

## 3. Langkah Reproduksi
1. Inisialisasi cluster: `minikube start --driver=docker --cni=calico --memory=2500mb`
2. Buat sertifikat SAN: `./generate_certs.sh`
3. Build & muat image: `docker build -t gateway:1.0 -f Dockerfile.gateway . && docker build -t storage:1.0 -f Dockerfile.storage .` lalu `minikube image load gateway:1.0 storage:1.0`
4. Buat `Secret` (`jwt-secret`, `gateway-tls-secret`, `storage-tls-secret`) dan terapkan manifest: `kubectl apply -f k8s/`
