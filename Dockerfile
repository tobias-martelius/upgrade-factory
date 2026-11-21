# Pinned tool versions; update deliberately and rerun the verification tests.
FROM aquasec/trivy:0.58.2 AS trivy
FROM maven:3.9.9-eclipse-temurin-21

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 lab \
    && useradd --uid 10001 --gid lab --create-home lab
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
WORKDIR /app
COPY lab.py upgrades.py inventory.py verification.py test_lab.py test_upgrades.py test_verification.py ./
COPY examples ./examples
RUN mkdir -p /app/.lab /home/lab/.m2 /home/lab/.cache/trivy \
    && chown -R lab:lab /app/.lab /home/lab
ENV HOME=/home/lab \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/home/lab/.cache/trivy
USER 10001:10001
CMD ["python3", "lab.py", "serve", "--host", "0.0.0.0"]
