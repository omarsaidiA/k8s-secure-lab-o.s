# headercheck (github.com/omarsaidiA/headerchecker) installed from a pinned commit.
# The commit archive is used instead of git, so the build image needs no extra tools.
FROM python:3.15.0-slim AS build
ARG HEADERCHECK_REF=f835ea53ab7d7020214fed651b3fa7aa31225af7
RUN python -m venv /opt/headercheck \
    && /opt/headercheck/bin/pip install --no-cache-dir \
        "https://github.com/omarsaidiA/headerchecker/archive/${HEADERCHECK_REF}.tar.gz"

FROM python:3.15.0-slim
# The root filesystem is read-only in the cluster: do not try to write .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
COPY --from=build /opt/headercheck /opt/headercheck
USER 10001:10001
ENTRYPOINT ["/opt/headercheck/bin/headercheck"]
