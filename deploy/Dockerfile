# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[postgres]"

FROM python:3.13-slim
RUN useradd --uid 10001 --create-home kavlo
COPY --from=build /install /usr/local
USER 10001
WORKDIR /home/kavlo
ENV KAVLO_CONFIG_DIR=/etc/kavlotryx PYTHONUNBUFFERED=1
EXPOSE 8080
ENTRYPOINT ["kavlo"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
