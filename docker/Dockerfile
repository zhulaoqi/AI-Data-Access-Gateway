FROM 172.30.10.185:15000/common/python:3.13-slim

ARG PYPI_INDEX_URL=https://pypi.org/simple
ENV APP_HOME /dianyi/app/sqlgw-executor
ENV PATH="${APP_HOME}/.venv/bin:$PATH"
ENV ADG_BACKEND_PORT=8000

WORKDIR $APP_HOME
COPY pyproject.toml uv.lock README.md alembic.ini ./
COPY src ./src
COPY examples ./examples
COPY docker/start.sh $APP_HOME/start.sh
RUN pip install --no-cache-dir --index-url "${PYPI_INDEX_URL}" uv \
    && uv sync --frozen --no-dev --extra all --default-index "${PYPI_INDEX_URL}" \
    && chmod 755 $APP_HOME/start.sh

EXPOSE 8000
CMD ["bash", "-c", "$APP_HOME/start.sh"]
