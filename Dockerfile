# set python version
ARG PYTHON_VERSION="3.12"

FROM docker.io/python:${PYTHON_VERSION}-slim AS build
COPY . /sslyze/
WORKDIR /sslyze
# use a venv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# install sslyze based on sourcecode
RUN pip install --upgrade pip setuptools wheel
RUN pip install .

FROM docker.io/python:${PYTHON_VERSION}-slim AS run
# set user to a non-root user sslyze
RUN adduser --no-create-home --disabled-password --gecos "" --uid 1001 sslyze
USER sslyze
WORKDIR /sslyze
# copy sslyze from build stage
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENTRYPOINT ["sslyze"]
CMD ["-h"]
