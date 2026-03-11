FROM postgres:16.6

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    postgresql-server-dev-16 \
    libclang-dev \
    libssl-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (needed for pg-cbor / pg-webauthn)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path --default-toolchain stable

# Build pg-cbor
WORKDIR /opt
RUN git clone https://github.com/truthly/pg-cbor.git
WORKDIR /opt/pg-cbor
RUN make && make install

# Build pg-webauthn
WORKDIR /opt
RUN git clone https://github.com/truthly/pg-webauthn.git
WORKDIR /opt/pg-webauthn
RUN make && make install

# Return to default postgres workdir
WORKDIR /