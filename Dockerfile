FROM mono:6.12.0

# Install .NET SDK
ENV DOTNET_VERSION=8.0

RUN curl -sSL https://dot.net/v1/dotnet-install.sh  \
    | bash -s -- -Channel $DOTNET_VERSION -InstallDir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet
    
WORKDIR /build

CMD [ "dotnet", "build" ]

## Build Docker image (one time):
# docker build -t shc-build . --no-cache

## Build solution (every time):
# docker run --rm -v .:/build shc-build
