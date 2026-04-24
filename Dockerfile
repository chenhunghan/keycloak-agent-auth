FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /build

# Resolve dependencies in a layer keyed only by pom.xml so source edits don't re-download.
COPY pom.xml .
RUN mvn -B -e dependency:go-offline

# Build the extension JAR and collect runtime libs into target/provider-libs/.
COPY src ./src
RUN mvn -B -e -Pquick package

FROM quay.io/keycloak/keycloak:26.1.4

COPY --from=build /build/target/keycloak-agent-auth-*.jar /opt/keycloak/providers/
COPY --from=build /build/target/provider-libs/*.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev"]
