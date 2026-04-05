FROM quay.io/keycloak/keycloak:26.1.4

COPY target/keycloak-agent-auth-*.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev"]
