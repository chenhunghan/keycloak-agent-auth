package com.github.chh.keycloak.agentauth.notify;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.urls.UrlType;

/**
 * AAP §7.2 CIBA push channel: emails the linked user when a delegated registration, capability
 * request, or reactivation kicks off through CIBA. The email body carries a direct link back to
 * {@code GET /agent-auth/verify?agent_id=...} so the user can approve from a separate device.
 *
 * <p>
 * Best-effort: any failure (no SMTP configured, user without email, send exception) is logged and
 * swallowed — the agent-auth HTTP response must not depend on whether email delivery succeeded.
 * Approvals can still be discovered via {@code GET /agent-auth/inbox}.
 *
 * <p>
 * Body builders are deliberately {@code static} pure functions so they can be unit-tested without a
 * Keycloak session.
 */
public final class CibaEmailNotifier {

  private static final Logger LOG = Logger.getLogger(CibaEmailNotifier.class.getName());

  private final KeycloakSession session;

  public CibaEmailNotifier(KeycloakSession session) {
    this.session = session;
  }

  /**
   * Notify the user linked to {@code hostData.user_id} that an agent registration awaits their
   * approval. Returns {@code true} when an email was attempted (regardless of whether SMTP actually
   * accepted it), {@code false} when no email was applicable.
   */
  public boolean notifyApproval(String agentId, Map<String, Object> agentData,
      Map<String, Object> hostData, String bindingMessage) {
    if (agentId == null || hostData == null) {
      return false;
    }
    RealmModel realm = session.getContext().getRealm();
    if (realm == null) {
      return false;
    }
    Map<String, String> smtp = realm.getSmtpConfig();
    if (smtp == null || smtp.isEmpty()) {
      LOG.log(Level.FINE, () -> "agent-auth: realm " + realm.getName()
          + " has no SMTP configured — skipping CIBA email notification");
      return false;
    }
    Object rawUserId = hostData.get("user_id");
    if (!(rawUserId instanceof String userId) || userId.isBlank()) {
      return false;
    }
    UserModel user = session.users().getUserById(realm, userId);
    if (user == null) {
      return false;
    }
    String email = user.getEmail();
    if (email == null || email.isBlank()) {
      LOG.log(Level.FINE, () -> "agent-auth: linked user " + userId
          + " has no email — skipping CIBA email notification");
      return false;
    }

    String agentName = stringField(agentData, "name", "(unnamed)");
    String hostName = stringField(hostData, "name", null);
    String verifyUrl = buildVerifyUrl(agentId);

    String subject = buildSubject(agentName, hostName);
    String text = buildTextBody(agentName, hostName, verifyUrl, bindingMessage);
    String html = buildHtmlBody(agentName, hostName, verifyUrl, bindingMessage);

    try {
      session.getProvider(EmailSenderProvider.class)
          .send(smtp, user, subject, text, html);
      return true;
    } catch (EmailException | RuntimeException e) {
      LOG.log(Level.WARNING,
          "agent-auth: CIBA email notification failed (caller continues; inbox is the fallback)",
          e);
      return false;
    }
  }

  private String buildVerifyUrl(String agentId) {
    return session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder()
        .path("realms").path(session.getContext().getRealm().getName()).path("agent-auth")
        .path("verify").queryParam("agent_id", agentId).build().toString();
  }

  static String buildSubject(String agentName, String hostName) {
    StringBuilder sb = new StringBuilder("Approve agent registration: ").append(agentName);
    if (hostName != null && !hostName.isBlank()) {
      sb.append(" (").append(hostName).append(")");
    }
    return sb.toString();
  }

  static String buildTextBody(String agentName, String hostName, String verifyUrl,
      String bindingMessage) {
    StringBuilder sb = new StringBuilder();
    sb.append("An agent named '").append(agentName).append("' is requesting access");
    if (hostName != null && !hostName.isBlank()) {
      sb.append(" through host '").append(hostName).append("'");
    }
    sb.append(".\n\n");
    if (bindingMessage != null && !bindingMessage.isBlank()) {
      sb.append("The application says: ").append(bindingMessage).append("\n\n");
    }
    sb.append("Approve or deny this request:\n").append(verifyUrl).append("\n\n");
    sb.append("If you did not initiate this, ignore this email.\n");
    return sb.toString();
  }

  static String buildHtmlBody(String agentName, String hostName, String verifyUrl,
      String bindingMessage) {
    StringBuilder sb = new StringBuilder();
    sb.append("<!DOCTYPE html><html lang=\"en\"><body>");
    sb.append("<p>An agent named <strong>").append(htmlEscape(agentName))
        .append("</strong> is requesting access");
    if (hostName != null && !hostName.isBlank()) {
      sb.append(" through host <strong>").append(htmlEscape(hostName)).append("</strong>");
    }
    sb.append(".</p>");
    if (bindingMessage != null && !bindingMessage.isBlank()) {
      sb.append("<blockquote>").append(htmlEscape(bindingMessage)).append("</blockquote>");
    }
    sb.append("<p><a href=\"").append(htmlEscape(verifyUrl))
        .append("\" rel=\"noreferrer\">Approve or deny this request</a></p>");
    sb.append("<p>If you did not initiate this, ignore this email.</p>");
    sb.append("</body></html>");
    return sb.toString();
  }

  private static String stringField(Map<String, Object> data, String key, String fallback) {
    if (data == null) {
      return fallback;
    }
    Object v = data.get(key);
    if (v instanceof String s && !s.isBlank()) {
      return s;
    }
    return fallback;
  }

  private static String htmlEscape(String raw) {
    if (raw == null) {
      return "";
    }
    return raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&#x27;");
  }
}
