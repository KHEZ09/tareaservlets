import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Formulario y lectura segura de las cookies de preferencias del usuario.
 */
@WebServlet("/cookies")
public class cookies extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static final String COOKIE_USERNAME = "uname";
    private static final String COOKIE_COLOR = "favoriteColor";
    private static final String COOKIE_LANGUAGE = "language";
    private static final String COOKIE_NOTIFICATIONS = "notifications";
    private static final String COOKIE_AGE = "age";

    private static final String DEFAULT_COLOR = "azul";
    private static final String DEFAULT_LANGUAGE = "es";
    private static final boolean DEFAULT_NOTIFICATIONS = false;
    private static final int DEFAULT_AGE = 18;
    private static final int MIN_AGE = 13;
    private static final int MAX_AGE = 120;
    private static final int COOKIE_MAX_AGE = 60 * 60 * 24 * 30;

    private static final Set<String> ALLOWED_COLORS = Set.of("azul", "verde", "rojo");
    private static final Set<String> ALLOWED_LANGUAGES = Set.of("es", "en", "fr");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        prepareNoCache(response);

        HttpSession session = getAuthenticatedSession(request, response);
        if (session == null) {
            return;
        }

        String username = (String) session.getAttribute("userName");
        CookieData data = readCookieData(request, username);
        renderForm(response, username, data, data.invalidCookiesMessage);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.setCharacterEncoding("UTF-8");
        prepareNoCache(response);

        HttpSession session = getAuthenticatedSession(request, response);
        if (session == null) {
            return;
        }

        String username = (String) session.getAttribute("userName");
        CookieData currentData = readCookieData(request, username);

        String color = getSingleParameter(request, "favoriteColor");
        String language = getSingleParameter(request, "language");
        String notificationsParameter = getSingleParameter(request, "notifications");
        String ageParameter = getSingleParameter(request, "age");

        String validationError = validateForm(color, language, notificationsParameter, ageParameter);
        if (validationError != null) {
            CookieData submittedData = dataForFormAfterError(
                    currentData, color, language, notificationsParameter, ageParameter);
            renderForm(response, username, submittedData, validationError);
            return;
        }

        boolean notifications = "true".equals(notificationsParameter);
        int age = Integer.parseInt(ageParameter);

        addCookie(response, request, COOKIE_USERNAME, username);
        addCookie(response, request, COOKIE_COLOR, color);
        addCookie(response, request, COOKIE_LANGUAGE, language);
        addCookie(response, request, COOKIE_NOTIFICATIONS, Boolean.toString(notifications));
        addCookie(response, request, COOKIE_AGE, Integer.toString(age));

        // PRG: evita volver a enviar el formulario al actualizar la página.
        response.sendRedirect(request.getContextPath() + "/cookies");
    }

    private HttpSession getAuthenticatedSession(HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session == null || !Boolean.TRUE.equals(session.getAttribute("authenticated"))
                || !(session.getAttribute("userName") instanceof String)) {
            response.sendRedirect(request.getContextPath() + "/login");
            return null;
        }
        return session;
    }

    private CookieData readCookieData(HttpServletRequest request, String sessionUsername) {
        CookieData data = new CookieData();
        data.username = sessionUsername;

        String usernameCookie = readCookie(request, COOKIE_USERNAME);
        if (usernameCookie == null) {
            data.invalidCookiesMessage = "La cookie de usuario no existe; se usó la sesión actual.";
        } else if (!sessionUsername.equals(usernameCookie)) {
            data.invalidCookiesMessage = "La cookie de usuario no coincide; se usó la sesión actual.";
        }

        String color = readCookie(request, COOKIE_COLOR);
        if (color != null && ALLOWED_COLORS.contains(color)) {
            data.color = color;
        } else if (color != null) {
            data.invalidCookiesMessage = "La cookie de color no es válida; se usó un valor predeterminado.";
        }

        String language = readCookie(request, COOKIE_LANGUAGE);
        if (language != null && ALLOWED_LANGUAGES.contains(language)) {
            data.language = language;
        } else if (language != null) {
            data.invalidCookiesMessage = "La cookie de idioma no es válida; se usó un valor predeterminado.";
        }

        String notifications = readCookie(request, COOKIE_NOTIFICATIONS);
        if ("true".equals(notifications) || "false".equals(notifications)) {
            data.notifications = Boolean.parseBoolean(notifications);
        } else if (notifications != null) {
            data.invalidCookiesMessage = "La cookie booleana no es válida; se usó un valor predeterminado.";
        }

        String age = readCookie(request, COOKIE_AGE);
        if (age != null) {
            try {
                int parsedAge = Integer.parseInt(age);
                if (parsedAge >= MIN_AGE && parsedAge <= MAX_AGE) {
                    data.age = parsedAge;
                } else {
                    data.invalidCookiesMessage = "La cookie numérica está fuera de rango; se usó un valor predeterminado.";
                }
            } catch (NumberFormatException exception) {
                data.invalidCookiesMessage = "La cookie numérica no es válida; se usó un valor predeterminado.";
            }
        }

        return data;
    }

    private String validateForm(String color, String language, String notifications, String age) {
        if (color == null || !ALLOWED_COLORS.contains(color)) {
            return "Selecciona un color válido.";
        }

        if (language == null || !ALLOWED_LANGUAGES.contains(language)) {
            return "Selecciona un idioma válido.";
        }

        if (notifications != null && !"true".equals(notifications)
                && !"false".equals(notifications)) {
            return "El valor de notificaciones debe ser true o false.";
        }

        if (age == null || age.isBlank()) {
            return "La edad es obligatoria.";
        }

        try {
            int parsedAge = Integer.parseInt(age);
            if (parsedAge < MIN_AGE || parsedAge > MAX_AGE) {
                return "La edad debe estar entre " + MIN_AGE + " y " + MAX_AGE + ".";
            }
        } catch (NumberFormatException exception) {
            return "La edad debe ser un número entero.";
        }

        return null;
    }

    private CookieData dataForFormAfterError(CookieData current, String color,
            String language, String notifications, String age) {
        CookieData data = new CookieData();
        data.username = current.username;

        if (color != null && ALLOWED_COLORS.contains(color)) {
            data.color = color;
        } else {
            data.color = current.color;
        }

        if (language != null && ALLOWED_LANGUAGES.contains(language)) {
            data.language = language;
        } else {
            data.language = current.language;
        }

        data.notifications = "true".equals(notifications);

        try {
            int parsedAge = Integer.parseInt(age);
            data.age = parsedAge >= MIN_AGE && parsedAge <= MAX_AGE ? parsedAge : current.age;
        } catch (NumberFormatException exception) {
            data.age = current.age;
        }

        return data;
    }

    private String getSingleParameter(HttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        if (values == null || values.length == 0) {
            return null;
        }
        if (values.length > 1) {
            return "";
        }
        return values[0] == null ? null : values[0].trim();
    }

    private String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                try {
                    return URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8);
                } catch (IllegalArgumentException exception) {
                    return null;
                }
            }
        }
        return null;
    }

    private void addCookie(HttpServletResponse response, HttpServletRequest request,
            String name, String value) {
        Cookie cookie = new Cookie(name, URLEncoder.encode(value, StandardCharsets.UTF_8));
        cookie.setMaxAge(COOKIE_MAX_AGE);
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setPath(request.getContextPath().isEmpty() ? "/" : request.getContextPath());
        response.addCookie(cookie);
    }

    private void renderForm(HttpServletResponse response, String username, CookieData data,
            String message) throws IOException {
        response.setContentType("text/html; charset=UTF-8");

        try (PrintWriter out = response.getWriter()) {
            out.println("<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>");
            out.println("<title>Preferencias y cookies</title></head><body>");
            out.println("<h1>Preferencias de " + escapeHtml(username) + "</h1>");

            if (message != null && !message.isEmpty()) {
                out.println("<p role='alert' style='color:#b00020;'><strong>Aviso:</strong> "
                        + escapeHtml(message) + "</p>");
            }

            out.println("<form action='cookies' method='post'>");
            out.println("<label for='favoriteColor'>Color favorito:</label>");
            out.println("<select id='favoriteColor' name='favoriteColor' required>");
            option(out, "azul", "Azul", data.color);
            option(out, "verde", "Verde", data.color);
            option(out, "rojo", "Rojo", data.color);
            out.println("</select><br>");

            out.println("<label for='language'>Idioma:</label>");
            out.println("<select id='language' name='language' required>");
            option(out, "es", "Español", data.language);
            option(out, "en", "Inglés", data.language);
            option(out, "fr", "Francés", data.language);
            out.println("</select><br>");

            out.println("<label for='notifications'>Recibir notificaciones:</label>");
            out.println("<input id='notifications' name='notifications' type='checkbox' value='true'"
                    + (data.notifications ? " checked" : "") + "><br>");

            out.println("<label for='age'>Edad:</label>");
            out.println("<input id='age' name='age' type='number' min='13' max='120' value='"
                    + data.age + "' required><br>");

            out.println("<button type='submit'>Guardar cookies</button>");
            out.println("</form>");

            out.println("<h2>Valores leídos de las cookies</h2><ul>");
            out.println("<li>Texto: " + escapeHtml(data.username) + "</li>");
            out.println("<li>Color: " + escapeHtml(data.color) + "</li>");
            out.println("<li>Idioma: " + escapeHtml(data.language) + "</li>");
            out.println("<li>Notificaciones: " + data.notifications + "</li>");
            out.println("<li>Edad: " + data.age + "</li></ul>");

            out.println("<form action='logout' method='post'><button type='submit'>Cerrar sesión</button></form>");
            out.println("</body></html>");
        }
    }

    private void option(PrintWriter out, String value, String label, String selected) {
        out.println("<option value='" + value + "'"
                + (value.equals(selected) ? " selected" : "") + ">"
                + label + "</option>");
    }

    private void prepareNoCache(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);
    }

    private String escapeHtml(String value) {
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static class CookieData {
        private String username;
        private String color = DEFAULT_COLOR;
        private String language = DEFAULT_LANGUAGE;
        private boolean notifications = DEFAULT_NOTIFICATIONS;
        private int age = DEFAULT_AGE;
        private String invalidCookiesMessage;
    }
}
