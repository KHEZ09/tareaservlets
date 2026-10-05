import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Valida el usuario y crea una sesión nueva únicamente cuando los datos son válidos.
 */
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static final int MIN_USERNAME_LENGTH = 4;
    private static final int MAX_USERNAME_LENGTH = 30;
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 64;
    private static final int SESSION_TIMEOUT_MINUTES = 15;

    // Debe comenzar con una letra y solo puede contener letras, números, punto,
    // guion y guion bajo. Al exigir una letra no se aceptan usuarios solo numéricos.
    private static final Pattern USERNAME_PATTERN = Pattern.compile(
            "^[\\p{L}][\\p{L}\\p{N}._-]{3,29}$");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        prepareNoCache(response);
        invalidateCurrentSession(request);
        renderLoginForm(response, "", "");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.setCharacterEncoding("UTF-8");
        prepareNoCache(response);

        String username = request.getParameter("userName");
        String validationError = validateUsername(username);

        String password = request.getParameter("password");
        if (validationError == null) {
            validationError = validatePassword(username, password);
        }

        if (validationError != null) {
            renderLoginForm(response, validationError, username == null ? "" : username.trim());
            return;
        }

        username = username.trim();

        // Previene reutilizar una sesión vieja o una sesión fijada antes del login.
        invalidateCurrentSession(request);

        HttpSession session = request.getSession(true);
        session.setMaxInactiveInterval(SESSION_TIMEOUT_MINUTES * 60);
        session.setAttribute("authenticated", Boolean.TRUE);
        session.setAttribute("userName", username);

        addUsernameCookie(response, request, username);

        response.sendRedirect(request.getContextPath() + "/cookies");
    }

    private void addUsernameCookie(HttpServletResponse response, HttpServletRequest request,
            String username) {
        Cookie cookie = new Cookie("uname", URLEncoder.encode(username, StandardCharsets.UTF_8));
        cookie.setMaxAge(60 * 60 * 24 * 30);
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setPath(request.getContextPath().isEmpty() ? "/" : request.getContextPath());
        response.addCookie(cookie);
    }

    private void invalidateCurrentSession(HttpServletRequest request) {
        HttpSession previousSession = request.getSession(false);
        if (previousSession != null) {
            try {
                previousSession.invalidate();
            } catch (IllegalStateException ignored) {
                // La sesión ya estaba invalidada; el objetivo ya se cumplió.
            }
        }
    }

    private String validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            return "El usuario es obligatorio.";
        }

        String normalizedUsername = username.trim();

        if (normalizedUsername.length() < MIN_USERNAME_LENGTH) {
            return "El usuario debe tener al menos " + MIN_USERNAME_LENGTH + " caracteres.";
        }

        if (normalizedUsername.length() > MAX_USERNAME_LENGTH) {
            return "El usuario no puede superar los " + MAX_USERNAME_LENGTH + " caracteres.";
        }

        if (normalizedUsername.chars().allMatch(Character::isDigit)) {
            return "El usuario no puede estar compuesto únicamente por números.";
        }

        if (!USERNAME_PATTERN.matcher(normalizedUsername).matches()) {
            return "Usa solo letras, números, punto, guion o guion bajo, y comienza con una letra.";
        }

        return null;
    }

    private String validatePassword(String username, String password) {
        if (password == null || password.isEmpty()) {
            return "La contraseña es obligatoria.";
        }

        if (password.length() < MIN_PASSWORD_LENGTH) {
            return "La contraseña debe tener al menos " + MIN_PASSWORD_LENGTH + " caracteres.";
        }

        if (password.length() > MAX_PASSWORD_LENGTH) {
            return "La contraseña no puede superar los " + MAX_PASSWORD_LENGTH + " caracteres.";
        }

        if (password.chars().anyMatch(Character::isWhitespace)) {
            return "La contraseña no puede contener espacios ni saltos de línea.";
        }

        if (username != null && password.equalsIgnoreCase(username.trim())) {
            return "La contraseña no puede ser igual al usuario.";
        }

        boolean hasUppercase = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLowercase = password.chars().anyMatch(Character::isLowerCase);
        boolean hasNumber = password.chars().anyMatch(Character::isDigit);
        boolean hasSymbol = password.chars()
                .anyMatch(character -> !Character.isLetterOrDigit(character)
                        && !Character.isWhitespace(character));

        if (!hasUppercase || !hasLowercase || !hasNumber || !hasSymbol) {
            return "La contraseña debe incluir mayúscula, minúscula, número y símbolo.";
        }

        return null;
    }

    private void renderLoginForm(HttpServletResponse response, String error, String username)
            throws IOException {
        response.setContentType("text/html; charset=UTF-8");

        try (PrintWriter out = response.getWriter()) {
            out.println("<!DOCTYPE html>");
            out.println("<html lang='es'><head><meta charset='UTF-8'>");
            out.println("<title>Iniciar sesión</title></head><body>");
            out.println("<h1>Iniciar sesión</h1>");

            if (!error.isEmpty()) {
                out.println("<p role='alert' style='color:#b00020;'><strong>Error:</strong> "
                        + escapeHtml(error) + "</p>");
            }

            out.println("<form action='" + escapeHtml("login") + "' method='post'>");
            out.println("<label for='userName'>Usuario:</label>");
            out.println("<input id='userName' name='userName' type='text' value='"
                    + escapeHtml(username)
                    + "' minlength='4' maxlength='30' pattern='[A-Za-zÁÉÍÓÚáéíóúÑñ][A-Za-zÁÉÍÓÚáéíóúÑñ0-9._-]{3,29}' required autofocus>");
            out.println("<small>4 a 30 caracteres, comienza con una letra y no admite espacios.</small>");
            out.println("<br><label for='password'>Contraseña:</label>");
            out.println("<input id='password' name='password' type='password' minlength='8' maxlength='64' "
                    + "autocomplete='current-password' required>");
            out.println("<small>8 a 64 caracteres, con mayúscula, minúscula, número y símbolo.</small>");
            out.println("<br><button type='submit'>Entrar</button>");
            out.println("</form></body></html>");
        }
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
}
