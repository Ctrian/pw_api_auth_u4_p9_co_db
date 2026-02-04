package uce.edu.web.api.auth.interfaces;

import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import uce.edu.web.api.auth.model.Rol;
import uce.edu.web.api.auth.model.Usuario;
import io.smallrye.jwt.build.Jwt;
import org.mindrot.jbcrypt.BCrypt;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    EntityManager em;

    @POST
    @Path("/token")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Transactional
    public Response token(LoginRequest login) {

        System.out.println(">>> Usuario recibido: " + login.getUsername());
        System.out.println(">>> Password recibido: " + login.getPassword());

        // 1. Buscar usuario
        Usuario usuario = Usuario.find("username", login.getUsername()).firstResult();

        if (usuario == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Usuario no encontrado").build();
        }

        // 2. Verificar contraseña (BCrypt compara texto plano con hash)
        if (!BCrypt.checkpw(login.getPassword(), usuario.getPasswordHash())) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Contraseña incorrecta").build();
        }

        // 3. Obtener roles
        Set<String> roles = usuario.getRoles()
                .stream()
                .map(Rol::getNombre)
                .collect(Collectors.toSet());

        // 4. Generar JWT
        Instant now = Instant.now();
        String jwt = Jwt.issuer("matricula-auth")
                .subject(usuario.getUsername())
                .upn(usuario.getEmail())
                .groups(roles)
                .claim("userId", usuario.getId())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600))
                .sign();

        return Response.ok(new TokenResponse(
                jwt,
                now.plusSeconds(3600).getEpochSecond(),
                roles)).build();
    }

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Transactional
    public Response register(RegisterRequest request) {

        // 1. Verificar si ya existe
        if (Usuario.find("username", request.getUsername()).firstResult() != null) {
            return Response.status(Response.Status.CONFLICT)
                    .entity("Usuario ya existe").build();
        }

        // 2. Crear nuevo usuario
        Usuario nuevo = new Usuario();
        nuevo.setUsername(request.getUsername());
        nuevo.setEmail(request.getEmail());
        nuevo.setActivo(true);

        // ✅ HASHEAR la contraseña antes de guardar
        String hashedPassword = BCrypt.hashpw(request.getPassword(), BCrypt.gensalt(12));
        nuevo.setPasswordHash(hashedPassword);

        // 3. Asignar rol por defecto (ej: "user")
        Rol rolUser = Rol.find("nombre", "user").firstResult();
        if (rolUser != null) {
            nuevo.setRoles(Set.of(rolUser));
        }

        // 4. Guardar
        nuevo.persist();

        return Response.status(Response.Status.CREATED)
                .entity("Usuario creado: " + nuevo.getUsername()).build();
    }

    // DTO para registro
    public static class RegisterRequest {
        private String username;
        private String password;
        private String email;

        // getters y setters
        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }

    // DTOs
    public static class LoginRequest {
        private String username;
        private String password;

        // getters/setters
        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    public static class TokenResponse {
        public String accessToken;
        public long expiresAt;
        public Set<String> roles; // ✅ Ahora es un Set, no solo String

        public TokenResponse(String accessToken, long expiresAt, Set<String> roles) {
            this.accessToken = accessToken;
            this.expiresAt = expiresAt;
            this.roles = roles;
        }
    }
}