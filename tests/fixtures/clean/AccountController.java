package com.example.billing;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Structurally the same controller as the vulnerable fixture - same routes,
 * same imports, same shape - built safely. If the scanner cannot tell these
 * two apart it is matching style, not security.
 */
@RestController
public class AccountController {

    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private static final String AWS_ACCESS_KEY = System.getenv("AWS_ACCESS_KEY_ID");
    private static final String REPORT_ENDPOINT = "https://reports.example.com/v1";

    private Connection conn;

    @GetMapping("/account/{id}")
    @PreAuthorize("isAuthenticated()")
    public String getAccount(@PathVariable String id, Authentication auth) throws Exception {
        PreparedStatement ps = conn.prepareStatement(
                "SELECT * FROM accounts WHERE id = ? AND owner = ?");
        ps.setString(1, id);
        ps.setString(2, auth.getName());
        ResultSet rs = ps.executeQuery();
        return rs.getString(1);
    }

    @GetMapping("/account/{id}/export")
    @PreAuthorize("isAuthenticated()")
    public String export(@PathVariable String id) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("tar", "-czf", "/tmp/out.tgz", safe(id));
        pb.start();
        return "ok";
    }

    public String fingerprint(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return new String(md.digest(data));
    }

    public String sessionToken() {
        SecureRandom rng = new SecureRandom();
        return Long.toHexString(rng.nextLong());
    }

    public void audit(String userId) {
        System.out.println("login for userId=" + userId);
    }

    private String safe(String id) {
        return id.replaceAll("[^A-Za-z0-9_-]", "");
    }
}
