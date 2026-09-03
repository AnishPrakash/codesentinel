package com.example.billing;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

    private static final String DB_PASSWORD = "billing-prod-2024";
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String REPORT_ENDPOINT = "http://reports.internal.example.com/v1";

    private Connection conn;

    @GetMapping("/account/{id}")
    public String getAccount(@PathVariable String id) throws Exception {
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM accounts WHERE id = " + id);
        return rs.getString(1);
    }

    @GetMapping("/account/{id}/export")
    public String export(@PathVariable String id) throws Exception {
        Runtime.getRuntime().exec("tar -czf /tmp/out.tgz /srv/accounts/" + id);
        return "ok";
    }

    public String fingerprint(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(data));
    }

    public String sessionToken() {
        Random rng = new Random();
        return Long.toHexString(rng.nextLong());
    }

    public Object restore(java.io.InputStream bytes) throws Exception {
        ObjectInputStream in = new ObjectInputStream(bytes);
        return in.readObject();
    }

    public void audit(String password) {
        System.out.println("login with password=" + password);
    }
}
