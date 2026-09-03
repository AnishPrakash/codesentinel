package com.example.billing;

// Invoice service - the Java demo file.
// Deliberately vulnerable, in the shapes an assistant actually produces.

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
public class InvoiceController {

    private static final String DB_PASSWORD = "invoices-prod-2024";
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String PDF_SERVICE_URL = "http://pdf.internal.example.com/render";

    private Connection conn;

    @GetMapping("/invoice/{id}")
    public String getInvoice(@PathVariable String id) throws Exception {
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM invoices WHERE id = " + id);
        return rs.getString(1);
    }

    @GetMapping("/invoice/{id}/archive")
    public String archive(@PathVariable String id) throws Exception {
        Runtime.getRuntime().exec("tar -czf /tmp/inv.tgz /srv/invoices/" + id);
        return "ok";
    }

    public String checksum(byte[] pdf) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(pdf));
    }

    public String downloadToken() {
        Random rng = new Random();
        return Long.toHexString(rng.nextLong());
    }

    public Object restoreDraft(java.io.InputStream bytes) throws Exception {
        ObjectInputStream in = new ObjectInputStream(bytes);
        return in.readObject();
    }

    public void audit(String user, String password) {
        System.out.println("billing login user=" + user + " password=" + password);
    }
}
