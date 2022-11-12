/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package validate;

import dbconnection.DBConnect;
import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 *
 * @author stephen
 */
public class ValidateLogin extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String user=request.getParameter("username").trim();
        String pass=request.getParameter("password").trim();
        
        String query = "select * from users where username = ? and password = ?";
        PreparedStatement stmt = null;
        
        try
             {
                 Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
                    if(con!=null && !con.isClosed())
                               {
                                   stmt = con.prepareStatement(query);
                                   stmt.setString(1, user);
                                   stmt.setString(2, pass);
                                   ResultSet rs = stmt.executeQuery();
                                   if(rs != null && rs.next()){
                                   HttpSession session=request.getSession();
                                        session.setAttribute("userid", rs.getString("id"));
                                        session.setAttribute("user", rs.getString("username"));
                                        session.setAttribute("isLoggedIn", "1");
//                                        Cookie privilege=new Cookie("privilege", secureCookie());
                                        String cookie = "privilege="+secureCookie();
//                                        privilege.setHttpOnly(true);
//                                        privilege.setSecure(true);
                                        response.addHeader("Set-Cookie", cookie+"; HttpOnly; Secure; SameSite=strict");
//                                        response.addCookie(privilege);
                                        response.setHeader("Access-Control-Allow-Headers","Origin, X-Requested-With, Content-Type, Accept, X-Auth-Token, X-Csrf-Token, WWW-Authenticate, Authorization");
                                        response.setHeader("Access-Control-Allow-Credentials", "false");
                                        response.setHeader("Content-Security-Policy", "self");
                                        response.sendRedirect("members.jsp");
                                   }                                 
                               }
                }
               catch(Exception ex)
                {
                           response.sendRedirect("failedLogin.jsp");
                 }
    }
    
    private static String secureCookie() {
        byte[] nonce = new byte[20];
        new SecureRandom().nextBytes(nonce);
        return convertBytesToHex(nonce);
    }
    
    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }


    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
