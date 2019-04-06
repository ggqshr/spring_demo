package com.spring_boot.demo.Controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
public class helloController {
    @RequestMapping(value = "/home")
    public String hello(HttpServletRequest request, Principal principal, @AuthenticationPrincipal User user) {
        SecurityContextImpl spring_security_context = (SecurityContextImpl) request.getSession().getAttribute("SPRING_SECURITY_CONTEXT");
        System.out.println("###");
        System.out.println(principal);
        System.out.println("###");
        spring_security_context.getAuthentication().setAuthenticated(false);
        return "hello";
    }

    @RequestMapping(value = "/index")
    public String index() {
        return "index";
    }

    @RequestMapping(value = "/log")
    public String login1() {
        return "login";
    }
}
