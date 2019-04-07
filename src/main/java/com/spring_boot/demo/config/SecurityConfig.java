package com.spring_boot.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 在这里配置对http请求的拦截，已经各种权限信息
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/log").permitAll()
                .and()
                .logout()
                .logoutSuccessUrl("/")
                .logoutUrl("/logout").permitAll()
                .and()
                .authorizeRequests()
                .antMatchers("/home").hasAnyAuthority("ROLE_admin")
                .antMatchers("/index").hasAnyAuthority("user")
                .anyRequest().permitAll();
    }

    /**
     * 在这里进行授权验证
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).
                withUser("ggq").password(new BCryptPasswordEncoder().encode("123456"))
                .roles("admin")
                .and()
                .withUser("swy").password(new BCryptPasswordEncoder().encode("swy")).authorities("user");
    }

    /**
     * 在这里配置对一些静态资源的忽略
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/");
    }
}
