package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 忽略静态资源的访问
        web.ignoring().antMatchers("/resources/**");
    }

    // AuthenticationManager: 认证的核心接口.
    // AuthenticationManagerBuilder: 用于构建AuthenticationManager对象的工具.
    // ProviderManager: AuthenticationManager接口的默认实现类.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 内置的认证规则
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));

        // 自定义认证规则
        // AuthenticationProvider: ProviderManager持有一组AuthenticationProvider,每个AuthenticationProvider负责一种认证.
        // 委托模式: ProviderManager将认证委托给AuthenticationProvider.
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication: 用于封装认证信息的接口,不同的实现类代表不同类型的认证信息.

            //这一部分其实就是把之前登陆验证模块放在这个
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();

                User user = userService.findUserByName(username);
                if (user == null) {

                    //抛出异常之后后面有filter处理
                    throw new UsernameNotFoundException("账号不存在!");
                }

                password = CommunityUtil.md5(password + user.getSalt());
                if (!user.getPassword().equals(password)) {
                    throw new BadCredentialsException("密码不正确!");
                }


                //返回接口实例，与下面supports相对应
                // principal: 主要信息; credentials: 证书，账号密码逻辑下通常就是密码; authorities: 权限;
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            // 当前的AuthenticationProvider支持哪种类型的认证.
            @Override
            public boolean supports(Class<?> aClass) {


                // UsernamePasswordAuthenticationToken: Authentication接口的常用的实现类.代表账号密码认证
                return UsernamePasswordAuthenticationToken.class.equals(aClass);
            }
        });
    }

    //默认覆盖所有请求，重写方法后就涉及方法内请求，重写这个方法避开默认的登陆页面
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登录表单相关配置
        http.formLogin()
                .loginPage("/loginpage")
                .loginProcessingUrl("/login")
                .successHandler(new AuthenticationSuccessHandler() {
                    //成功情况下的处理逻辑
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                       //成功跳转到首页
                        response.sendRedirect(request.getContextPath() + "/index");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        //失败情况回到登陆页面，给一个错误提示
                        //请求转发
                        request.setAttribute("error", e.getMessage());
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                    }
                });

        // 退出相关配置
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath() + "/index");
                    }
                });

        // 授权配置
        //权限和路径对应关系
        //exceptionHandling().accessDeniedPage权限不匹配之后地方处理页面
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER", "ADMIN")
                .antMatchers("/admin").hasAnyAuthority("ADMIN")
                .and().exceptionHandling().accessDeniedPage("/denied");


        //自定义一个filter，在账号密码之前
        // 增加Filter,处理验证码
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
               //转型为(HttpServletRequest)，方法比较多，使用起来方便
                HttpServletRequest request = (HttpServletRequest) servletRequest;
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                //说明是登陆多业务
                if (request.getServletPath().equals("/login")) {
                    String verifyCode = request.getParameter("verifyCode");
                    //假设验证码是"1234"
                    if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")) {
                        //回到登陆页面
                        request.setAttribute("error", "验证码错误!");
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                        return;
                    }
                }

                //要么不是登陆请求，要么验证码对了
                // 让请求继续向下执行,执行到下一个filter，没有filter就终止
                filterChain.doFilter(request, response);
            }
        }, UsernamePasswordAuthenticationFilter.class);

        // 记住我
        //把用户信息记录到内存中
        //.userDetailsService(userService)帮你查出用户完整信息，关机操作后，内存失效后重新查找
        http.rememberMe()
                .tokenRepository(new InMemoryTokenRepositoryImpl())
                .tokenValiditySeconds(3600 * 24)
                .userDetailsService(userService);

    }
}
