# Spring-Security-and-Session-Management-Basics

# Dependencies

<dependency>
  
    <groupId>org.springframework.boot</groupId>
    
    <artifactId>spring-boot-starter-security</artifactId>
    
</dependency>

# SpringConstants

public static final String LOGIN_URI = "/login";
public static final String LOGOUT_URI = "/logout";
public static final String JSESSIONID = "JSESSIONID";
public static final String ADMIN_ROLE = "ADMIN";
public static final String ADMIN_SUCCESS_URL = "/admin/dashboard";
public static final String USER_ROLE = "USER";
public static final String USER_SUCCESS_URL = "/user/dashboard";
SecurityConfig.java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private LoginAuthenticationProvider loginAuthenticationProvider;

    @Autowired
    private LoginSuccessHandler loginSuccessHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                // make sure to grant access to any login page you are forwarding to
                .antMatchers(LOGIN_URI).permitAll()
                .antMatchers("/admin/**").hasAuthority(ADMIN_ROLE)
                .antMatchers("/user/**").hasAuthority(USER_ROLE)
                .and()
                .authenticationProvider(loginAuthenticationProvider)
                .formLogin().loginPage(LOGIN_URI).successHandler(loginSuccessHandler)
                .and()
                .logout().logoutUrl(LOGOUT_URI).logoutSuccessUrl(LOGIN_URI).deleteCookies(JSESSIONID)
                .and()
                .sessionManagement()
                .maximumSessions(1)
                .expiredUrl(LOGIN_URI)
                .maxSessionsPreventsLogin(false)
                .and()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl(LOGIN_URI);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        web.ignoring().antMatchers("/this-path-is-ignored-from-the-rules-above/**");
    }

}
LoginAuthenticationProvider.java
@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserService userService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        User retrievedUser = userService.login(username, password);
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(retrievedUser.getRole());
        return new UsernamePasswordAuthenticationToken(retrievedUser.getId(), password, Collections.singleton(grantedAuthority));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
LoginSuccessHandler.java
@Component
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        if (securityHelper.checkForRole(authentication, ADMIN_ROLE)) {
            redirectToSuccessUrl(request, response, ADMIN_SUCCESS_URL);
        } else {
            redirectToSuccessUrl(request, response, USER_SUCCESS_URL);
        }
    }

    private void redirectToSuccessUrl(HttpServletRequest request, HttpServletResponse response, String success_url) throws IOException {
        RedirectStrategy redirectStrategy = super.getRedirectStrategy();
        redirectStrategy.sendRedirect(request, response, success_url);
    }

    public boolean checkForRole(Authentication authentication, String role) {
        if (authentication != null) {
            return authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()).contains(role);
        }
        return false;
    }
}
LoginFailureHandler.java
@Component
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationException exception) throws IOException {
        if (exception instanceof UsernameNotFoundException) {
            request.getSession().setAttribute("errorMsg", "User does not Exist!");
        }
        RedirectStrategy redirectStrategy = super.getRedirectStrategy();
        redirectStrategy.sendRedirect(request, response, LOGIN_URI);
    }
}
