package com.iotplatform.auth.test;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;

import com.iotplatform.auth.config.SecurityConfig;
import com.iotplatform.auth.filter.JwtAuthenticationFilter;
import com.iotplatform.auth.service.CustomUserDetailsService;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecurityConfig.class)
public class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CustomUserDetailsService userDetailsService;

    @MockBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Test
    void whenAccessPublicEndpoint_thenOk() throws Exception {
        mockMvc.perform(get("/api/auth/login"))
               .andExpect(status().isOk());
    }

    @Test
    void whenAccessProtectedEndpointWithoutAuth_thenUnauthorized() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
               .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void whenAccessAdminEndpointWithAdminRole_thenOk() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
               .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "USER")
    void whenAccessAdminEndpointWithUserRole_thenForbidden() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
               .andExpect(status().isForbidden());
    }
}
