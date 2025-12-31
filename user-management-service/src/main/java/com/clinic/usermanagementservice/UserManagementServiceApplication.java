package com.clinic.usermanagementservice;

import com.clinic.usermanagementservice.domain.Permission;
import com.clinic.usermanagementservice.domain.Role;
import com.clinic.usermanagementservice.repository.PermissionRepository;
import com.clinic.usermanagementservice.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@SpringBootApplication
@ComponentScan(basePackages = {
        "com.clinic.usermanagementservice",
        "com.clinic.sharedsecurity",
        "com.clinic.sharedinternaltokengen",
        "com.clinic.sharedlib.audit",
        "com.clinic.sharedsecurityjwt"
})
@EnableDiscoveryClient
public class UserManagementServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserManagementServiceApplication.class, args);

}


    @Bean
    CommandLineRunner initRolesAndPermissions(
//                TenantRepository tenantRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository
    ) {
        return args -> {

//                String tenantCode = "CLINIC_001";
//
//                Tenant tenant = tenantRepository.findByCode(tenantCode)
//                        .orElseThrow(() -> new IllegalStateException("Tenant not found"));

            // 1️⃣ Permissions (Global)
            Map<String, Permission> permissions = new HashMap<>();

            List<String> permissionNames = List.of(
                    "USER_CREATE", "USER_UPDATE", "USER_DELETE", "USER_VIEW",
                    "ROLE_CREATE", "ROLE_UPDATE", "ROLE_ASSIGN",
                    "PATIENT_CREATE", "PATIENT_UPDATE", "PATIENT_VIEW",
                    "APPOINTMENT_CREATE", "APPOINTMENT_UPDATE", "APPOINTMENT_CANCEL", "APPOINTMENT_VIEW",
                    "BILLING_CREATE", "BILLING_VIEW"
            );

            for (String name : permissionNames) {
                Permission permission = permissionRepository
                        .findByName(name)
                        .orElseGet(() ->
                                permissionRepository.save(
                                        Permission.builder().name(name).build()
                                )
                        );
                permissions.put(name, permission);
            }

            // 2️⃣ Roles + Permissions mapping
            Map<String, Set<String>> rolePermissions = Map.of(
                    "SUPER_ADMIN", permissions.keySet(),

                    "TENANT_ADMIN", Set.of(
                            "USER_CREATE", "USER_UPDATE", "USER_VIEW",
                            "ROLE_ASSIGN",
                            "PATIENT_VIEW",
                            "APPOINTMENT_VIEW",
                            "BILLING_VIEW"
                    ),

                    "DOCTOR", Set.of(
                            "PATIENT_VIEW",
                            "APPOINTMENT_VIEW",
                            "APPOINTMENT_UPDATE"
                    ),

                    "RECEPTIONIST", Set.of(
                            "PATIENT_CREATE",
                            "PATIENT_VIEW",
                            "APPOINTMENT_CREATE",
                            "APPOINTMENT_VIEW"
                    ),

                    "ACCOUNTANT", Set.of(
                            "BILLING_CREATE",
                            "BILLING_VIEW"
                    ),

                    "PATIENT", Set.of(
                            "APPOINTMENT_VIEW"
                    )
            );

            // 3️⃣ Save roles
            for (var entry : rolePermissions.entrySet()) {

                String roleName = entry.getKey();
                Set<String> perms = entry.getValue();

                Role role = roleRepository
                        .findByNameAndTenantId(roleName, "1")
                        .orElseGet(() -> {
                            Role r = new Role();
                            r.setName(roleName);
                            r.setTenantId("1");
                            return r;
                        });

                Set<Permission> rolePerms = perms.stream()
                        .map(permissions::get)
                        .collect(Collectors.toSet());

                role.setPermissions(rolePerms);
                roleRepository.save(role);
            }

            System.out.println("✔ Roles & Permissions initialized for tenant: " + "1");
        };
    }

}

