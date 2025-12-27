package com.clinic.usermanagementservice.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "permissions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Permission {

    @Id
    @GeneratedValue
    private Long id;

    @Column(unique = true)
    private String name;
}
