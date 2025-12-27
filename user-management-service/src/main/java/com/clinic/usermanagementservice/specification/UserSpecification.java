package com.clinic.usermanagementservice.specification;

import com.clinic.usermanagementservice.domain.User;
import com.clinic.usermanagementservice.domain.enmus.UserStatus;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;


public class UserSpecification {

    public static Specification<User> filterBy(String email, String fullName, UserStatus status) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if(email != null) predicates.add(cb.equal(root.get("email"), email));
            if(fullName != null) predicates.add(cb.like(cb.lower(root.get("fullName")), "%" + fullName.toLowerCase() + "%"));
            if(status != null) predicates.add(cb.equal(root.get("status"), status));
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
