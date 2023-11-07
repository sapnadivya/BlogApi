package com.restapi.blog.repository;

import com.restapi.blog.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PostRepository extends JpaRepository<Post,Long> {
    //JPA repository internally supports pagination and sorting.
    //with extending repository with jpa repository it take cares of crud operation with database
    //we dont need to add @repository to the repository if it extends jpa repository
    //bcz jpa repository internally implements simple jpa repository which annotates with @repository

}
