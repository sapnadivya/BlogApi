package com.restapi.blog.payload;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

@Data
public class PostDto {
    //THIS class will help to convert json to java and java to json this will not explore user actaul resources.
    private long id;
    //title should not be empty and null.
    // title should have  at least 2 characters
    @NotEmpty
    @Size(min=2,message="Post title should have atleast 2 character")
    private String title;
    //title should not be empty and null.
    // title should have  at least 2 characters
    @NotEmpty
    @Size(min=10,message="Post description should have atleast 2 character")
    private String description;

    @NotEmpty
    private String content;
    private Set<CommentDto> comments;
}
