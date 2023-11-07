package com.restapi.blog.service;

import com.restapi.blog.payload.PostDto;
import com.restapi.blog.payload.PostResponse;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface PostService {
    PostDto createPost(PostDto postDto);
    //List<PostDto> getAllPost();
    PostResponse getAllPost(int pageNo, int pageSize,String SortBy,String sortDir);

    PostDto getPostById(long id);
    PostDto updatePostById(PostDto postDto,long id);
    void deletePost(long id);
}
