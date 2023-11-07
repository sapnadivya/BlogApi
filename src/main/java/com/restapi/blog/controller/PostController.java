package com.restapi.blog.controller;

import com.restapi.blog.entity.Post;
import com.restapi.blog.payload.PostDto;
import com.restapi.blog.payload.PostResponse;
import com.restapi.blog.service.PostService;
import com.restapi.blog.utils.AppConstants;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
@RestController
@RequestMapping("/api/posts")
public class PostController {
    //inject service class into controller
    private PostService postService;//we are injecting interface not class hence we are making loose coupling here.

    public PostController(PostService postService) {
        this.postService = postService;
    }

    //create blog post restapi
    //enable rest api validation using @valid with @requestbody using hibernate validator

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<PostDto> createPost(@Valid @RequestBody PostDto postDto) {
        return new ResponseEntity<>(postService.createPost(postDto), HttpStatus.CREATED);

    }

    //get all post rest api
   /* @GetMapping
    public List<PostDto> getAllPosts() {
        return postService.getAllPost();

    }*/
//get all post rest api ( pagination )
    //for pagination we require two request param pageno and page size.
    @GetMapping
    public PostResponse getAllPosts(
            @RequestParam(value = "pageNo",defaultValue = AppConstants.DEFAULT_PAGE_NO,required = false) int pageNo,
            @RequestParam(value = "pageSize",defaultValue = AppConstants.DEFAULT_PAGE_SIZE,required = false) int pageSize,
            @RequestParam(value = "sortBy",defaultValue = AppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
            @RequestParam(value = "sortDir",defaultValue=AppConstants.DEFAULT_SORT_DIRECTION,required=false)String sortDir
 ) {
        return postService.getAllPost(pageNo,pageSize,sortBy,sortDir);
    }

    @GetMapping("/{id}")
    public ResponseEntity<PostDto> getPostById(@PathVariable(name = "id") long id) {
        return ResponseEntity.ok(postService.getPostById(id));
    }


    //update post by id rest api
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<PostDto> updatePostById(@Valid @RequestBody PostDto postDto, @PathVariable(name = "id") long id) {
        PostDto postDtoResponse = postService.updatePostById(postDto, id);
        return new ResponseEntity<>(postDtoResponse, HttpStatus.OK);
    }

    //Delete post rest api
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deletePost(@PathVariable(name = "id") long id) {
        postService.deletePost(id);
        return new ResponseEntity<>("post not found!!deleted successfully", HttpStatus.OK);
    }
}
