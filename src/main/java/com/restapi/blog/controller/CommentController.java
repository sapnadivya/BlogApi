package com.restapi.blog.controller;

import com.restapi.blog.entity.Comment;
import com.restapi.blog.payload.CommentDto;
import com.restapi.blog.service.CommentService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/")
public class CommentController {

    private CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @PostMapping("/posts/{postId}/comments")
    public ResponseEntity<CommentDto> createComment(@PathVariable(value = "postId") long postId,
                                                   @Valid @RequestBody CommentDto commentDto) {


        return new ResponseEntity<>(commentService.createComment(postId, commentDto), HttpStatus.CREATED);
    }

    @GetMapping("/posts/{postId}/comments")
    public List<CommentDto> getCommentsByPostId(@PathVariable(value = "postId") long postId) {
        return commentService.getCommentsByPostId(postId);
    }
    @GetMapping("/posts/{postId}/comments/{commentId}")
    public ResponseEntity<CommentDto> getCommentById(@PathVariable(value = "postId") long postId,
                                                     @PathVariable(value = "commentId") long commentId){
        CommentDto commentDto=commentService.getCommentById(postId,commentId);
        return new ResponseEntity<>(commentDto,HttpStatus.OK);
    }

    @PutMapping("/posts/{postId}/comments/{commentId}")

    public ResponseEntity<CommentDto> UpdateComment(@PathVariable(value = "postId") long postId
            ,@PathVariable(value = "commentId") long commentId, @Valid @RequestBody CommentDto commentDto){
        CommentDto updatedComment= commentService.updateComment(postId,commentId,commentDto);
        return new ResponseEntity<>(updatedComment,HttpStatus.OK);

    }
    @DeleteMapping("/posts/{postId}/comments/{commentId}")

    public ResponseEntity<String> deleteComment(@PathVariable(value = "postId") long postId,
                                                @PathVariable(value = "commentId") long commentId){
        commentService.deleteComment(postId, commentId);
        return new ResponseEntity<>("comment deleted succesfully",HttpStatus.OK);

    }

}
