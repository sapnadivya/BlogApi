package com.restapi.blog.service.impl;

import com.restapi.blog.entity.Comment;
import com.restapi.blog.entity.Post;
import com.restapi.blog.exception.BlogApiException;
import com.restapi.blog.exception.ResourceNotFoundException;
import com.restapi.blog.payload.CommentDto;
import com.restapi.blog.payload.PostDto;
import com.restapi.blog.repository.CommentRepository;
import com.restapi.blog.repository.PostRepository;
import com.restapi.blog.service.CommentService;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CommentServiceImpl implements CommentService {
    private CommentRepository commentRepository;
    private PostRepository postRepository;
    private ModelMapper modelMapper;


    public CommentServiceImpl(CommentRepository commentRepository, PostRepository postRepository,ModelMapper modelMapper) {
        this.commentRepository = commentRepository;
        this.postRepository = postRepository;
        this.modelMapper=modelMapper;
    }

    @Override
    public CommentDto createComment(long postId, CommentDto commentDto) {
        Comment comment = mapToEntity(commentDto);
        Post post = postRepository.findById(postId).orElseThrow(() -> new ResourceNotFoundException("Post", "id", postId));
        //set post to comment entity
        comment.setPost(post);
        //save comment entity to database
        Comment newcomment = commentRepository.save(comment);
        System.out.println(comment);

        return mapToDto(newcomment);
    }

    @Override
    public List<CommentDto> getCommentsByPostId(long postId) {
        //retrieve clist of comments by post id
        List<Comment> commentList = commentRepository.findByPostId(postId);
        //convert list of comment entities to list of comment dto's.
        //stream is used from java 8
        return commentList.stream().map(comment -> mapToDto(comment)).collect(Collectors.toList());
    }

    @Override
    public CommentDto getCommentById(Long postId, Long commentId) {
        // retrieve post entity by Id
        Post post = postRepository.findById(postId).orElseThrow(() ->
                new ResourceNotFoundException("Post", "id", postId));
        //Retrieve comment entity by Id
        Comment comment = commentRepository.findById(commentId).orElseThrow(() ->
                new ResourceNotFoundException("Comment", "id", commentId));
        if (!(comment.getPost().getId() == post.getId())) {
            throw new BlogApiException(HttpStatus.BAD_REQUEST, "Comment doesnt belong to particular post ");
        }


        return mapToDto(comment);
    }

    @Override
    public CommentDto updateComment(long postId, long commentId, CommentDto commentDto) {
        // retrieve post entity by Id
        Post post = postRepository.findById(postId).orElseThrow(() ->
                new ResourceNotFoundException("Post", "id", postId));
        //Retrieve comment entity by Id
        Comment comment = commentRepository.findById(commentId).orElseThrow(() ->
                new ResourceNotFoundException("Comment", "id", commentId));
        if (!(comment.getPost().getId() == post.getId())) {
            throw new BlogApiException(HttpStatus.BAD_REQUEST, "Comment doesnt belong to particular post ");
        }
        comment.setName(commentDto.getName());
        comment.setEmail(commentDto.getEmail());
        comment.setBody(commentDto.getBody());
        Comment updatedComment=commentRepository.save(comment);
        return mapToDto(updatedComment);
    }

    @Override
    public void deleteComment(long postId, long commentId) {
        // retrieve post entity by Id
        Post post = postRepository.findById(postId).orElseThrow(() ->
                new ResourceNotFoundException("Post", "id", postId));
        //Retrieve comment entity by Id
        Comment comment = commentRepository.findById(commentId).orElseThrow(() ->
                new ResourceNotFoundException("Comment", "id", commentId));
        if (!(comment.getPost().getId() == post.getId())) {
            throw new BlogApiException(HttpStatus.BAD_REQUEST, "Comment doesnt belong to particular post ");
        }
        commentRepository.delete(comment);
        System.out.println("comment deleted successfully for postId -> "+postId+" and name -> "+ comment.getName());
    }


    //convert entity into DTO.
    private CommentDto mapToDto(Comment comment) {
        CommentDto commentDto=modelMapper.map(comment,CommentDto.class);
        /*CommentDto commentDto = new CommentDto();
        commentDto.setId(comment.getId());
        //commentDto.setName(comment.getName());
        commentDto.setName(comment.getName());
        System.out.println("get the name -> " + comment.getName());
        commentDto.setBody(comment.getBody());
        System.out.println("get body -> " + comment.getBody());


        commentDto.setEmail(comment.getEmail());*/
        return commentDto;
    }

    //convert DTO into entity.
    private Comment mapToEntity(CommentDto commentDto) {
        Comment comment=modelMapper.map(commentDto,Comment.class);
       /* Comment comment = new Comment();
        comment.setId(commentDto.getId());
        comment.setName(commentDto.getName());
        comment.setBody(commentDto.getBody());
        comment.setEmail(commentDto.getEmail());*/
        return comment;
    }

}
