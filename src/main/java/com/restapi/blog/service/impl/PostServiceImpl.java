package com.restapi.blog.service.impl;

import com.restapi.blog.entity.Post;
import com.restapi.blog.exception.ResourceNotFoundException;
import com.restapi.blog.payload.PostDto;
import com.restapi.blog.payload.PostResponse;
import com.restapi.blog.repository.PostRepository;
import com.restapi.blog.service.PostService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.awt.print.Pageable;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class PostServiceImpl implements PostService {
    private PostRepository postRepository;
    private ModelMapper modelMapper;

    public PostServiceImpl(PostRepository postRepository,ModelMapper modelMapper) {

        this.postRepository = postRepository;
        this.modelMapper=modelMapper;
    }

    @Override
    public PostDto createPost(PostDto postDto) {
        //convert DTO to entity
        Post post=  mapToEntity(postDto);

        //save this entity to database with use of postrepository
        Post newPost=postRepository.save(post);
        //now we have to convert post entity to post dto bcz return type is postdto
        //convert entity to DTO
        PostDto postResponse= mapToDto(newPost);
        return postResponse;




    }
    @Override
    public PostResponse getAllPost(int pageNo, int pageSize,String sortBy,String sortDir){
        Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name()) ? Sort.by(sortBy).ascending()
                : Sort.by(sortBy).descending();
        // Create pageable instance.
        PageRequest pageable = PageRequest.of(pageNo,pageSize,sort);
        Page<Post> posts = postRepository.findAll(pageable);
        // Get content from the page object. So here we will get a list of posts, and whenever we get a page object, we have to use getContent() to get the content.
        List<Post> postList = posts.getContent();
        List<PostDto> content = postList.stream().map(post -> mapToDto(post)).collect(Collectors.toList());
        PostResponse postResponse=new PostResponse();
        postResponse.setContent(content);
        postResponse.setPageNo(posts.getNumber());
        postResponse.setPageSize(posts.getSize());
        postResponse.setTotalElements(posts.getTotalElements());
        postResponse.setTotalPages(posts.getTotalPages());
        postResponse.setLast(posts.isLast());
        return postResponse;

    }


   /* @Override
    public List<PostDto> getAllPost() {
        List<Post> posts=postRepository.findAll();
        return posts.stream().map(post -> mapToDto(post)).collect(Collectors.toList());



    }*/

    @Override
    public PostDto getPostById(long id) {
        Post post=postRepository.findById(id).orElseThrow(()->
                new ResourceNotFoundException("Post","id",id));
        return mapToDto(post);
    }

    @Override
    public PostDto updatePostById(PostDto postDto, long id) {
        //get the post by id from database.
        Post post=postRepository.findById(id).orElseThrow(()->
                new ResourceNotFoundException("Post","id",id));
        post.setTitle(postDto.getTitle());
        post.setDescription(postDto.getDescription());
        post.setContent(postDto.getContent());
        Post updatedPost=postRepository.save(post);
        return mapToDto(updatedPost);


    }

    @Override
    public void deletePost(long id) {
        Post post=postRepository.findById(id).orElseThrow(()->
                new ResourceNotFoundException("Post","id",id));
        postRepository.delete(post);//this will delete entity from the database

    }


    //convert entity into DTO.
    private PostDto mapToDto(Post post){
        PostDto postDto=modelMapper.map(post,PostDto.class);
        /*PostDto postDto=new PostDto();
        postDto.setId(post.getId());
        postDto.setTitle(post.getTitle());
        postDto.setDescription(post.getDescription());
        postDto.setContent(post.getContent());*/
       // postDto.setCommentDtoSet(post.getComments());
        return postDto;
    }

    //convert DTO into entity.
    private Post mapToEntity(PostDto postDto){
        Post post=modelMapper.map(postDto,Post.class);
       /* Post post=new Post();
        post.setTitle(postDto.getTitle());
        post.setDescription(postDto.getDescription());
        post.setContent(postDto.getContent());
        //post.setComments(postDto.getCommentDtoSet());*/
        return post;
    }





}
