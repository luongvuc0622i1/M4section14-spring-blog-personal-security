package com.codegym.service.blog;

import com.codegym.model.Blog;
import com.codegym.model.Category;
import com.codegym.service.IGeneralService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

public interface IBlogService extends IGeneralService<Blog> {
    Page<Blog> findAll(Pageable pageable);

    Iterable<Blog> findAllByCategory(Optional<Category> category);

    Page<Blog> findAllByTitleContaining(String tittle, Pageable pageable);

    Page<Blog> findAllByCategory_Id(Long id,Pageable pageable);
}
