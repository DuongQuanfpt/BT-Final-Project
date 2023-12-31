package finalproject.group1.BE.domain.entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "Category_tbl")
@Data
public class Category {
    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private int id;

    @Column(name = "name", nullable = false)
    private String name;

    @OneToMany(mappedBy = "category")
    private List<Product> products= new ArrayList<>();

    @OneToOne(mappedBy = "category",cascade = CascadeType.ALL,orphanRemoval = true)
    private CategoryImg categoryImg;
}
