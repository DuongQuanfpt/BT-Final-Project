package finalproject.group1.BE.web.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OkieController {
    @GetMapping("/okie")
    public ResponseEntity okie(){
        return ResponseEntity.ok("OKIE DOOKIE");
    }
}
