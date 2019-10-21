package nl.quintor.iamservice.controller;

import nl.quintor.iamservice.model.Quser;
import nl.quintor.iamservice.service.QuserService;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.PermitAll;
import java.util.List;

@RestController
@RequestMapping("/user")
public class QuserController {
    private QuserService quserService;

    public QuserController(QuserService quserService) {
        this.quserService = quserService;
    }

    @GetMapping
    @Secured({"ROLE_ADMIN", "ROLE_MANAGER", "ROLE_ASSISTANT_MANAGER"})
    public List<Quser> findAllUsers() {
        return quserService.findAll();
    }

    @PostMapping
    @PermitAll
    public Quser create(@RequestBody  Quser user) {
        return quserService.save(user);
    }
}
