package nl.quintor.iamservice.service;

import nl.quintor.iamservice.model.Quser;
import nl.quintor.iamservice.repository.QuserRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class QuserService {

    private QuserRepository quserRepository;

    public QuserService(QuserRepository quserRepository) {
        this.quserRepository = quserRepository;
    }

    public Optional<Quser> findByUsername(String username) {
        return quserRepository.findByUsername(username);
    }

    public List<Quser> findAll() {
        return quserRepository.findAll();
    }

    public Quser save(Quser quser) {
        return quserRepository.save(quser);
    }
}
