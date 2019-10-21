package nl.quintor.iamservice.repository;

import nl.quintor.iamservice.model.Quser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface QuserRepository extends JpaRepository<Quser, Long> {

    Optional<Quser> findByUsername(String username);

}
