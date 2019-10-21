package nl.quintor.iamservice.security.jwt;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@RunWith(SpringRunner.class)
@ActiveProfiles("test")
public class JwtRsaKeyTest {

    private static final String KEYSTORE_PATH = "./src/test/java/keystore.jks";
    private static final String KEYSTORE_PASSWORD = "password";
    private static final String KEY_ALIAS = "quintorRSA";


    @Test
    public void createJwtRsaKey_withValidArguments_shouldReturnAValidInstance() throws KeyStoreException, IOException {
        var fileInput = new File(KEYSTORE_PATH);
        var passwordInput = KEYSTORE_PASSWORD;
        var aliasInput = KEY_ALIAS;


        var jwtRsaKey = new JwtRsaKey(fileInput, aliasInput, passwordInput);

        assertThat(jwtRsaKey).isNotNull();
        assertThat(jwtRsaKey.getSigningKeyForCreation()).isNotNull();
        assertThat(jwtRsaKey.getSigningKeyForVerification()).isNotNull();
    }

    @Test
    public void createJwtRsaKey_withInvalidFile_throwsException() {
        var fileInput = new File("SomeNoneExistingFile");
        var passwordInput = KEYSTORE_PASSWORD;
        var aliasInput = KEY_ALIAS;

        assertThatThrownBy(() -> new JwtRsaKey(fileInput, aliasInput, passwordInput))
                .isExactlyInstanceOf(KeyStoreException.class)
                .hasMessage("Provided keyStoreFile is not a valid file");
    }

    @Test
    public void createJwtRsaKey_withInvalidPassword_throwsException() {
        var fileInput = new File(KEYSTORE_PATH);
        var passwordInput = "invalidPassword";
        var aliasInput = KEY_ALIAS;

        assertThatThrownBy(() -> new JwtRsaKey(fileInput, aliasInput, passwordInput))
                .isExactlyInstanceOf(IOException.class)
                .hasMessage("keystore password was incorrect");
    }

    @Test
    public void createJwtRsaKey_withInvalidAlias_throwsException() {
        var fileInput = new File(KEYSTORE_PATH);
        var passwordInput = KEYSTORE_PASSWORD;
        var aliasInput = "invalidAlias";

        assertThatThrownBy(() -> new JwtRsaKey(fileInput, aliasInput, passwordInput))
                .isExactlyInstanceOf(KeyStoreException.class)
                .hasMessage("Provided alias is not a valid private key in the keystore");
    }
}
