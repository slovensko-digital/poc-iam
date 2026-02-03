package digital.slovensko.poc.migalotros;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class STSApp {

    public static void main(String[] args) {
        new SpringApplicationBuilder()
                .sources(STSApp.class)
                .run(args);
    }
}