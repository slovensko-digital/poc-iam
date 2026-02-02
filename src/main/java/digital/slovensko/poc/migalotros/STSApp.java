package digital.slovensko.poc.migalotros;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ImportResource;
//import redis.clients.jedis.JedisPool;
//import redis.clients.jedis.JedisPoolConfig;


@SpringBootApplication
@ImportResource("classpath:beans.xml") // This wires everything
public class STSApp {
    public static void main(String[] args) {
        SpringApplication.run(STSApp.class, args);
    }
}