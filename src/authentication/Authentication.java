package authentication;

import java.util.ArrayList;
import java.util.List;

public class Authentication {


    private List<User> users;

    public Authentication() {
        users = new ArrayList<>();
        users.add(new User("helalha", "helal123"));
        users.add(new User("rober","rober123"));
        users.add(new User("sherbel","sherbel123"));
    }

    public boolean authenticate(User user){
        return users.contains(user);
    }
}
