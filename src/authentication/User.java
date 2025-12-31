package authentication;

public class User {
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public boolean equals(Object o) {
        if(! (o instanceof User))
            return false;
        User u = (User) o;
        if(this.username.equals(u.username) && this.password.equals(u.password))
            return true;
        return false;
    }
}