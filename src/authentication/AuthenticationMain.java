package authentication;

public class AuthenticationMain {
    public static void main(String[] args) {
        Authentication authentication = new Authentication();

        boolean flag = authentication.authenticate(new User("rober","rober123"));

        if(flag) {
            System.out.println("ok");
        }else {
            System.out.println("no");
        }
    }
}
