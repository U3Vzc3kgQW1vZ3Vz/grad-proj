
public class CheckExpando {
    public static void main(String[] args) {
        System.out.println("Is Expando Serializable? " + java.io.Serializable.class.isAssignableFrom(groovy.util.Expando.class));
    }
}
