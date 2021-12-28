package cz.cuni.mff.ufal.dspace.runnable;

import org.dspace.authorize.AuthorizeException;
import org.dspace.content.Item;
import org.dspace.content.ItemIterator;
import org.dspace.content.Metadatum;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;

import java.io.Console;
import java.sql.SQLException;

public abstract class FixBase {

    public abstract void fixItem(Item item) throws SQLException, AuthorizeException;

    public static void loopThroughAllItemsWithAsEPerson(Class<? extends FixBase> fixStrategy) throws IllegalAccessException, InstantiationException, SQLException, AuthorizeException {
        FixBase fb = fixStrategy.newInstance();
        Context context = new Context();
        Console console = System.console();
        EPerson eperson;
        do{
            String email = console.readLine("Enter site administrators email:");
            eperson = EPerson.findByEmail(context,email);
        }while (eperson == null);
        context.setCurrentUser(eperson);
        ItemIterator ii = Item.findAll(context);
        while(ii.hasNext()){
            Item item = ii.next();
            try{
                fb.fixItem(item);
            } catch (SQLException | AuthorizeException e) {
                context.abort();
                System.err.print(String.format("Error on item %s. Quitting.", item.getID()));
                e.printStackTrace();
                break;
            }
        }
        context.complete();
    }

    public static void showItemMetadataPrompt(Item item) {
       Console console = System.console();
       boolean exit;
       do{
           String actionString = console.readLine("Enter an action \\r, \\a, \\c or use \\q to exit:");
           Action action;
           if("\\q".equals(actionString)){
               action = new ExitAction();
           }else if("\\r".equals(actionString)){
               action = new ReadAction();
           }else if("\\a".equals(actionString)){
               action = new AddAction();
           }else if("\\c".equals(actionString)){
               action = new ClearAction();
           }else {
               action = null;
           }

           if(action != null){
               exit = action.perform(item);
           }else {
               exit  = false;
           }
       }while(!exit);
    }

    abstract static class Action{
        /**
         *
         * @return true if the caller should exit
         * @param item on which the action will be performed
         */
        abstract boolean perform(Item item);

        void printFieldValues(Item item, Console console, String field){
            final Metadatum[] metadata = item.getMetadataByMetadataString(field);
            if(metadata != null && metadata.length > 0){
                for(Metadatum md : metadata){
                    console.printf("%s.%s%s = '%s'\n", md.schema, md.element,
                            md.qualifier == null || md.qualifier.isEmpty() ? "" : "." + md.qualifier, md.value);
                }
            }else {
                console.printf("No such metadata field found\n");
            }
        }

        Metadatum fieldToMetadatum(String field, Console console){
            String[] fieldParts = field.split("\\.");
            String schema, element, qualifier;
            if(fieldParts.length == 2 || fieldParts.length == 3) {
                schema = fieldParts[0];
                element = fieldParts[1];
            }else{
                console.printf("Wrong field name format; use schema.element[.qualifier]\n");
                return null;
            }

            if(fieldParts.length == 3){
                qualifier = fieldParts[2];
            }else {
                qualifier = null;
            }
            Metadatum md = new Metadatum();
            md.schema = schema;
            md.element = element;
            md.qualifier = qualifier;
            return md;
        }
    }

    private static class ExitAction extends Action{
        @Override
        public boolean perform(Item item) {
            return true;
        }
    }

    private static class ReadAction extends Action{
        @Override
        public boolean perform(Item item) {
            Console console = System.console();
            boolean exit = false;
            do {
                String field = console.readLine("Enter a field name to read, empty line to return:");
                if(field.isEmpty()){
                    exit = true;
                }else{
                    printFieldValues(item, console, field);
                }
            }while(!exit);
            return false;
        }
    }

    private static class AddAction extends Action {
        @Override
        public boolean perform(Item item) {
            Console console = System.console();
            boolean exit = false;
            do {
                String field = console.readLine("Enter a field name to add, empty line to return:");
                String value = console.readLine("Enter the value, empty line to return:");
                if(field.isEmpty() || value.isEmpty()){
                    exit = true;
                }else{
                    Metadatum md = fieldToMetadatum(field, console);
                    if(md == null){
                        continue;
                    }
                    item.addMetadata(md.schema, md.element, md.qualifier, Item.ANY, value);
                    try {
                        item.update();
                    } catch (SQLException | AuthorizeException e) {
                        console.printf(e.toString());
                    }
                    printFieldValues(item, console, field);
                }
            }while(!exit);
            return false;
        }
    }

    private static class ClearAction extends Action {
        @Override
        public boolean perform(Item item) {
            Console console = System.console();
            boolean exit = false;
            do {
                String field = console.readLine("Enter a field name to clear, empty line to return:");
                if(field.isEmpty()){
                    exit = true;
                }else{
                    console.printf("About to remove the following values:\n");
                    printFieldValues(item, console, field);
                    String confirm = console.readLine("Are you sure?");
                    if("y".equalsIgnoreCase(confirm)){
                        Metadatum md = fieldToMetadatum(field, console);
                        item.clearMetadata(md.schema, md.element, md.qualifier, Item.ANY);
                        try {
                            item.update();
                        } catch (SQLException | AuthorizeException e) {
                            console.printf(e.toString());
                        }
                    }else{
                        continue;
                    }
                }
            }while(!exit);
            return false;
        }
    }
}
