package cz.cuni.mff.ufal.dspace.runnable;

import org.dspace.authorize.AuthorizeException;
import org.dspace.content.Item;
import org.dspace.content.Metadatum;

import java.io.Console;
import java.math.BigDecimal;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.dspace.app.util.DCInput.ComplexDefinition.SEPARATOR;

public class CopyMSsize extends FixBase {
    private static final Map<String, BigDecimal> multipliers = new HashMap<>();
    static {
        multipliers.put("kilo", new BigDecimal(1000));
        multipliers.put("hundred", new BigDecimal(100));
        multipliers.put("mega", new BigDecimal(1_000_000));
        multipliers.put("tera", new BigDecimal(1_000_000_000_000L));
    }

    @Override
    public void fixItem(Item item) throws SQLException, AuthorizeException {
        Metadatum[] unit = item.getMetadataByMetadataString("metashare.ResourceInfo#TextInfo#SizeInfo.sizeUnit");

        BigDecimal val = getMSsizeWithMultiplier(item);
        if(val == null){
            return;
        }else{
            if(unit != null && unit.length == 1){
                final String valueToAdd = val + SEPARATOR  + unit[0].value;
                Console console = System.console();
                boolean finished = false;
                boolean doAdd = false;
                String confirm;
                do{
                    confirm = console.readLine(getMessage(item, valueToAdd));
                    if("y".equalsIgnoreCase(confirm)){
                        finished = true;
                        doAdd = true;
                    }else if ("n".equalsIgnoreCase(confirm)){
                        finished = true;
                    }else if("i".equalsIgnoreCase(confirm)){
                        FixBase.showItemMetadataPrompt(item);
                    }
                }while (!finished);

                if(doAdd){
                    item.addMetadata("local", "size", "info", Item.ANY, valueToAdd);
                    item.update();
                }
            }else{
                System.err.println(String.format("No size unit found for item %s, please fix manually.", item.getID()));
                return;
            }
        }
    }

    private String getMessage(Item item, String valueToAdd) {
        final Metadatum[] currentSizeInfo = item.getMetadataByMetadataString("local.size.info");
        StringBuilder msg = new StringBuilder();
        if(currentSizeInfo != null){
            msg.append("Current local.size.info values: \n");
            for(Metadatum md : currentSizeInfo){
                msg.append(md.value).append("\n");
            }
        }
        msg.append("About to add \"").append(valueToAdd).append("\" to local.size.info\n").append("Continue? " +
                "[Y]es/[N]o/[I]nspect");
        return msg.toString();
    }

    private BigDecimal getMSsizeWithMultiplier(Item item){
        BigDecimal val = getSizeAsDecimal(item);
        if(val != null) {
            BigDecimal mul = new BigDecimal(1);
            Metadatum[] multiplier = item.getMetadataByMetadataString("metashare.ResourceInfo#TextInfo#SizeInfo" +
                    ".sizeUnitMultiplier");
            if(multiplier != null && multiplier.length >0){
                if(multiplier.length == 1){
                        String mulKey = multiplier[0].value;
                        if(multipliers.containsKey(mulKey)){
                            mul = multipliers.get(mulKey);
                        } else{
                            System.err.println(String.format("Unknown size multiplier \"%s\" for item %s, please fix " +
                                    "manually.", mulKey, item.getID()));
                            FixBase.showItemMetadataPrompt(item);
                            return null;
                        }
                } else{
                    System.err.println(String.format("Multiple metashare size multipliers for item %s, please fix " +
                                    "manually.", item.getID()));
                    FixBase.showItemMetadataPrompt(item);
                    return null;
                }
            }
            return val.multiply(mul);
        }else {
            return null;
        }
    }

    private BigDecimal getSizeAsDecimal(Item item) {
        Metadatum[] size = item.getMetadataByMetadataString("metashare.ResourceInfo#TextInfo#SizeInfo.size");

        if(size != null && size.length > 0){
            if(size.length == 1){
                try {
                    return new BigDecimal(size[0].value);
                }catch (NumberFormatException e){
                    System.err.println(String.format("Incorrect value format \"%s\" for item %s, please fix manually.",
                            size[0].value, item.getID()));
                    FixBase.showItemMetadataPrompt(item);
                }
            }
            else{
                System.err.println(String.format("Multiple metashare sizes for item %s, please fix manually.",
                        item.getID()));
                FixBase.showItemMetadataPrompt(item);
            }
        }
        return null;
    }

    public static void main(String[] args) throws SQLException, InstantiationException, AuthorizeException, IllegalAccessException {
        FixBase.loopThroughAllItemsWithAsEPerson(CopyMSsize.class);
    }
}
