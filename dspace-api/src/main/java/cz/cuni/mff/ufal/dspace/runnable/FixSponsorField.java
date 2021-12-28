package cz.cuni.mff.ufal.dspace.runnable;

import org.dspace.app.util.DCInput;
import org.dspace.authorize.AuthorizeException;
import org.dspace.content.Item;
import org.dspace.content.Metadatum;

import java.sql.SQLException;

/**
 * Created by okosarko on 28.12.15.
 *
 * The structured string stored in local.sponsor is expected to have 5 fields, add empty ones if this is not true.
 */
public class FixSponsorField extends FixBase {

    private static final int EXPECTED_FIELD_COUNT = 5;

    public void fixItem(Item item) throws SQLException, AuthorizeException {
        Metadatum[] sponsors = item.getMetadataByMetadataString("local.sponsor");
        if(sponsors != null && sponsors.length > 0) {
            item.clearMetadata("local","sponsor", Item.ANY, Item.ANY);
            for (Metadatum dval : sponsors) {
                String val = dval.value;
                int seenFieldCount = val.split(DCInput.ComplexDefinition.SEPARATOR, -1).length;
                if (seenFieldCount != EXPECTED_FIELD_COUNT) {
                    for (int i = EXPECTED_FIELD_COUNT - seenFieldCount; i > 0; i--) {
                        val += DCInput.ComplexDefinition.SEPARATOR;
                    }
                    dval.value = val;
                }
                item.addMetadatum(dval);
            }
            item.update();
        }
    }

    public static void main(String[] args) throws SQLException, InstantiationException, AuthorizeException, IllegalAccessException {
        FixBase.loopThroughAllItemsWithAsEPerson(FixSponsorField.class);
    }

}
