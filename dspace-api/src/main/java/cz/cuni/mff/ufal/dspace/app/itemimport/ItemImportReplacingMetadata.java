package cz.cuni.mff.ufal.dspace.app.itemimport;

import cz.cuni.mff.ufal.DSpaceApi;
import cz.cuni.mff.ufal.lindat.utilities.hibernate.LicenseDefinition;
import cz.cuni.mff.ufal.lindat.utilities.interfaces.IFunctionalities;
import org.dspace.app.itemimport.ItemImport;
import org.dspace.content.*;
import org.dspace.core.Context;
import org.dspace.handle.HandleManager;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ItemImportReplacingMetadata extends ItemImport {

    private java.nio.file.FileSystem fs = java.nio.file.FileSystems.getDefault();
    IFunctionalities functionalities = DSpaceApi.getFunctionalityManager();

    @Override
    protected void replaceItems(Context c, Collection[] mycollections, String sourceDir, String mapFile,
                            boolean template) throws Exception {
        // verify the source directory
        File d = new java.io.File(sourceDir);
        List<Item> processedItems = new ArrayList<>();

        if (d == null || !d.isDirectory())
        {
            throw new Exception("Error, cannot open source directory "
                    + sourceDir);
        }

        // read in HashMap first, to get list of handles & source dirs
        Map<String, String> myHash = readMapFile(mapFile);

        for (Map.Entry<String, String> mapEntry : myHash.entrySet())
        {
            String itemName = mapEntry.getKey();
            String handle = mapEntry.getValue();
            Item item;

            if (handle.indexOf('/') != -1)
            {
                System.out.println("\tReplacing:  " + handle);

                // add new item, locate old one
                item = (Item) HandleManager.resolveToObject(c, handle);
            }
            else
            {
                item = Item.find(c, Integer.parseInt(handle));
            }

            final Metadatum[] provenance = item.getMetadataByMetadataString("dc.description.provenance");
            final Metadatum[] accessioned = item.getMetadataByMetadataString("dc.date.accessioned");
            final Metadatum[] available = item.getMetadataByMetadataString("dc.date.available");
            final Metadatum[] branding = item.getMetadataByMetadataString("local.branding");

            item.clearMetadata(Item.ANY, Item.ANY, Item.ANY, Item.ANY);
            loadMetadata(c, item, java.nio.file.Paths.get(sourceDir, itemName).toString() + fs.getSeparator());
            for (Metadatum[] mds : new Metadatum[][]{provenance, accessioned, available, branding}){
                for(Metadatum md : mds){
                    item.addMetadatum(md);
                }
            }
            processedItems.add(item);
        }

        //attempt at saving all changes or none;
        for(Item i : processedItems){
            i.update();
        }
        c.commit();
        c.clearCache();

        // attach license, license label requires an update
        functionalities.openSession();
        for(Item i : processedItems){
            final String licenseURI = i.getMetadata("dc.rights.uri");
            if(licenseURI != null) {
                final LicenseDefinition license = functionalities.getLicenseByDefinition(licenseURI);
                final int licenseId = license.getLicenseId();
                for(Bundle bundle : i.getBundles("ORIGINAL")){
                    for(Bitstream b : bundle.getBitstreams()){
                        functionalities.detachLicenses(b.getID());
                        functionalities.attachLicense(licenseId, b.getID());
                    }
                }
                i.clearMetadata("dc", "rights", "label", Item.ANY);
                i.addMetadata("dc", "rights", "label", Item.ANY, license.getLicenseLabel().getLabel());
                i.update();
            }
        }
        c.commit();
        c.clearCache();
        functionalities.closeSession();
    }
}
