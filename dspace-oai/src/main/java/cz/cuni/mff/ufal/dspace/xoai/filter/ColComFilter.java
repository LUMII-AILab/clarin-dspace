package cz.cuni.mff.ufal.dspace.xoai.filter;

import com.lyncode.xoai.dataprovider.core.ReferenceSet;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.solr.client.solrj.util.ClientUtils;
import org.dspace.content.Collection;
import org.dspace.content.Community;
import org.dspace.content.DSpaceObject;
import org.dspace.core.Constants;
import org.dspace.core.Context;
import org.dspace.handle.HandleManager;
import org.dspace.xoai.data.DSpaceItem;
import org.dspace.xoai.filter.DSpaceFilter;
import org.dspace.xoai.filter.results.DatabaseFilterResult;
import org.dspace.xoai.filter.results.SolrFilterResult;

import java.sql.SQLException;

public class ColComFilter extends DSpaceFilter {
    private static Logger log = LogManager.getLogger(ColComFilter.class);

    private DSpaceObject dso = null;

    @Override
    public DatabaseFilterResult buildDatabaseQuery(Context context) {
        throw new UnsupportedOperationException("Database query not implemented.");
    }

    @Override
    public SolrFilterResult buildSolrQuery() {
        if (getDSpaceObject() != null) {
            /*
                -foo is transformed by solr into (*:* -foo) only if the top level query is a pure negative query
                bar OR (-foo) is not transformed; so we need bar OR (*:* -foo)
                bar comes from org.dspace.xoai.services.impl.xoai.BaseDSpaceFilterResolver#buildSolrQuery
             */
            String q = "*:* AND ";
            String setSpec = getSetSpec();
            if (dso.getType() == Constants.COLLECTION) {
                return new SolrFilterResult(q + "-item.collections:"
                        + ClientUtils.escapeQueryChars(setSpec));
            } else if (dso.getType() == Constants.COMMUNITY) {
                return new SolrFilterResult(q + "-item.communities:"
                        + ClientUtils.escapeQueryChars(setSpec));
            }
        };
        return new SolrFilterResult("*:*");
    }

    @Override
    public boolean isShown(DSpaceItem item) {
        if(getDSpaceObject() != null) {
            String setSpec = getSetSpec();
            for (ReferenceSet s : item.getSets()) {
                if (s.getSetSpec().equals(setSpec)) {
                    return false;
                }
            }
        }
        return true;
    }

    private String getSetSpec(){
        return "hdl_" + dso.getHandle().replace("/", "_");
    }

    private DSpaceObject getDSpaceObject(){
        if (dso == null) {
            if(getConfiguration().get("handle") != null) {
                String handle = getConfiguration().get("handle").asSimpleType().asString();
                try {
                    dso = HandleManager.resolveToObject(context, handle);
                } catch (SQLException e) {
                    log.error(e);
                }
            }else if(getConfiguration().get("name") != null){
                String name = getConfiguration().get("name").asSimpleType().asString();
                try {
                    for(Community c : Community.findAll(context)){
                       if(name.equals(c.getName())){
                           dso = c;
                           break;
                       }
                    }
                    if(dso == null){
                        for(Collection c : Collection.findAll(context)){
                            if(name.equals(c.getName())){
                                dso = c;
                                break;
                            }
                        }
                    }
                } catch (SQLException e) {
                    log.error(e);
                }

            }
        }
        return dso;
    }
}
