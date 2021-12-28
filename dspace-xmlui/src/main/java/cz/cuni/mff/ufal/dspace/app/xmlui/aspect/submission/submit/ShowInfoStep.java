package cz.cuni.mff.ufal.dspace.app.xmlui.aspect.submission.submit;

import org.dspace.app.xmlui.aspect.submission.AbstractSubmissionStep;
import org.dspace.app.xmlui.utils.UIException;
import org.dspace.app.xmlui.wing.Message;
import org.dspace.app.xmlui.wing.WingException;
import org.dspace.app.xmlui.wing.element.Body;
import org.dspace.app.xmlui.wing.element.Division;
import org.dspace.app.xmlui.wing.element.List;
import org.dspace.authorize.AuthorizeException;
import org.dspace.content.Collection;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.sql.SQLException;

public class ShowInfoStep extends AbstractSubmissionStep
{

    /** Language Strings **/
    protected static final Message T_head =
            message("xmlui.Submission.submit.ShowInfoStep.head");
    protected static final Message T_info1 =
            message("xmlui.Submission.submit.ShowInfoStep.info1");


    @Override
    public void addBody(Body body) throws SAXException, WingException,
            UIException, SQLException, IOException, AuthorizeException
    {
        Collection collection = submission.getCollection();
        String actionURL = contextPath + "/handle/"+collection.getHandle() + "/submit/" + knot.getId() + ".continue";

        Division div = body.addInteractiveDivision("submit-showinfo",actionURL, Division.METHOD_POST,
                "primary submission");

        div.setHead(T_head);

        div.addPara(T_info1);

        // add standard control/paging buttons
        List list = div.addList( "submit-showinfo-controls", List.TYPE_FORM );
        addControlButtons(list);
    }

    @Override
    public List addReviewSection(List reviewList) throws SAXException, WingException, UIException, SQLException, IOException, AuthorizeException {
        return null;
    }
}
