package cz.cuni.mff.ufal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URL;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.*;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class PiwikHelper {
	private static final String[] requiredStatsNames = {"nb_visits", "nb_uniq_visitors", "nb_pageviews",
			"nb_uniq_pageviews", "nb_downloads", "nb_uniq_downloads"};


	public static String mergeXML(String report, String downloadReport) throws Exception {
		/**
		 * add page views from downloadReport as nb_downloads to report
		 */
		Document reportDoc = loadXMLFromString(report);
		Document downloadReportDoc = loadXMLFromString(downloadReport);
		
		XPathFactory xpathFactory = XPathFactory.newInstance();
		XPath xpath = xpathFactory.newXPath();
		XPathExpression resExpr = xpath.compile("//result");
		XPathExpression downExpr = xpath.compile("./nb_downloads");
		XPathExpression uniqDownExpr = xpath.compile("./nb_uniq_downloads");
				
		NodeList rRows = (NodeList)resExpr.evaluate(reportDoc, XPathConstants.NODESET);

		for(int i=0;i<rRows.getLength();i++) {
			Node rRow = rRows.item(i);
			rRow = ensureRequiredStatsPresent(reportDoc, xpath, rRow);
			Node down = (Node) downExpr.evaluate(rRow, XPathConstants.NODE);
			Node uniqDown = (Node) uniqDownExpr.evaluate(rRow, XPathConstants.NODE);
			XPathExpression pvExpr = xpath.compile(String.format("/results/result[@%s]/nb_pageviews/text()", rRow.getAttributes().getNamedItem("date")));
			XPathExpression upvExpr = xpath.compile(String.format("/results/result[@%s]/nb_uniq_pageviews/text()", rRow.getAttributes().getNamedItem("date")));

			int pvCount = ((Double)pvExpr.evaluate(downloadReportDoc, XPathConstants.NUMBER)).intValue();
			int upvCount = ((Double)upvExpr.evaluate(downloadReportDoc, XPathConstants.NUMBER)).intValue();

			down.setTextContent(Integer.toString(pvCount));
			uniqDown.setTextContent(Integer.toString(upvCount));
		}

		Transformer tf = TransformerFactory.newInstance().newTransformer();
		tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
		tf.setOutputProperty(OutputKeys.INDENT, "yes");
		Writer out = new StringWriter();
		tf.transform(new DOMSource(reportDoc), new StreamResult(out));
		return out.toString();
	}

	private static Node ensureRequiredStatsPresent(Document reportDoc, XPath xpath, Node rRow) throws XPathExpressionException {
		for(String tagName : requiredStatsNames){
			XPathExpression expr = xpath.compile("./" + tagName);
			Node node = (Node) expr.evaluate(rRow, XPathConstants.NODE);
			if(node == null){
				Element el = reportDoc.createElement(tagName);
				el.setTextContent("0");
				rRow.appendChild(el);
			}
		}
		return rRow;
	}

	public static String mergeJSON(String report, String downloadReport) throws Exception {
		/**
		 * add page views from downloadReport as nb_downloads to report
		 */
		JSONParser parser = new JSONParser();
		JSONObject reportJSON = (JSONObject)parser.parse(report);
		JSONObject downloadReportJSON = (JSONObject)parser.parse(downloadReport);
		for(Object key : reportJSON.keySet()) {			
			JSONObject rRow = null;
			JSONObject dRow = null;
			try{
				dRow = (JSONObject)downloadReportJSON.get(key);
			} catch (ClassCastException e) {
				continue;
			}
			try {
				rRow = (JSONObject)reportJSON.get(key);
			} catch (ClassCastException e) {
				rRow = new JSONObject();
				reportJSON.put(key, rRow);
			}			
			rRow.put("nb_downloads", dRow.get("nb_pageviews"));
			rRow.put("nb_uniq_downloads", dRow.get("nb_uniq_pageviews"));
		}
		return reportJSON.toJSONString();
	}
	
	public static String mergeJSONResults(String report) throws Exception {
		JSONParser parser = new JSONParser();
		JSONArray json = (JSONArray)parser.parse(report);
		JSONObject views = (JSONObject)json.get(0);
		JSONObject downloads = (JSONObject)json.get(1);
		JSONObject result = new JSONObject();

		for(Object key : views.keySet()) {
			JSONObject view_data = new JSONObject();
			// any valid view data?
			try {
				view_data = (JSONObject) views.get(key);
			} catch (ClassCastException e) {
			}
			// any valid download data?
			try {
				JSONObject download_data = (JSONObject)downloads.get(key);
				view_data.put("nb_downloads", download_data.get("nb_pageviews"));
				view_data.put("nb_uniq_downloads", download_data.get("nb_uniq_pageviews"));
			} catch (ClassCastException e) {
			}
			result.put(key, view_data);
		}
		return result.toJSONString();
	}
	
	public static String transformJSONResults(String report) throws Exception {
		JSONParser parser = new JSONParser();
		JSONArray json = (JSONArray)parser.parse(report);
		JSONObject views = (JSONObject)json.get(0);
		JSONObject downloads = (JSONObject)json.get(1);
		JSONObject response = new JSONObject();
		JSONObject result = new JSONObject();		
		response.put("response", result);		
		
		result.put("views", transformJSON(views));
		result.put("downloads", transformJSON(downloads));
		
		return response.toJSONString().replace("\\/", "/");
	}
	
	
	public static JSONObject transformJSON(JSONObject views) {
		JSONObject result = new JSONObject();
		JSONObject total = new JSONObject();		
		for(Object key : views.keySet()) {
			JSONArray view_data = (JSONArray) views.get(key);
			
			if(view_data.size()==0) continue;
			
			String dmy[] = key.toString().split("-");
			if(dmy.length==1) {
				int y = Integer.parseInt(dmy[0]);
				JSONObject year = null;
				if(!result.containsKey(y)) {
					year = new JSONObject();
					result.put(y, year);
				} else {
					year = (JSONObject)result.get(y);
				}
				for (int i = 0 ; i < view_data.size(); i++) {
					JSONObject row = (JSONObject)view_data.get(i);
					String url = row.get("label").toString();
					url = url.split("\\?|@")[0];					
					JSONObject v = null;
					int nb_visits = 0;
					int nb_hits = 0;
					if(year.containsKey(url)) {
						v = (JSONObject)year.get(url);						
						nb_visits = Integer.parseInt(v.get("nb_visits").toString());
						nb_hits = Integer.parseInt(v.get("nb_hits").toString());
					}
					v = new JSONObject();	
					nb_visits = nb_visits + Integer.parseInt(row.get("nb_visits").toString());
					nb_hits = nb_hits + Integer.parseInt(row.get("nb_hits").toString());
					v.put("nb_hits", "" +  nb_hits);
					v.put("nb_visits", "" + nb_visits);					
					year.put(url, v);
					
					int total_nb_visits = 0;
					int total_nb_hits = 0;					
					
					if(total.containsKey(y)) {
						v = (JSONObject)total.get(y);						
						total_nb_visits = Integer.parseInt(v.get("nb_visits").toString());
						total_nb_hits = Integer.parseInt(v.get("nb_hits").toString());
					}
					v = new JSONObject();	
					total_nb_visits = total_nb_visits + Integer.parseInt(row.get("nb_visits").toString());
					total_nb_hits = total_nb_hits + Integer.parseInt(row.get("nb_hits").toString());
					v.put("nb_hits", "" +  total_nb_hits);
					v.put("nb_visits", "" + total_nb_visits);					
					total.put(y, v);
					
					total_nb_visits = 0;
					total_nb_hits = 0;					
					
					if(total.containsKey("nb_visits")) {
						total_nb_visits = Integer.parseInt(total.get("nb_visits").toString());
					}
					
					if(total.containsKey("nb_hits")) {
						total_nb_hits = Integer.parseInt(total.get("nb_hits").toString());						
					}
					total_nb_visits = total_nb_visits + Integer.parseInt(row.get("nb_visits").toString());
					total_nb_hits = total_nb_hits + Integer.parseInt(row.get("nb_hits").toString());					
					
					total.put("nb_hits", total_nb_hits);
					total.put("nb_visits", total_nb_visits);
					
				}
			} else if(dmy.length==2) {
				JSONObject year = null;
				int y = Integer.parseInt(dmy[0]);
				if(!result.containsKey(y)) {
					year = new JSONObject();
					result.put(y, year);
				} else {
					year = (JSONObject)result.get(y);
				}
				int m = Integer.parseInt(dmy[1]);
				JSONObject month = null;
				if(!year.containsKey(m)) {
					month = new JSONObject();
					year.put(m, month);
				} else {
					month = (JSONObject)year.get(m);
				}
				for (int i = 0 ; i < view_data.size(); i++) {
					JSONObject row = (JSONObject)view_data.get(i);
					String url = row.get("label").toString();
					url = url.split("\\?|@")[0];					
					JSONObject v = null;
					int nb_visits = 0;
					int nb_hits = 0;
					if(month.containsKey(url)) {
						v = (JSONObject)month.get(url);						
						nb_visits = Integer.parseInt(v.get("nb_visits").toString());
						nb_hits = Integer.parseInt(v.get("nb_hits").toString());
					}
					v = new JSONObject();	
					nb_visits = nb_visits + Integer.parseInt(row.get("nb_visits").toString());
					nb_hits = nb_hits + Integer.parseInt(row.get("nb_hits").toString());
					v.put("nb_hits", "" +  nb_hits);
					v.put("nb_visits", "" + nb_visits);					
					month.put(url, v);
					
					JSONObject tyear = null;
					
					if(total.containsKey(y)) {
						tyear = (JSONObject)total.get(y);						
					} else {
						tyear = new JSONObject();
						total.put(y, tyear);
					}
					
					JSONObject tmonth = null;
								
					if(tyear.containsKey(m)) {
						tmonth = (JSONObject)tyear.get(m);
					} else {
						tmonth = new JSONObject();
						tyear.put(m, tmonth);
					}
					
					int total_nb_visits = 0;
					int total_nb_hits = 0;			
					
					if(tmonth.containsKey("nb_visits")) {
						total_nb_visits = Integer.parseInt(tmonth.get("nb_visits").toString());
					}
					if(tmonth.containsKey("nb_hits")) {
						total_nb_hits = Integer.parseInt(tmonth.get("nb_hits").toString());
					}

					v = new JSONObject();	
					total_nb_visits = total_nb_visits + Integer.parseInt(row.get("nb_visits").toString());
					total_nb_hits = total_nb_hits + Integer.parseInt(row.get("nb_hits").toString());
					v.put("nb_hits", "" +  total_nb_hits);
					v.put("nb_visits", "" + total_nb_visits);					
					tyear.put(m, v);					
					
				}				
			} else if(dmy.length==3) {
				JSONObject year = null;
				int y = Integer.parseInt(dmy[0]);
				if(!result.containsKey(y)) {
					year = new JSONObject();
					result.put(y, year);
				} else {
					year = (JSONObject)result.get(y);
				}
				int m = Integer.parseInt(dmy[1]);
				JSONObject month = null;
				if(!year.containsKey(m)) {
					month = new JSONObject();
					year.put(m, month);
				} else {
					month = (JSONObject)year.get(m);
				}
				int d = Integer.parseInt(dmy[2]);
				JSONObject day = null;
				if(!month.containsKey(d)) {
					day = new JSONObject();
					month.put(d, day);
				} else {
					day = (JSONObject)month.get(d);
				}
	
				for (int i = 0 ; i < view_data.size(); i++) {
					JSONObject row = (JSONObject)view_data.get(i);
					String url = row.get("label").toString();
					url = url.split("\\?|@")[0];					
					JSONObject v = null;
					int nb_visits = 0;
					int nb_hits = 0;
					if(day.containsKey(url)) {
						v = (JSONObject)day.get(url);						
						nb_visits = Integer.parseInt(v.get("nb_visits").toString());
						nb_hits = Integer.parseInt(v.get("nb_hits").toString());
					}
					v = new JSONObject();	
					nb_visits = nb_visits + Integer.parseInt(row.get("nb_visits").toString());
					nb_hits = nb_hits + Integer.parseInt(row.get("nb_hits").toString());
					v.put("nb_hits", "" +  nb_hits);
					v.put("nb_visits", "" + nb_visits);					
					day.put(url, v);
					JSONObject tyear = null;
					
					if(total.containsKey(y)) {
						tyear = (JSONObject)total.get(y);						
					} else {
						tyear = new JSONObject();
						total.put(y, tyear);
					}
					
					JSONObject tmonth = null;
								
					if(tyear.containsKey(m)) {
						tmonth = (JSONObject)tyear.get(m);
					} else {
						tmonth = new JSONObject();
						tyear.put(m, tmonth);
					}

					JSONObject tday = null;
					
					if(tmonth.containsKey(d)) {
						tday = (JSONObject)tmonth.get(d);
					} else {
						tday = new JSONObject();
						tmonth.put(d, tday);
					}
					
					int total_nb_visits = 0;
					int total_nb_hits = 0;			
					
					if(tday.containsKey("nb_visits")) {
						total_nb_visits = Integer.parseInt(tday.get("nb_visits").toString());
					}
					if(tday.containsKey("nb_hits")) {
						total_nb_hits = Integer.parseInt(tday.get("nb_hits").toString());
					}
				
					v = new JSONObject();	
					total_nb_visits = total_nb_visits + Integer.parseInt(row.get("nb_visits").toString());
					total_nb_hits = total_nb_hits + Integer.parseInt(row.get("nb_hits").toString());
					v.put("nb_hits", "" +  total_nb_hits);
					v.put("nb_visits", "" + total_nb_visits);					
					tmonth.put(d, v);					
				}

			}
			result.put("total", total);			
		}			
		return result;
	}
	

	public static String readFromURL(String url) throws IOException {
		StringBuilder output = new StringBuilder();		
		URL widget = new URL(url);
        String old_value = "false";
        try{
            old_value = System.getProperty("jsse.enableSNIExtension");
            System.setProperty("jsse.enableSNIExtension", "false");

            BufferedReader in = new BufferedReader(new InputStreamReader(widget.openStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                output.append(inputLine).append("\n");
            }
            in.close();
        }finally {
        	//true is the default http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html
        	old_value = (old_value == null) ? "true" : old_value;
            System.setProperty("jsse.enableSNIExtension", old_value);
        }
		return output.toString();
	}

	public static Document loadXMLFromString(String xml) throws Exception {
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    InputSource is = new InputSource(new StringReader(xml));
	    return builder.parse(is);
	}
		
}
