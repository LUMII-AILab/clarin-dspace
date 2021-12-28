/*global jQuery */
/*jshint globalstrict: true*/
'use strict';
var ufal = ufal || {};

ufal.selectCollection = {
		
	// TODO: use css classes instead of inline styling

	model : null,
	
	getSelectCommunityDiv : function() {
		return $('#cz_cuni_mff_ufal_dspace_app_xmlui_aspect_submission_submit_SelectCollectionStep_div_select-community-div');
	},
	
	getSelectCommunityCommunitiesListDiv : function() {
		return $('#cz_cuni_mff_ufal_dspace_app_xmlui_aspect_submission_submit_SelectCollectionStep_div_communities-list');
	},

	div_communities: function(html) {
		return ufal.selectCollection.getSelectCommunityCommunitiesListDiv().html(html);
	},

	getCollectionsListDiv : function(){
		return $("#collection_list");
	},

	div_collections: function(html){
	    var where = ufal.selectCollection.getCollectionsListDiv();
	    if(where.length){
	    	return where.html(html);
		}else {
			return ufal.selectCollection.getSelectCommunityCommunitiesListDiv().after('<hr /><div' +
				' id="collection_list">' + html + '</div>');
		}
	},
		
	getSelectCommunityCommunitiesListLinks : function() {
		return $('#cz_cuni_mff_ufal_dspace_app_xmlui_aspect_submission_submit_SelectCollectionStep_div_communities-list a');
	},	
	
	getSelectCollectionSelect: function() {
		return $('#cz_cuni_mff_ufal_dspace_app_xmlui_aspect_submission_submit_SelectCollectionStep_field_handle');
	},
	
	getSelectCollectionDiv : function() {
		return $('#cz_cuni_mff_ufal_dspace_app_xmlui_aspect_submission_submit_SelectCollectionStep_div_select-collection-div');
	},
	
	getSelectCollectionSubmitButton : function() {
		return $('#cz_cuni_mff_ufal_dspace_app_xmlui_aspect_submission_submit_SelectCollectionStep_field_submit');
	},
	
	getCommunitiesModelInput : function() {
		return $('#cz_cuni_mff_ufal_dspace_app_xmlui_aspect_submission_submit_SelectCollectionStep_field_communities-model');
	},
	
	createGUI : function(model, key) {
		var html = '';				
		html += '<div style="margin-bottom:20px;">';
		html += '<div class="well well-light" style="display: table-row;" class="text-center" id="' + key +'">';
		for ( var i in model[key]) {
			if(i > 0) {
				html += '<div style="display: table-cell; vertical-align: top; width: 2%;"></div>';
			}
			var communityOrCollection = model[key][i];
			var id = key + "_" + communityOrCollection.id;
			html += '<div style="display: table-cell; vertical-align: top; width: 49%;">';
			html += '<a href="#" class="thumbnail" style="display: block; line-height: inherit; padding: 1em 2em;" id="' + id + '">';
			if (communityOrCollection.logoURL != "") {
				html += '<div style="line-height: 200px; text-align: center;">';
				html += '<img src="' + communityOrCollection.logoURL + '" alt="'
						+ communityOrCollection.name + '" />';
				html += '</div>';
			}			
			html += '<div style="min-height: 7em;">';
			html += '<h4 class="text-center">' + communityOrCollection.name + '</h4>';
			if (communityOrCollection.shortDescription != "") {
				html += '<p>' + communityOrCollection.shortDescription + '</p>';
			}
			html += '</div>';
			html += '</a>';
			html += '</div>';

		}		
		html += '</div>';
		html += '</div>';
		var appendTo = ufal.selectCollection['div_' + key](html);
	},

	createCommunitiesGUI : function(model) {
		ufal.selectCollection.createGUI(model, 'communities');
    },

	getCommunitiesModel : function() {
		var model = {};
		var modelJSON = ufal.selectCollection.getCommunitiesModelInput().val();
		if (modelJSON != "") {
			model = jQuery.parseJSON(modelJSON);
		}
		return model;
	},		

	populateCollections : function(communityID, model) {
		var select = ufal.selectCollection.getSelectCollectionSelect();
		select.find('option:gt(0)').remove();
		for ( var i in model.communities) {
			var community = model.communities[i];
			if (community.id == communityID) {
				for ( var j in community.collections) {
					var collection = community.collections[j];
					select.append('<option value="' + collection.handle + '">'
							+ collection.name + '</option>');
				}
				return community;
			}
		}
	},		
	
	showCommunitiesGUI: function() {
		ufal.selectCollection.getSelectCommunityDiv().removeClass('hidden');				
	},

	hideCollectionsGUI : function() {
		ufal.selectCollection.getSelectCollectionDiv().hide();
		ufal.selectCollection.getSelectCollectionSubmitButton().attr('disabled', 'disabled');
	},

	showCollectionsGUI : function() {		
		ufal.selectCollection.getSelectCollectionDiv().show();
		if(ufal.selectCollection.getSelectCollectionDiv().find('select').val() == "") {
			ufal.selectCollection.getSelectCollectionSubmitButton().attr('disabled', 'disabled');
		}
		else {
			ufal.selectCollection.getSelectCollectionSubmitButton().removeAttr('disabled');
		}
		$('html, body').delay(100).animate({
			scrollTop: ufal.selectCollection.getSelectCollectionDiv().offset().top
		}, 200);
	},

	showCollectionsGUI2 : function(community, collectionSelect) {
		ufal.selectCollection.createGUI(community, 'collections');
		ufal.selectCollection.getCollectionsListDiv().find("a").on('click', function(){
			ufal.selectCollection.getCollectionsListDiv().find(".alert-info").each(function(){
				$(this).removeClass('alert-info');
			});
			var $this = $(this);
			$this.toggleClass('alert-info');
			var name = $this.attr('id');
			var collectionID = name.replace(/^.*_(\d+)/, '$1');
			var handle;
			for (var i in community.collections){
				var collection = community.collections[i];
				if(collection.id == collectionID){
					handle = collection.handle;
					break;
				}
			}
			if(handle) {
				collectionSelect.find('option[value="' + handle + '"]').prop('selected', true);
				ufal.selectCollection.getSelectCollectionSubmitButton().removeAttr('disabled');
			}
		});
	},

	showNextButtonOnly : function() {
			ufal.selectCollection.getSelectCollectionDiv().hide();
		ufal.selectCollection.getSelectCollectionSubmitButton().removeAttr('disabled');
	},
	
	onCommunityClick : function(e) {
		ufal.selectCollection.getSelectCommunityCommunitiesListLinks().removeClass('alert-info');
		$(this).toggleClass('alert-info');			
		var name = $(this).attr('id');
		var communityID = name.replace(/^.*_(\d+)/, '$1');
		var community = ufal.selectCollection.populateCollections(communityID, ufal.selectCollection.model);
		var collectionSelect = ufal.selectCollection.getSelectCollectionSelect();
		if(collectionSelect.find('option').length == 2) {
			collectionSelect.find('option:eq(1)').prop('selected', true);
			ufal.selectCollection.showNextButtonOnly();			
		}
		else {
			if(ufal.selectCollection.model.GUI2){
				ufal.selectCollection.showCollectionsGUI2(community, collectionSelect)
			}else{
				ufal.selectCollection.showCollectionsGUI();
			}
		}
		return false;
	},
	
	onCollectionChange : function(e) {
		if ($(this).val() != "") {				
			ufal.selectCollection.getSelectCollectionSubmitButton().removeAttr('disabled');
		} else {				
			ufal.selectCollection.getSelectCollectionSubmitButton().attr('disabled', 'disabled');
		}
	},
	
	init : function() {
		// remove well-small added in general xsl transformation				
		
		ufal.selectCollection.model = ufal.selectCollection.getCommunitiesModel();
		
		if (ufal.selectCollection.model.communities.length == 1
				&& ufal.selectCollection.model.communities[0].collections.length == 1) {
			// only one selectable collection - bypass this step
			ufal.selectCollection.getSelectCollectionSubmitButton().click();			
		}
		else {
			// hide collections and wait for selection of community
			ufal.selectCollection.hideCollectionsGUI();
						
			// create list of communities
			ufal.selectCollection.createCommunitiesGUI(ufal.selectCollection.model);
			
			// show list of communities
			ufal.selectCollection.showCommunitiesGUI();
			
			// bind events
			ufal.selectCollection.getSelectCommunityCommunitiesListLinks().on('click', ufal.selectCollection.onCommunityClick);		
			ufal.selectCollection.getSelectCollectionSelect().on('change', ufal.selectCollection.onCollectionChange);
		}
	}

};

jQuery(document).ready(function() {
	ufal.selectCollection.init();
}); // ready
