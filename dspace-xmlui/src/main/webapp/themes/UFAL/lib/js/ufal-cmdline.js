var ufal = ufal || {};

ufal.cmdline = {
    init: function(){
        jQuery('div#files_section > h4').after(jQuery('<a class="btn btn-primary" href="#" style="text-decoration:none;"><i class="fa fa-download fa-3x" style="display:block;">&nbsp;</i>' + jQuery.i18n._('download-all-cmdline') + '</a>').click(function(e){
            e.preventDefault();
            var jqFilesLinks = $("a.filebutton[href*='bitstream']");
            var baseUrl = jqFilesLinks.prop('href');
            baseUrl = baseUrl.substring(0,baseUrl.lastIndexOf("/"))
            var command = "curl --remote-name-all " + baseUrl + "{";
            jqFilesLinks.each(function(index, element){
                var fileName = $(this).prop('href');
                fileName = fileName.substring(fileName.lastIndexOf("/"));
                command += fileName.split("?")[0];
                if(index < jqFilesLinks.length - 1){
                    command += ',';
                }else{
                    command += '}';
                }
            });
            var jqCommand = jQuery("div#command-div");
            if(jqCommand.length === 0){
                jqCommand = jQuery("<div id='command-div'>")
                    .append(jQuery("<button class=\"repo-copy-btn pull-right\" data-clipboard-target=\"#command-div\" />"))
                    .append(jQuery("<pre style='background-color:#d9edf7; color:#3a87ad;'>").text(command));
                $(this).after(jqCommand);
            }
            jqCommand.fadeToggle();
            //console.log(command);
        }));
    }
}

jQuery(document).ready(function() {
    ufal.cmdline.init();
}); // ready
