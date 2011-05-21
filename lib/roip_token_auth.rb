module RoipTokenAuth
  
  mattr_accessor :ok_namespaces
  @@ok_namespaces = ["okn1"]
  
  # VITAL for security: replace this technique with a CA-based Signature cert
  SIGNINGSECRET = "mugwhump"
  
  module Controllers
    module Helpers
      def roip_token_filter

        if request.headers["HTTP_AUTHORIZATION"] && 
          ((oauth_string = request.headers["HTTP_AUTHORIZATION"].gsub(/OAuth /, "").size > 0))
          theToken = RoipTextAccessToken.new(JSON.parse oauth_string)
        end

        logger.debug "In roip_token_filter, request.fullpath is #{request.fullpath}," +
        " ::RoipTokenAuth::ok_namespaces is #{::RoipTokenAuth::ok_namespaces.inspect}"
        if theToken && theToken.valid?(request.fullpath)
          true
        else
          # TODO: Allow the parent app to set a "failure" route
          render :text => "Invalid RoIP Token", :status => 401
        end
      end
    end
  end
end