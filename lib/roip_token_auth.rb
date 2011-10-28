module RoipTokenAuth

  mattr_accessor :cas_public_dss_keys
  
  # This file contains a method (roip_token_filter) to be used as a before_filter
  # and cors_set_access_control_headers to be used as an after_filter.

  # To allow AJAX requests from anywhere to pick up token-validated assets:
  #   1. First in the filter chain, use before_filter :cors_preflight_access_check to
  #       return a blank text body with necessary headers for subsequent AJAX requests to work.
  #   1. Next, use before_filter :roip_token_filter to filter incoming requests
  #   2. Following that in the filter chain, use after_filter :cors_set_access_control_headers
  #      to set outgoing header options.
  #   3. Be sure the parent site's routes.rb allows OPTIONS queries to the assets controller.

  # CORS (Cross-Origin Resource Sharing) is safe since only token-authorized requests
  # will be presented as long as before_filter :roip_token_filter is used to filter
  # hits to the asset endpoint.

  # Configure these keys in the parent app's config/initializers/roip_token_auth.rb, e.g.:
  #    RoipTokenAuth::cas_public_dss_keys = [ "-----BEGIN PUBLIC KEY-----..." ]
  @@cas_public_dss_keys = [] # The list of DSS public keys in PEM format, one per Authorization Server whose access tokens are trusted

  require 'engine' if defined?(Rails)

  module Controllers
    module Helpers
      # Filter access to permit only token-validated requests
      def roip_token_filter
        if request.headers["HTTP_AUTHORIZATION"] && 
          ((oauth_string = request.headers["HTTP_AUTHORIZATION"].gsub!(/^.*Oauth /, "")).size > 0)
          Rails.logger.debug "JSON Oauth token is #{oauth_string}"
          theToken = RoipTextAccessToken.new(JSON.parse oauth_string)
        end



        if ! (theToken && theToken.valid?(request.fullpath, request.request_method))
          # TODO: Allow the parent app to set a "failure" route
          response.headers["Access-Control-Allow-Origin"] = "*" # For XMLHttpRequests from anywhere
          render :text => "Invalid RoIP Token", :status => 401
        end
      end

      
      # If this is a preflight OPTIONS request, then short-circuit the
      # request, return only the necessary headers and return an empty
      # text/plain.
      def cors_preflight_check
        if request.method == :options
          headers['Access-Control-Allow-Origin'] = '*'
          headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
          headers['Access-Control-Allow-Headers'] = 'Authorization, X-Requested-With, X-Prototype-Version'
          headers['Access-Control-Max-Age'] = '1728000'
          render :text => '', :content_type => 'text/plain'
        end
      end


      def cors_set_access_control_headers
        headers['Access-Control-Allow-Origin'] = '*'
        headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
        headers['Access-Control-Allow-Headers'] = 'Authorization, X-Requested-With, X-Prototype-Version'
        headers['Access-Control-Max-Age'] = "1728000"
      end
    end
  end
end
