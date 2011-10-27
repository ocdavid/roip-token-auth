module RoipTokenAuth

  mattr_accessor :cas_public_dss_keys
  
  # Important note: To allow AJAX requests from anywhere to pick up token-validated assets,
  # set a header line as follows in the controller that initiates the response:
  #  response.headers["Access-Control-Allow-Origin"] = "*" # For XMLHttpRequests from anywhere
  # This is safe since only token-authorized requests will be presented as long as
  #   before_filter :roip_token_filter
  # is used to filter hits to the asset endpoint.

  # Configure these in the parent app's config/initializers/roip_token_auth.rb, e.g.:
  #    RoipTokenAuth::cas_public_dss_keys = [ "-----BEGIN PUBLIC KEY-----..." ]
  @@cas_public_dss_keys = [] # The list of DSS public keys in PEM format, one per Authorization Server whose access tokens are trusted

  require 'engine' if defined?(Rails)

  module Controllers
    module Helpers
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
    end
  end
end
