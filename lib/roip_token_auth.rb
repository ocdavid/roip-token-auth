module RoipTokenAuth

  mattr_accessor :cas_public_dss_keys
  
  # Configure these in the parent app's config/initializers/roip_token_auth.rb, e.g.:
  #    RoipTokenAuth::cas_public_dss_keys = [ "-----BEGIN PUBLIC KEY-----..." ]
  @@cas_public_dss_keys = [] # The list of DSS public keys in PEM format, one per Authorization Server whose access tokens are trusted

  require 'engine' if defined?(Rails)

  module Controllers
    module Helpers
      def roip_token_filter
        if request.headers["HTTP_AUTHORIZATION"] && 
          ((oauth_string = request.headers["HTTP_AUTHORIZATION"].gsub!(/^.*Oauth /, "")).size > 0)
          theToken = RoipTextAccessToken.new(JSON.parse oauth_string)
        end

        if ! (theToken && theToken.valid?(request.fullpath))
          # TODO: Allow the parent app to set a "failure" route
          render :text => "Invalid RoIP Token", :status => 401
        end
      end
    end
  end
end
