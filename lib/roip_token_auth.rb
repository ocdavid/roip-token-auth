module RoipTokenAuth

  mattr_accessor :ok_namespaces, :cas_public_dss_keys
  
  # Configure these in the parent app's config/initializers/roip_token_auth.rb, e.g.:
  #    RoipTokenAuth::ok_namespaces = [ "foo", "bar", "baz/foobar" ]
  @@ok_namespaces = [] # The list of namespaces this server will accept and serve - should include its primary hostname
  @@cas_public_dss_keys = [] # The list of DSS public keys in PEM format, one per Authorization Server whose access tokens are trusted

  require 'engine' if defined?(Rails)

  # VITAL for security: replace this technique with a CA-based Signature cert
  SIGNINGSECRET = "mugwhump"

  module Controllers
    module Helpers
      def roip_token_filter

        logger.debug "Header: #{request.headers["HTTP_AUTHORIZATION"]}"
        if request.headers["HTTP_AUTHORIZATION"] && 
          ((oauth_string = request.headers["HTTP_AUTHORIZATION"].gsub!(/^.*Oauth /, "")).size > 0)
          theToken = RoipTextAccessToken.new(JSON.parse oauth_string)
        end

        logger.debug "In roip_token_filter, token is #{theToken}, request.fullpath is #{request.fullpath}," +
        " ::RoipTokenAuth::ok_namespaces is #{::RoipTokenAuth::ok_namespaces.inspect}"
        if ! (theToken && theToken.valid?(request.fullpath))
          # TODO: Allow the parent app to set a "failure" route
          render :text => "Invalid RoIP Token", :status => 401
        end
      end
    end
  end
end
